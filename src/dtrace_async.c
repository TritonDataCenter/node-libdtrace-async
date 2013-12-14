/*
 * dtrace_async.c: Guts of the asynchronous libdtrace binding for Node.js.  See
 * README.md for details.
 *
 * TODO:
 * - The error buffer and async operation fields of the handle could be
 *   abstracted into a common structure provided either by the shim or by
 *   another library.
 * - Fix the UNPACK_SELF ugliness.
 * - See what other entry points we want to pull in from node-libdtrace.
 */

#include <shim.h>

#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

/*
 * Sadly, libelf refuses to compile if _FILE_OFFSET_BITS has been manually
 * jacked to 64 on a 32-bit compile.  In this case, we just manually set it
 * back to 32.
 */
#if defined(_ILP32) && (_FILE_OFFSET_BITS != 32)
#undef _FILE_OFFSET_BITS
#define _FILE_OFFSET_BITS 32
#endif

#include <dtrace.h>

/*
 * This is a tad unsightly:  if we didn't find the definition of the
 * llquantize() aggregating action, we're going to redefine it here (along
 * with its support cast of macros).  This allows node-libdtrace to operate
 * on a machine that has llquantize(), even if it was compiled on a machine
 * without the support.
 */
#ifndef DTRACEAGG_LLQUANTIZE

#define	DTRACEAGG_LLQUANTIZE			(DTRACEACT_AGGREGATION + 9)

#define	DTRACE_LLQUANTIZE_FACTORSHIFT		48
#define	DTRACE_LLQUANTIZE_FACTORMASK		((uint64_t)UINT16_MAX << 48)
#define	DTRACE_LLQUANTIZE_LOWSHIFT		32
#define	DTRACE_LLQUANTIZE_LOWMASK		((uint64_t)UINT16_MAX << 32)
#define	DTRACE_LLQUANTIZE_HIGHSHIFT		16
#define	DTRACE_LLQUANTIZE_HIGHMASK		((uint64_t)UINT16_MAX << 16)
#define	DTRACE_LLQUANTIZE_NSTEPSHIFT		0
#define	DTRACE_LLQUANTIZE_NSTEPMASK		UINT16_MAX

#define DTRACE_LLQUANTIZE_FACTOR(x)             \
	(uint16_t)(((x) & DTRACE_LLQUANTIZE_FACTORMASK) >> \
	DTRACE_LLQUANTIZE_FACTORSHIFT)

#define DTRACE_LLQUANTIZE_LOW(x)                \
        (uint16_t)(((x) & DTRACE_LLQUANTIZE_LOWMASK) >> \
        DTRACE_LLQUANTIZE_LOWSHIFT)

#define DTRACE_LLQUANTIZE_HIGH(x)               \
        (uint16_t)(((x) & DTRACE_LLQUANTIZE_HIGHMASK) >> \
        DTRACE_LLQUANTIZE_HIGHSHIFT)

#define DTRACE_LLQUANTIZE_NSTEP(x)              \
        (uint16_t)(((x) & DTRACE_LLQUANTIZE_NSTEPMASK) >> \
        DTRACE_LLQUANTIZE_NSTEPSHIFT)
#endif /* NDEF DTRACEAGG_LLQUANTIZE */


/*
 * Handle flags: these indicate when various operations are going on.
 */
typedef enum {
	DTA_F_BUSY = 0x1,		/* async operation pending */
	DTA_F_CONSUMING = 0x2,		/* consume operation ongoing */
} dta_flags_t;

/*
 * Handle: there's one of these per JavaScript DTraceConsumer.  It may have at
 * most one asynchronous operation, consume operation, or aggwalk operation
 * pending.
 */
typedef struct dta_hdl {
	dtrace_hdl_t	*dta_dtrace;	/* libdtrace handle */
	int		dta_flags;

	/* current consume operation state */
	shim_val_t	*dta_consume_callback;
	shim_ctx_t	*dta_consume_ctx;

	/* async operation state */
	shim_val_t	*dta_callback;			/* user callback */
	void		*dta_uarg1;			/* user argument 1 */
	void		*dta_uarg2;			/* user argument 2 */
	void		(*dta_func)(struct dta_hdl *);	/* internal func */
	int		dta_rval;			/* internal rval */
	char		dta_errmsg[1024];		/* error message */
} dta_hdl_t;


/* Shim configuration */
static int initialize(shim_ctx_t *, shim_val_t *, shim_val_t *);
SHIM_MODULE(dtrace_async, initialize)

/* JavaScript entry points */
static int dta_conf(shim_ctx_t *, shim_args_t *);
static int dta_version(shim_ctx_t *, shim_args_t *);
static int dta_init(shim_ctx_t *, shim_args_t *);
static int dta_strcompile(shim_ctx_t *, shim_args_t *);
static int dta_go(shim_ctx_t *, shim_args_t *);
static int dta_stop(shim_ctx_t *, shim_args_t *);
static int dta_setopt(shim_ctx_t *, shim_args_t *);
static int dta_consume(shim_ctx_t *, shim_args_t *);
static int dta_aggwalk(shim_ctx_t *, shim_args_t *);

/* Helper functions */
static void dta_error_clear(dta_hdl_t *);
static void dta_error_canonicalize(dta_hdl_t *);
static void dta_error_throw(dta_hdl_t *, shim_ctx_t *);
static shim_val_t *dta_error_obj(dta_hdl_t *, shim_ctx_t *);

static int dta_dt_valid(const dtrace_recdesc_t *);
static const char *dta_dt_action(dtrace_actkind_t);
static shim_val_t *dta_dt_record(dta_hdl_t *, const dtrace_recdesc_t *,
    caddr_t);
static int dta_aggwalk_argv_populate(dta_hdl_t *, shim_val_t **, int,
    const dtrace_aggdata_t *, int *);

/* libdtrace callbacks */
static int dta_dt_bufhandler(const dtrace_bufdata_t *, void *);
static int dta_dt_consumehandler(const dtrace_probedata_t *,
    const dtrace_recdesc_t *, void *);
static int dta_dt_aggwalk(const dtrace_aggdata_t *, void *);

/* Asynchronous work helper functions */
static int dta_async_begin(shim_ctx_t *, dta_hdl_t *,
    void (*)(struct dta_hdl *), shim_val_t *);
static void dta_async_uvwork(shim_work_t *, void *);
static void dta_async_uvafter(shim_ctx_t *, shim_work_t *, int, void *);

/* Asynchronous operations */
static void dta_async_open(dta_hdl_t *);
static void dta_async_strcompile(dta_hdl_t *);
static void dta_async_go(dta_hdl_t *);
static void dta_async_stop(dta_hdl_t *);


/*
 * XXX For reasons not yet well understood, values of type "external" that
 * represent C pointers sometimes get translated by V8 into SMIs.  But when you
 * unpack them as an integer, V8 implicitly shifts the value over.  We need to
 * shift it back here.  The right answer, of course, is for the shim library to
 * properly support unpacking EXTERNALs.
 */
#define	UNPACK_SELF(arg) ((dta_hdl_t *)((arg) << 1))


/*
 * Configuration variables: these are exported to JavaScript so it can interpret
 * DTrace values.
 */
typedef struct {
	const char 	*dtc_name;
	uint64_t	dtc_value;
} dta_conf_t;

#define DEF_CONF(name) { # name , name }
dta_conf_t dta_conf_vars[] = {
	DEF_CONF(DTRACE_QUANTIZE_NBUCKETS),
	DEF_CONF(DTRACE_QUANTIZE_ZEROBUCKET),
	DEF_CONF(INT64_MAX),
	DEF_CONF(INT64_MIN),
};
#undef DEF_CONF


/*
 * Shim configuration
 */
static int
initialize(shim_ctx_t *ctx, shim_val_t *exports, shim_val_t *module)
{
	shim_fspec_t funcs[] = {
		SHIM_FS_FULL("conf", dta_conf, 0, NULL, 0),
		SHIM_FS_FULL("version", dta_version, 0, NULL, 0),

		SHIM_FS_FULL("init", dta_init, 0, NULL, 0),
		SHIM_FS_FULL("strcompile", dta_strcompile, 0, NULL, 0),
		SHIM_FS_FULL("go", dta_go, 0, NULL, 0),
		SHIM_FS_FULL("stop", dta_stop, 0, NULL, 0),
		SHIM_FS_FULL("setopt", dta_setopt, 0, NULL, 0),
		SHIM_FS_FULL("consume", dta_consume, 0, NULL, 0),
		SHIM_FS_FULL("aggwalk", dta_aggwalk, 0, NULL, 0),
		SHIM_FS_END,
	};
	
	shim_obj_set_funcs(ctx, exports, funcs);
	return (TRUE);
}


/*
 * JavaScript entry points
 */

static int
dta_conf(shim_ctx_t *ctx, shim_args_t *args)
{
	shim_val_t *callback;
	shim_val_t *argv[2];
	int i, nvars;

	callback = shim_value_alloc();
	if (!shim_unpack(ctx, args,
	    SHIM_TYPE_FUNCTION, &callback, SHIM_TYPE_UNKNOWN))
		return (FALSE);

	nvars = sizeof (dta_conf_vars) / sizeof (dta_conf_vars[0]);
	for (i = 0; i < nvars; i++) {
		argv[0] = shim_string_new_copy(ctx, dta_conf_vars[i].dtc_name);
		argv[1] = shim_number_new(ctx, dta_conf_vars[i].dtc_value);
		(void) shim_func_call_val(ctx, NULL, callback, 2, argv, NULL);
		shim_value_release(argv[0]);
		shim_value_release(argv[1]);
	}

	return (TRUE);
}

static int
dta_version(shim_ctx_t *ctx, shim_args_t *args)
{
	shim_args_set_rval(ctx, args,
	    shim_string_new_copy(ctx, _dtrace_version));
	return (TRUE);
}

static int
dta_init(shim_ctx_t *ctx, shim_args_t *args)
{
	dta_hdl_t *dtap;
	shim_val_t *callback;
	shim_val_t *external_wrapper;
	shim_val_t *persistent_wrapper;

	dtap = malloc(sizeof (*dtap));
	if (dtap == NULL) {
		shim_throw_error(ctx, "malloc: %s", strerror(errno));
		return (FALSE);
	}

	bzero(dtap, sizeof (*dtap));

	/* By design, argument checking happens in the caller. */
	callback = shim_args_get(args, 0);

	// XXX consider making weak?
	external_wrapper = shim_external_new(ctx, dtap);
	persistent_wrapper = shim_persistent_new(ctx, external_wrapper);
	shim_value_release(external_wrapper);

	shim_args_set_rval(ctx, args, persistent_wrapper);
	return (dta_async_begin(ctx, dtap, dta_async_open, callback));
}

static void
dta_async_open(dta_hdl_t *dtap)
{
	int err;
	dtrace_hdl_t *dtp;

	dtp = dtrace_open(DTRACE_VERSION, 0, &err);
	if (dtp == NULL) {
		(void) snprintf(dtap->dta_errmsg, sizeof (dtap->dta_errmsg),
		    "dtrace_open: %s", dtrace_errmsg(NULL, err));
		return;
	}

	/*
	 * Set our buffer size and aggregation buffer size to the de facto
	 * standard of 4M.
	 */
	(void) dtrace_setopt(dtp, "bufsize", "4m");
	(void) dtrace_setopt(dtp, "aggsize", "4m");

	if (dtrace_handle_buffered(dtp, dta_dt_bufhandler, dtap) == -1) {
		(void) snprintf(dtap->dta_errmsg, sizeof (dtap->dta_errmsg),
		    "dtrace_handle_buffered: %s",
		    dtrace_errmsg(dtp, dtrace_errno(dtp)));
		dtrace_close(dtp);
		return;
	}

	dtap->dta_rval = 0;
	dtap->dta_dtrace = dtp;
}

static int
dta_strcompile(shim_ctx_t *ctx, shim_args_t *args)
{
	uintptr_t selfptr;
	dta_hdl_t *dtap;
	int rv;
	shim_val_t *jsstr = shim_value_alloc();
	shim_val_t *callback = shim_value_alloc();

	/* XXX backwards convention? 0 == failure? */
	if (!shim_unpack(ctx, args,
	    SHIM_TYPE_UINT32, &selfptr,
	    SHIM_TYPE_STRING, &jsstr,
	    SHIM_TYPE_FUNCTION, &callback,
	    SHIM_TYPE_UNKNOWN)) {
		return (FALSE);
	}

	dtap = UNPACK_SELF(selfptr);

	if ((dtap->dta_flags & DTA_F_BUSY) != 0) {
		shim_throw_error(ctx, "consumer is busy");
		return (TRUE);
	}

	dtap->dta_uarg1 = shim_string_value(jsstr);
	shim_value_release(jsstr);
	rv = dta_async_begin(ctx, dtap, dta_async_strcompile, callback);
	shim_value_release(callback);
	return (rv);
}

static void
dta_async_strcompile(dta_hdl_t *dtap)
{
	dtrace_hdl_t *dtp = dtap->dta_dtrace;
	dtrace_prog_t *dp;
	dtrace_proginfo_t info;
	char *program = dtap->dta_uarg1;

	dp = dtrace_program_strcompile(dtp, program,
	    DTRACE_PROBESPEC_NAME, 0, 0, NULL);
	if (dp == NULL) {
		(void) snprintf(dtap->dta_errmsg, sizeof (dtap->dta_errmsg),
		    "couldn't compile '%s': %s\n", program,
		    dtrace_errmsg(dtp, dtrace_errno(dtp)));
		goto out;
	}

	if (dtrace_program_exec(dtp, dp, &info) == -1) {
		(void) snprintf(dtap->dta_errmsg, sizeof (dtap->dta_errmsg),
		    "couldn't execute '%s': %s\n", program,
		    dtrace_errmsg(dtp, dtrace_errno(dtp)));
		goto out;
	}

	dtap->dta_rval = 0;

out:
	free(program);
	dtap->dta_uarg1 = NULL;
}

static int
dta_go(shim_ctx_t *ctx, shim_args_t *args)
{
	uintptr_t selfptr;
	dta_hdl_t *dtap;
	int rv;
	shim_val_t *callback = shim_value_alloc();

	if (!shim_unpack(ctx, args,
	    SHIM_TYPE_UINT32, &selfptr,
	    SHIM_TYPE_FUNCTION, &callback,
	    SHIM_TYPE_UNKNOWN)) {
		return (FALSE);
	}

	dtap = UNPACK_SELF(selfptr);

	if ((dtap->dta_flags & DTA_F_BUSY) != 0) {
		shim_throw_error(ctx, "consumer is busy");
		return (TRUE);
	}

	rv = dta_async_begin(ctx, dtap, dta_async_go, callback);
	shim_value_release(callback);
	return (rv);
}

static void
dta_async_go(dta_hdl_t *dtap)
{
	dtrace_hdl_t *dtp = dtap->dta_dtrace;

	if (dtrace_go(dtp) == -1) {
		(void) snprintf(dtap->dta_errmsg, sizeof (dtap->dta_errmsg),
		    "couldn't enable tracing: %s\n",
		    dtrace_errmsg(dtp, dtrace_errno(dtp)));
	} else {
		dtap->dta_rval = 0;
	}
}

static int
dta_stop(shim_ctx_t *ctx, shim_args_t *args)
{
	uintptr_t selfptr;
	dta_hdl_t *dtap;
	int rv;
	shim_val_t *callback = shim_value_alloc();

	if (!shim_unpack(ctx, args,
	    SHIM_TYPE_UINT32, &selfptr,
	    SHIM_TYPE_FUNCTION, &callback,
	    SHIM_TYPE_UNKNOWN)) {
		return (FALSE);
	}

	dtap = UNPACK_SELF(selfptr);

	if ((dtap->dta_flags & DTA_F_BUSY) != 0) {
		/*
		 * XXX in this one case, should we queue this?  We want to be
		 * able to stop at any time.
		 */
		shim_throw_error(ctx, "consumer is busy");
		return (TRUE);
	}

	rv = dta_async_begin(ctx, dtap, dta_async_stop, callback);
	shim_value_release(callback);
	return (rv);
}

static void
dta_async_stop(dta_hdl_t *dtap)
{
	dtrace_hdl_t *dtp = dtap->dta_dtrace;

	if (dtrace_stop(dtp) == -1) {
		(void) snprintf(dtap->dta_errmsg, sizeof (dtap->dta_errmsg),
		    "couldn't disable tracing: %s\n",
		    dtrace_errmsg(dtp, dtrace_errno(dtp)));
	} else {
		dtap->dta_rval = 0;
	}
}

static int
dta_setopt(shim_ctx_t *ctx, shim_args_t *args)
{
	char *coption, *cvalue;
	uintptr_t selfptr;
	dta_hdl_t *dtap;
	dtrace_hdl_t *dtp;
	shim_val_t *option = shim_value_alloc();
	shim_val_t *value = shim_value_alloc();

	if (!shim_unpack(ctx, args,
	    SHIM_TYPE_UINT32, &selfptr,
	    SHIM_TYPE_STRING, &option,
	    SHIM_TYPE_UNKNOWN))
		return (FALSE);

	dtap = UNPACK_SELF(selfptr);
	dtp = dtap->dta_dtrace;

	coption = shim_string_value(option);
	value = shim_args_get(args, 2);
	if (shim_value_is(value, SHIM_TYPE_STRING)) {
		cvalue = shim_string_value(value);
	} else {
		cvalue = NULL;
	}

	if (dtrace_setopt(dtp, coption, cvalue) != 0)
		shim_throw_error(ctx, "couldn't set option '%s': %s\n",
		    coption, dtrace_errmsg(dtp, dtrace_errno(dtp)));

	free(coption);
	free(cvalue);
	shim_value_release(option);
	shim_value_release(value);
	return (TRUE);
}

static int
dta_consume(shim_ctx_t *ctx, shim_args_t *args)
{
	uintptr_t selfptr;
	dta_hdl_t *dtap;
	dtrace_workstatus_t status;
	dtrace_hdl_t *dtp;
	shim_val_t *callback = shim_value_alloc();

	if (!shim_unpack(ctx, args,
	    SHIM_TYPE_UINT32, &selfptr,
	    SHIM_TYPE_FUNCTION, &callback,
	    SHIM_TYPE_UNKNOWN)) {
		return (FALSE);
	}

	dtap = UNPACK_SELF(selfptr);
	dtp = dtap->dta_dtrace;

	if ((dtap->dta_flags & (DTA_F_BUSY | DTA_F_CONSUMING)) != 0) {
		shim_throw_error(ctx, "consumer is busy");
		return (TRUE);
	}

	dtap->dta_flags |= DTA_F_CONSUMING;
	dtap->dta_consume_callback = callback;
	dtap->dta_consume_ctx = ctx;
	dta_error_clear(dtap);
	dtap->dta_rval = 0;
	status = dtrace_work(dtp, NULL, NULL, dta_dt_consumehandler, dtap);
	dtap->dta_consume_callback = NULL;
	dtap->dta_consume_ctx = NULL;
	dtap->dta_flags &= ~DTA_F_CONSUMING;

	if (status != 0)
		dtap->dta_rval = 0;

	shim_value_release(callback);
	dta_error_throw(dtap, ctx);
	return (TRUE);
}

static int
dta_dt_bufhandler(const dtrace_bufdata_t *bufdata, void *arg)
{
	dta_hdl_t *dtap = arg;
	dtrace_probedata_t *data = bufdata->dtbda_probe;
	const dtrace_recdesc_t *rec = bufdata->dtbda_recdesc;
	dtrace_probedesc_t *pd = data->dtpda_pdesc;
	shim_ctx_t *ctx = dtap->dta_consume_ctx;
	shim_val_t *argv[5];
	int i, argc;

	if (rec == NULL || rec->dtrd_action != DTRACEACT_PRINTF)
		return (DTRACE_HANDLE_OK);

	argv[0] = shim_string_new_copy(ctx, pd->dtpd_provider);
	argv[1] = shim_string_new_copy(ctx, pd->dtpd_mod);
	argv[2] = shim_string_new_copy(ctx, pd->dtpd_func);
	argv[3] = shim_string_new_copy(ctx, pd->dtpd_name);
	argv[4] = shim_string_new_copy(ctx, bufdata->dtbda_buffered);
	argc = 5;

	(void) shim_func_call_val(ctx, NULL,
	    dtap->dta_consume_callback, argc, argv, NULL);
	for (i = 0; i < argc; i++)
		shim_value_release(argv[i]);
	return (DTRACE_HANDLE_OK);
}

static int
dta_dt_consumehandler(const dtrace_probedata_t *data,
    const dtrace_recdesc_t *rec, void *arg)
{
	dta_hdl_t *dtap = arg;
	dtrace_probedesc_t *pd = data->dtpda_pdesc;
	shim_val_t *callback = dtap->dta_consume_callback;
	shim_val_t *argv[5];
	shim_ctx_t *ctx = dtap->dta_consume_ctx;
	int i, argc;

	argv[0] = shim_string_new_copy(ctx, pd->dtpd_provider);
	argv[1] = shim_string_new_copy(ctx, pd->dtpd_mod);
	argv[2] = shim_string_new_copy(ctx, pd->dtpd_func);
	argv[3] = shim_string_new_copy(ctx, pd->dtpd_name);
	argc = 4;

	if (rec == NULL)
		goto out;

	if (!dta_dt_valid(rec)) {
		/*
		 * If this is a printf(), we'll defer to the bufhandler.
		 */
		if (rec->dtrd_action == DTRACEACT_PRINTF)
			return (DTRACE_CONSUME_THIS);

		(void) snprintf(dtap->dta_errmsg, sizeof (dtap->dta_errmsg),
		    "unsupported action %s in record for %s:%s:%s:%s\n",
		    dta_dt_action(rec->dtrd_action), pd->dtpd_provider,
		    pd->dtpd_mod, pd->dtpd_func, pd->dtpd_name);
		dtap->dta_rval = -1;
		return (DTRACE_CONSUME_ABORT);
	}

	argv[argc++] = dta_dt_record(dtap, rec, data->dtpda_data);

out:
	(void) shim_func_call_val(ctx, NULL, callback, argc, argv, NULL);
	for (i = 0; i < argc; i++)
		shim_value_release(argv[i]);
	return (DTRACE_CONSUME_THIS);
}

static int
dta_aggwalk(shim_ctx_t *ctx, shim_args_t *args)
{
	uintptr_t selfptr;
	dta_hdl_t *dtap;
	dtrace_hdl_t *dtp;
	int rval;
	shim_val_t *callback = shim_value_alloc();

	if (!shim_unpack(ctx, args,
	    SHIM_TYPE_UINT32, &selfptr,
	    SHIM_TYPE_FUNCTION, &callback,
	    SHIM_TYPE_UNKNOWN)) {
		return (FALSE);
	}

	/* XXX commonize this with dta_consume? */
	dtap = UNPACK_SELF(selfptr);
	dtp = dtap->dta_dtrace;

	if ((dtap->dta_flags & (DTA_F_BUSY | DTA_F_CONSUMING)) != 0) {
		shim_throw_error(ctx, "consumer is busy");
		return (TRUE);
	}

	dtap->dta_flags |= DTA_F_CONSUMING;
	dtap->dta_consume_callback = callback;
	dtap->dta_consume_ctx = ctx;
	dta_error_clear(dtap);

	if (dtrace_status(dtp) == -1) {
		(void) snprintf(dtap->dta_errmsg, sizeof (dtap->dta_errmsg),
		    "couldn't get status: %s\n",
		    dtrace_errmsg(dtp, dtrace_errno(dtp)));
		goto out;
	}

	if (dtrace_aggregate_snap(dtp) == -1) {
		(void) snprintf(dtap->dta_errmsg, sizeof (dtap->dta_errmsg),
		    "couldn't snap aggregate: %s\n",
		    dtrace_errmsg(dtp, dtrace_errno(dtp)));
		goto out;
	}

	dtap->dta_rval = 0;
	rval = dtrace_aggregate_walk(dtp, dta_dt_aggwalk, dtap);
	if (dtap->dta_rval == 0 && rval == -1)
		(void) snprintf(dtap->dta_errmsg, sizeof (dtap->dta_errmsg),
		    "couldn't walk aggregate: %s\n",
		    dtrace_errmsg(dtp, dtrace_errno(dtp)));

out:
	dtap->dta_consume_callback = NULL;
	dtap->dta_consume_ctx = NULL;
	dtap->dta_flags &= ~DTA_F_CONSUMING;
	shim_value_release(callback);
	dta_error_throw(dtap, ctx);
	return (TRUE);
}

static int
dta_dt_aggwalk(const dtrace_aggdata_t *agg, void *arg)
{
	dta_hdl_t *dtap = arg;
	shim_ctx_t *ctx = dtap->dta_consume_ctx;
	shim_val_t *callback = dtap->dta_consume_callback;
	const dtrace_aggdesc_t *aggdesc = agg->dtada_desc;
	const dtrace_recdesc_t *aggrec;
	shim_val_t **argv;
	int argc, nvalargs, i;

	/*
	 * We expect to have both a variable ID and an aggregation value here;
	 * if we have fewer than two records, something is deeply wrong.
	 */
	assert(aggdesc->dtagd_nrecs >= 2);

	/*
	 * The callback will be invoked as
	 *
	 *     callback(varid, action, nkeys, key1, ..., value, ...)
	 *
	 * The format of the "value" arguments depends on "action":
	 *
	 *   COUNT, MIN, MAX, SUM, AVG:	first (only) value is a number
	 *
	 *   QUANTIZE:			subsequent pairs of values denote
	 *   				power-of-two bucket "i" followed by
	 *   				the value in that bucket.
	 *
	 *   LQUANTIZE:			values are "base", "step", "levels",
	 *   				followed by pairs of values denoting the
	 *   				bucket index and the value in that
	 *   				bucket.
	 *
	 *   LLQUANTIZE:		values are "factor", "low", "high",
	 *   				"nsteps" followed by the pairs of values
	 *   				denoting the bucket index and the value
	 *   				in that bucket.
	 *
	 * Recall that there's one record for the variable ID, one for the
	 * value, and one for each aggregation key.  Our initial argc ignores
	 * the value, since that will translate into a variable number of
	 * callback arguments, but adds one each for "action" and "nkeys".
	 */
	argc = aggdesc->dtagd_nrecs + 1;
	if (dta_aggwalk_argv_populate(dtap, NULL, 0, agg, &nvalargs) != 0)
		return (DTRACE_AGGWALK_ERROR);

	argc += nvalargs;
	argv = malloc(argc * sizeof (argv[0])); /* XXX */
	bzero(argv, argc * sizeof (argv[0]));

	argv[0] = shim_integer_new(ctx, aggdesc->dtagd_varid);

	aggrec = &aggdesc->dtagd_rec[aggdesc->dtagd_nrecs - 1];
	argv[1] = shim_string_new_copy(ctx, dta_dt_action(aggrec->dtrd_action));
	argv[2] = shim_integer_uint(ctx, aggdesc->dtagd_nrecs - 2);

	for (i = 2; i < aggdesc->dtagd_nrecs; i++) {
		const dtrace_recdesc_t *rec = &aggdesc->dtagd_rec[i - 1];
		caddr_t addr = agg->dtada_data + rec->dtrd_offset;

		if (!dta_dt_valid(rec)) {
			(void) snprintf(dtap->dta_errmsg,
			    sizeof (dtap->dta_errmsg),
			    "unsupported action %s as key #%d in aggregation "
			    "\"%s\"\n", dta_dt_action(rec->dtrd_action),
			    i - 1, aggdesc->dtagd_name);
			dtap->dta_rval = -1;
			return (DTRACE_AGGWALK_ERROR);
		}

		assert(i < argc - 1);
		argv[i + 1] = dta_dt_record(dtap, rec, addr);
	}

	(void) dta_aggwalk_argv_populate(dtap, &argv[i + 1], nvalargs, agg,
	    NULL);

	(void) shim_func_call_val(ctx, NULL, callback, argc, argv, NULL);
	for (i = 0; i < argc; i++)
		shim_value_release(argv[i]);
	free(argv);
	return (DTRACE_AGGWALK_REMOVE);
}

static int
dta_aggwalk_argv_populate(dta_hdl_t *dtap, shim_val_t **argv, int argc,
    const dtrace_aggdata_t *agg, int *nvalargs)
{
	shim_ctx_t *ctx = dtap->dta_consume_ctx;
	const dtrace_aggdesc_t *aggdesc = agg->dtada_desc;
	const dtrace_recdesc_t *aggrec;
	int i = 0, count = 0;

#define APPEND(val) \
	if (argv != NULL && i < argc)	\
		argv[i++] = (val);	\
	count++

	aggrec = &aggdesc->dtagd_rec[aggdesc->dtagd_nrecs - 1];

	switch (aggrec->dtrd_action) {
	case DTRACEAGG_COUNT:
	case DTRACEAGG_MIN:
	case DTRACEAGG_MAX:
	case DTRACEAGG_SUM: {
		caddr_t addr = agg->dtada_data + aggrec->dtrd_offset;

		assert(aggrec->dtrd_size == sizeof (uint64_t));
		APPEND(shim_number_new(ctx, (double)(*((int64_t *)addr))));
		break;
	}

	case DTRACEAGG_AVG: {
		const int64_t *data = (int64_t *)(agg->dtada_data +
		    aggrec->dtrd_offset);

		assert(aggrec->dtrd_size == sizeof (uint64_t) * 2);
		APPEND(shim_number_new(ctx, data[1] / (double)data[0]));
		break;
	}

	case DTRACEAGG_QUANTIZE: {
		const int64_t *data = (int64_t *)(agg->dtada_data +
		    aggrec->dtrd_offset);
		int bi;

		for (bi = 0; bi < DTRACE_QUANTIZE_NBUCKETS; bi++) {
			if (!data[bi])
				continue;

			APPEND(shim_integer_new(ctx, bi));
			APPEND(shim_number_new(ctx, data[bi]));
		}

		break;
	}

	case DTRACEAGG_LQUANTIZE:
	case DTRACEAGG_LLQUANTIZE: {
		const int64_t *data = (int64_t *)(agg->dtada_data +
		    aggrec->dtrd_offset);
		uint64_t arg = *data++;
		int levels = (aggrec->dtrd_size / sizeof (uint64_t)) - 1;
		int bi;

		if (aggrec->dtrd_action == DTRACEAGG_LQUANTIZE) {
			APPEND(shim_integer_new(ctx,
			    DTRACE_LQUANTIZE_BASE(arg)));
			APPEND(shim_integer_new(ctx,
			    DTRACE_LQUANTIZE_STEP(arg)));
			APPEND(shim_integer_new(ctx,
			    DTRACE_LQUANTIZE_LEVELS(arg)));
		} else {
			APPEND(shim_integer_new(ctx,
			    DTRACE_LLQUANTIZE_FACTOR(arg)));
			APPEND(shim_integer_new(ctx,
			    DTRACE_LLQUANTIZE_LOW(arg)));
			APPEND(shim_integer_new(ctx,
			    DTRACE_LLQUANTIZE_HIGH(arg)));
			APPEND(shim_integer_new(ctx,
			    DTRACE_LLQUANTIZE_NSTEP(arg)));
		}

		for (bi = 0; bi < levels; bi++) {
			if (!data[bi])
				continue;

			APPEND(shim_number_new(ctx, data[bi]));
			APPEND(shim_number_new(ctx, data[bi]));
		}

		break;
	}

	default:
		(void) snprintf(dtap->dta_errmsg, sizeof (dtap->dta_errmsg),
		    "unsupported aggregating action %s in aggregation "
		    "\"%s\"\n", dta_dt_action(aggrec->dtrd_action),
		    aggdesc->dtagd_name);
		dtap->dta_rval = -1;
		return (-1);
	}

	if (nvalargs != NULL)
		*nvalargs = count;

	return (0);
#undef APPEND
}


/*
 * Error handling helpers
 */

static void
dta_error_clear(dta_hdl_t *dtap)
{
	dtap->dta_errmsg[0] = '\0';
	dtap->dta_rval = -1;
}

static void
dta_error_canonicalize(dta_hdl_t *dtap)
{
	if (dtap->dta_rval != 0 && dtap->dta_errmsg[0] == '\0')
		(void) snprintf(dtap->dta_errmsg, sizeof (dtap->dta_errmsg),
		    "unknown error (errno = %d, %s)", errno, strerror(errno));
}

static void
dta_error_throw(dta_hdl_t *dtap, shim_ctx_t *ctx)
{
	dta_error_canonicalize(dtap);
	if (dtap->dta_rval != 0)
		shim_throw_error(ctx, "%s", dtap->dta_errmsg);
}

static shim_val_t *
dta_error_obj(dta_hdl_t *dtap, shim_ctx_t *ctx)
{
	dta_error_canonicalize(dtap);
	if (dtap->dta_rval == 0)
		return (shim_null());
	return (shim_error_new(ctx, "%s", dtap->dta_errmsg));
}


/*
 * Asynchronous operation management
 */

static int
dta_async_begin(shim_ctx_t *ctx, dta_hdl_t *dtap,
    void (*func)(struct dta_hdl *), shim_val_t *lcallback)
{
	shim_val_t *callback;

	assert((dtap->dta_flags & DTA_F_BUSY) == 0);
	assert(dtap->dta_func == NULL);
	assert(dtap->dta_callback == NULL);

	callback = shim_persistent_new(ctx, lcallback);
	dtap->dta_flags |= DTA_F_BUSY;
	dtap->dta_func = func;
	dtap->dta_callback = callback;
	shim_queue_work(dta_async_uvwork, dta_async_uvafter, dtap);
	return (TRUE);
}

static void
dta_async_uvwork(shim_work_t *req, void *arg)
{
	dta_hdl_t *dtap = arg;

	assert((dtap->dta_flags & DTA_F_BUSY) != 0);
	dta_error_clear(dtap);
	dtap->dta_func(dtap);
	assert((dtap->dta_flags & DTA_F_BUSY) != 0);
}

static void
dta_async_uvafter(shim_ctx_t *ctx, shim_work_t *req, int status, void *arg)
{
	dta_hdl_t *dtap = arg;
	shim_val_t *argv[1];
	shim_val_t *callback;

	assert((dtap->dta_flags & DTA_F_BUSY) != 0);
	callback = dtap->dta_callback;
	dtap->dta_func = NULL;
	dtap->dta_callback = NULL;
	dtap->dta_flags &= ~DTA_F_BUSY;

	argv[0] = dta_error_obj(dtap, ctx);
	(void) shim_make_callback_val(ctx, NULL, callback, 1, argv, NULL);
	shim_value_release(argv[0]);
	shim_persistent_dispose(callback);
}


/*
 * libdtrace helper functions
 */

static int
dta_dt_valid(const dtrace_recdesc_t *rec)
{
	dtrace_actkind_t action = rec->dtrd_action;

	switch (action) {
	case DTRACEACT_DIFEXPR:
	case DTRACEACT_SYM:
	case DTRACEACT_MOD:
	case DTRACEACT_USYM:
	case DTRACEACT_UMOD:
	case DTRACEACT_UADDR:
		return (TRUE);

	default:
		return (FALSE);
	}
}

static const char *
dta_dt_action(dtrace_actkind_t action)
{
	static struct {
		dtrace_actkind_t action;
		const char *name;
	} act[] = {
		{ DTRACEACT_NONE,	"<none>" },
		{ DTRACEACT_DIFEXPR,	"<DIF expression>" },
		{ DTRACEACT_EXIT,	"exit()" },
		{ DTRACEACT_PRINTF,	"printf()" },
		{ DTRACEACT_PRINTA,	"printa()" },
		{ DTRACEACT_LIBACT,	"<library action>" },
		{ DTRACEACT_USTACK,	"ustack()" },
		{ DTRACEACT_JSTACK,	"jstack()" },
		{ DTRACEACT_USYM,	"usym()" },
		{ DTRACEACT_UMOD,	"umod()" },
		{ DTRACEACT_UADDR,	"uaddr()" },
		{ DTRACEACT_STOP,	"stop()" },
		{ DTRACEACT_RAISE,	"raise()" },
		{ DTRACEACT_SYSTEM,	"system()" },
		{ DTRACEACT_FREOPEN,	"freopen()" },
		{ DTRACEACT_STACK,	"stack()" },
		{ DTRACEACT_SYM,	"sym()" },
		{ DTRACEACT_MOD,	"mod()" },
		{ DTRACEAGG_COUNT,	"count()" },
		{ DTRACEAGG_MIN,	"min()" },
		{ DTRACEAGG_MAX,	"max()" },
		{ DTRACEAGG_AVG,	"avg()" },
		{ DTRACEAGG_SUM,	"sum()" },
		{ DTRACEAGG_STDDEV,	"stddev()" },
		{ DTRACEAGG_QUANTIZE,	"quantize()" },
		{ DTRACEAGG_LQUANTIZE,	"lquantize()" },
		{ DTRACEAGG_LLQUANTIZE,	"llquantize()" },
		{ DTRACEACT_NONE,	NULL },
	};

	int i;

	for (i = 0; act[i].name != NULL; i++) {
		if (act[i].action == action)
			return (act[i].name);
	}

	return ("<unknown action>");
}

static shim_val_t *
dta_dt_record(dta_hdl_t *dtap, const dtrace_recdesc_t *rec, caddr_t addr)
{
	shim_ctx_t *ctx = dtap->dta_consume_ctx;
	dtrace_hdl_t *dtp = dtap->dta_dtrace;
	char buf[2048], *tick, *plus;

	switch (rec->dtrd_action) {
	case DTRACEACT_DIFEXPR:
		switch (rec->dtrd_size) {
		case sizeof (uint64_t):
			return (shim_number_new(ctx,
			    (double)(*(int64_t *)addr)));

		case sizeof (uint32_t):
			return (shim_integer_uint(ctx, *((uint32_t *)addr)));

		case sizeof (uint16_t):
			return (shim_integer_uint(ctx, *((uint16_t *)addr)));

		case sizeof (uint8_t):
			return (shim_integer_uint(ctx, *((uint8_t *)addr)));

		default:
			return (shim_string_new_copy(ctx, addr));
		}

	case DTRACEACT_SYM:
	case DTRACEACT_MOD:
	case DTRACEACT_USYM:
	case DTRACEACT_UMOD:
	case DTRACEACT_UADDR:
		buf[0] = '\0';

		if (DTRACEACT_CLASS(rec->dtrd_action) == DTRACEACT_KERNEL) {
			uint64_t pc = ((uint64_t *)addr)[0];
			dtrace_addr2str(dtp, pc, buf, sizeof (buf) - 1);
		} else {
			uint64_t pid = ((uint64_t *)addr)[0];
			uint64_t pc = ((uint64_t *)addr)[1];
			dtrace_uaddr2str(dtp, pid, pc, buf, sizeof (buf) - 1);
		}

		if (rec->dtrd_action == DTRACEACT_MOD ||
		    rec->dtrd_action == DTRACEACT_UMOD) {
			/*
			 * If we're looking for the module name, we'll
			 * return everything to the left of the left-most
			 * tick -- or "<undefined>" if there is none.
			 */
			if ((tick = strchr(buf, '`')) == NULL)
				return (shim_string_new_copy(ctx, "<unknown>"));

			*tick = '\0';
		} else if (rec->dtrd_action == DTRACEACT_SYM ||
		    rec->dtrd_action == DTRACEACT_USYM) {
			/*
			 * If we're looking for the symbol name, we'll
			 * return everything to the left of the right-most
			 * plus sign (if there is one).
			 */
			if ((plus = strrchr(buf, '+')) != NULL)
				*plus = '\0';
		}

		return (shim_string_new_copy(ctx, buf));
	}

	assert(B_FALSE);
	return (shim_integer_uint(ctx, -1));
}
