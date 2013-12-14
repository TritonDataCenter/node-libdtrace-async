/*
 * lib/dtrace-async.js: public interface for the async libdtrace binding.  This
 * provides an object wrapper around the low-level native binding, which is not
 * directly exposed to users.
 */
var binding = require('bindings')('dtrace_async.node');

var mod_assert = require('assert');
var mod_events = require('events');
var mod_util = require('util');

var makeBindingWrapper = require('./binding_wrap');

/* Public interface */
exports.createConsumer = createConsumer;

/* Static configuration */
var dtc_conf;				/* miscellaneous C constants */
var dtc_isready = function () { this.checkReady(); };

var dtc_buckets_quantize = null;	/* quantize() action bucket ranges */
var dtc_buckets_lquantize = {};		/* lquantize() action bucket ranges */
					/* (indexed by params) */

/*
 * Public interface: create an asynchronous DTraceConsumer.  See README.md for
 * details.
 */
function createConsumer()
{
	return (new DTraceConsumer());
}


/*
 * Each DTraceConsumer encapsulates a single DTrace enabling -- what normally
 * corresponds to an invocation of the dtrace(1M) command.  You provide a
 * script, which can have many probes, clauses, aggregations, and the like, but
 * it's all enabled, disabled, and consumed as a single unit.
 */
function DTraceConsumer()
{
	var dt = this;

	mod_events.EventEmitter.call(this);

	this.dt_status = 'uninit';
	this.dt = binding.init(function (err) {
		if (err) {
			dt.dt_status = 'error';
			dt.dt_error = err;
			dt.emit('error', err);
		} else {
			dt.dt_status = 'ready';
			dt.emit('ready');
		}
	});

	if (dtc_conf === undefined) {
		dtc_conf = {};
		binding.conf(function (name, value) {
			dtc_conf[name] = value;
		});
	}
}

mod_util.inherits(DTraceConsumer, mod_events.EventEmitter);

DTraceConsumer.prototype.checkReady = function ()
{
	switch (this.dt_status) {
	case 'uninit':
		throw (new Error('DTraceConsumer not yet ready'));
	case 'error':
		throw (new Error('DTraceConsumer failed to initialize'));
	case 'destroyed':
		throw (new Error('DTraceConsumer already destroyed'));
	default:
		mod_assert.equal(this.dt_status, 'ready');
		break;
	}
};

DTraceConsumer.prototype.setopt = function (option, value)
{
	this.checkReady();
	mod_assert.equal(typeof (option), 'string',
	    'setopt: expected string argument');
	if (arguments.length > 1)
		value = '' + value;
	binding.setopt(this.dt, option, value);
};

DTraceConsumer.prototype.consume = function (callback)
{
	this.checkReady();
	mod_assert.equal(typeof (callback), 'function',
	    'consume: expected function argument');
	binding.consume(this.dt, function (provider, module, func, name, data) {
		var probe = {
		    'provider': provider,
		    'module': module,
		    'func': func,
		    'name': name
		};

		if (arguments.length == 4)
			callback(probe);
		else
			callback(probe, { 'data': data });
	});
};

DTraceConsumer.prototype.aggwalk = function (callback)
{
	this.checkReady();
	mod_assert.equal(typeof (callback), 'function',
	    'aggwalk: expected function argument');
	binding.aggwalk(this.dt, function (vid, action, nkeys) {
		var key, value, i;
		key = new Array(nkeys);
		for (i = 0; i < nkeys; i++)
			key[i] = arguments[i + 3];

		if (action == 'quantize()') {
			value = xlateQuantize(
			    Array.prototype.slice.call(arguments, i + 3));
		} else if (action == 'lquantize()') {
			value = xlateLquantize(
			    Array.prototype.slice.call(arguments, i + 3));
		} else if (action == 'llquantize()') {
			value = xlateLlquantize(
			    Array.prototype.slice.call(arguments, i + 3));
		} else {
			value = arguments[i + 3];
		}

		callback(vid, key, value);
	});
};

DTraceConsumer.prototype.strcompile = makeBindingWrapper(
    binding, 'dt', 'strcompile', dtc_isready, [ 'string', 'function' ]);
DTraceConsumer.prototype.go = makeBindingWrapper(
    binding, 'dt', 'go', dtc_isready, [ 'function' ]);
DTraceConsumer.prototype.stop = makeBindingWrapper(
    binding, 'dt', 'stop', dtc_isready, [ 'function' ]);
DTraceConsumer.prototype.version = makeBindingWrapper(
    binding, 'dt', 'version', null, []);

/*
 * Initialize the mapping between bucket index and the corresponding range of
 * values for a quantize() bucket.  Each range is an array denoting [min, max].
 * Values are always integers, and both endpoints are included.  As a result,
 * you get buckets like:
 *
 * RANGE     CONTAINED VALUES
 * [-7, -4]  -7, -6, -5, and -4
 * [-3, -2]  -2 and -3
 * [-1, -1]  -1
 * [ 0,  0]   0
 * [ 1,  1]   1
 * [ 2,  3]   2 and 3
 * [ 4,  7]   4, 5, 6, and 7
 */
function makeQuantizeBuckets()
{
	var rv = new Array(dtc_conf.DTRACE_QUANTIZE_NBUCKETS);
	var i, min, max;

	for (i = 0; i < rv.length; i++) {
		if (i < dtc_conf.DTRACE_QUANTIZE_ZEROBUCKET) {
			min = i > 0 ? quantizeBucketval(i - 1) + 1 :
			    dtc_conf.INT64_MIN;
			max = quantizeBucketval(i);
		} else if (i == dtc_conf.DTRACE_QUANTIZE_ZEROBUCKET) {
			min = max = 0;
		} else {
			min = quantizeBucketval(i);
			max = i < dtc_conf.DTRACE_QUANTIZE_NBUCKETS - 1 ?
			    quantizeBucketval(i + 1) - 1 : dtc_conf.INT64_MAX;
		}

		rv[i] = [ min, max ];
	}

	console.log(rv);
	return (rv);
}

/*
 * Translate from the internal format of a "quantize()" aggregation value into
 * the format we provide to consumers.
 */
function xlateQuantize(args)
{
	if (dtc_buckets_quantize === null)
		dtc_buckets_quantize = makeQuantizeBuckets();

	return (xlateBuckets(dtc_buckets_quantize, args));
}

/*
 * JS implementation of DTRACE_QUANTIZE_BUCKETVAL() macro.
 */
function quantizeBucketval(bi)
{
	/*
	 * There aren't enough bits in JavaScript numbers for shifting to do the
	 * right thing.  Math.pow() is pretty slow, but we're only doing this
	 * once in the entire program lifetime.
	 */
	if (bi < dtc_conf.DTRACE_QUANTIZE_ZEROBUCKET)
		return (-Math.pow(2,
		    (dtc_conf.DTRACE_QUANTIZE_ZEROBUCKET - 1 - bi)));
	if (bi == dtc_conf.DTRACE_QUANTIZE_ZEROBUCKET)
		return (0);
	return (Math.pow(2, (bi - dtc_conf.DTRACE_QUANTIZE_ZEROBUCKET - 1)));
}

function makeLquantizeBuckets(base, step, nlevels)
{
	var rv = new Array(nlevels + 2);
	var i, min, max;

	for (i = 0; i < rv.length; i++) {
		min = i === 0 ? dtc_conf.INT64_MIN : base + ((i - 1) * step);
		max = i > nlevels ? dtc_conf.INT64_MAX : base + (i * step) - 1;
		rv[i] = [ min, max ];
	}

	return (rv);
}

function xlateLquantize(args)
{
	var base = args[0];
	var step = args[1];
	var nlevels = args[2];
	var ranges;

	if (dtc_buckets_lquantize[nlevels] === undefined)
		dtc_buckets_lquantize[nlevels] = {};
	if (dtc_buckets_lquantize[nlevels][base] === undefined)
		dtc_buckets_lquantize[nlevels][base] = {};
	if (dtc_buckets_lquantize[nlevels][base][step] === undefined)
		dtc_buckets_lquantize[nlevels][base][step] =
		    makeLquantizeBuckets(base, step, nlevels);

	ranges = dtc_buckets_lquantize[nlevels][base][step];
	return (xlateBuckets(ranges, args.slice(3)));
}

function xlateBuckets(ranges, args)
{
	var nbuckets = args.length >> 1;
	var rv = new Array(nbuckets);
	var i;

	for (i = 0; i < nbuckets; i++)
		rv[i] = [ ranges[args[i << 1]], args[(i << 1) + 1]];
	return (rv);
}

function xlateLlquantize()
{
	/* XXX */
	return (null);
}
