/* XXX should probably use 'bindings' module */
/* XXX name isn't quite right, is it? */
var binding = require('../build/Release/dtrace_async');

var mod_assert = require('assert');
var mod_events = require('events');
var mod_util = require('util');

exports.createConsumer = createConsumer;

var conf;	/* static DTrace configuration */

function createConsumer()
{
	return (new DTraceConsumer());
}

function makeWrapper(bind, obj, method_name, binding_prop, precond, proto_args)
{
	obj[method_name] = function () {
		var args;

		if (precond)
			precond.call(obj);
		args = Array.prototype.slice.call(arguments);
		proto_args.forEach(function (expected_type, i) {
			var actual = typeof (args[i]);

			if (actual == expected_type)
				return;

			throw (new Error(mod_util.format(
			    '%s: arg%s: expected type "%s" (found "%s")',
			    method_name, i, expected_type, actual)));
		});

		args.unshift(obj[binding_prop]);
		return (bind[method_name].apply(null, args));
	};
}

function DTraceConsumer()
{
	var dt = this;

	mod_events.EventEmitter.call(this);

	[
	    [ 'strcompile', true, 'string',  'function' ],
	    [ 'go',         true, 'function' ],
	    [ 'stop',       true, 'function' ],
	    [ 'version',    false ],
	    [ 'fini',       false ]
	].forEach(function (conf) {
		makeWrapper(binding, dt, conf[0], 'dt',
		    conf[1] ? function () { this.checkReady(); } : null,
		    conf.slice(2));
	});

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

	if (conf === undefined) {
		conf = {};
		binding.conf(function (name, value) {
			conf[name] = value;
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
	}
};

/*
DTraceConsumer.prototype.strcompile = function (str, callback)
{
	this.checkReady();
	mod_assert.equal(typeof (str), 'string',
	    'strcompile: expected string argument');
	mod_assert.equal(typeof (callback), 'function',
	    'strcompile: expected function argument');
	binding.strcompile(this.dt, str, callback);
};

DTraceConsumer.prototype.go = function (callback)
{
	this.checkReady();
	mod_assert.equal(typeof (callback), 'function',
	    'go: expected function argument');
	binding.go(this.dt, callback);
};
*/

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
			value = arguments[i + 3]; /* XXX */
		}

		callback(vid, key, value);
	});
};

/*
DTraceConsumer.prototype.version = function ()
{
	return (binding.version(this.dt, callback));
};
*/

var bucketsQuantize = null;

function xlateQuantize(args)
{
	var rv, i;

	if (bucketsQuantize === null)
		bucketsQuantize = makeQuantizeBuckets();

	rv = [];
	for (i = 0; i < args.length; i += 2)
		rv.push([ bucketsQuantize[args[i]], args[i + 1] ]);

	return (rv);
}

function quantizeBucketval(bi)
{
	/*
	 * There aren't enough bits in JavaScript numbers for shifting to do the
	 * right thing.  Math.pow() is pretty slow, but we're only doing this
	 * once in the entire program lifetime.
	 */
	if (bi < conf.DTRACE_QUANTIZE_ZEROBUCKET)
		return (-Math.pow(2,
		    (conf.DTRACE_QUANTIZE_ZEROBUCKET - 1 - bi)));
	if (bi == conf.DTRACE_QUANTIZE_ZEROBUCKET)
		return (0);
	return (Math.pow(2, (bi - conf.DTRACE_QUANTIZE_ZEROBUCKET - 1)));
}

/*
 * XXX this creates buckets that look mostly right, but include:
 *    [-1, -1], [0, 0], [1, 1], [2, 3]
 * and [2, 3] appears to include both 2 *and* 3.  I guess that does seem right.
 */
function makeQuantizeBuckets()
{
	var rv = new Array(conf.DTRACE_QUANTIZE_NBUCKETS);
	var i, min, max;

	for (i = 0; i < rv.length; i++) {
		if (i < conf.DTRACE_QUANTIZE_ZEROBUCKET) {
			min = i > 0 ? quantizeBucketval(i - 1) + 1 :
			    conf.INT64_MIN;
			max = quantizeBucketval(i);
		} else if (i == conf.DTRACE_QUANTIZE_ZEROBUCKET) {
			min = max = 0;
		} else {
			min = quantizeBucketval(i);
			max = i < conf.DTRACE_QUANTIZE_NBUCKETS - 1 ?
			    quantizeBucketval(i + 1) - 1 : conf.INT64_MAX;
		}

		rv[i] = [ min, max ];
	}

	return (rv);
}
