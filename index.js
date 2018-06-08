/**
 * Plug-in easy encryption, using AES-256-CTR + HMAC hash check.
 * @author Andras Kemeny <pdx@pdx.hu>
 * @copyright Andras Kemeny, 2016
 * @license MIT
 */

var crypto = require('crypto');

/**
 * Instantiates a DecEnc instance.
 * opts: {
 *		'algo':'aes-256-ctr',
 *		'encoding':'base64',
 *		'key':null,
 *		'hashkey':null
 * }
 * WARNING! opts.key must be exactly 32 characters long!
 * @param {Object} [opts={}]
 * @constructor
 */
function decenc(opts) {
	if (typeof opts==='undefined') {
		opts = {};
	}
	this.options = {
			'algo':'aes-256-ctr',
			'encoding':'base64',
			'key':null,
			'hashkey':null
		};
	if (opts!==null && opts!=={}) {
		Object.keys(opts).forEach(function(k) {
			this.options[k] = opts[k];
		}.bind(this));
	}
	this.lastError = '';
}

/**
 * Encrypt a UTF8 text, and returns an object with keys of block (it contains encoded+iv+hash), hash, encoded, iv. 
 * @param {String} text
 * @param {String} [secretpass=null] if null is given, uses options.key; otherwise a string of 32 characters
 * @param {String} [secrethash=null] if null is given, uses options.hashkey
 * @param {Buffer} [iv=null] if null is given, generates random IV
 * @param {String} [encoding=null] can be 'base64' or 'hex', if null, uses options.encoding
 * @returns {Object}
 */
decenc.prototype.encode = function(text,secretpass,secrethash,iv,encoding) {
	if (typeof encoding==='undefined' || encoding===null) {
		encoding = this.options.encoding;
	} else {
		this.options.encoding = encoding;
	}
	if (typeof iv==='undefined' || iv===null) {
		iv = crypto.randomBytes(16);
	}
	if (typeof secrethash==='undefined' || secrethash===null) {
		secrethash = this.options.hashkey;
	} else {
		this.options.hashkey = secrethash;
	}
	if (typeof secretpass==='undefined' || secretpass===null) {
		secretpass = this.options.key;
	} else {
		this.options.key = secretpass;
	}
	if (secretpass.length!==32) {
		this.lastError = 'key_length';
		return null;
	}
	var ivstr = iv.toString(this.options.encoding);
	var crypt = crypto.createCipheriv(this.options.algo, secretpass, iv);
	var done = crypt.update(text,'utf8',this.options.encoding);
	done += crypt.final(this.options.encoding);
	var hmac = crypto.createHmac('sha256', secrethash);
	hmac.update(done+ivstr);
	var digest = hmac.digest(this.options.encoding);
	this.lastError = '';
	return {
		'block':done+ivstr+digest,
		'hash':digest,
		'encoded':done,
		'iv':ivstr
	};
};

/**
 * Decrypts a block produced by encode, and returns the decrypted UTF8 text, or null if the checksum failed.
 * @param {String} block to decode, consisting of [cryptext][iv][hash]
 * @param {String} [secretpass=null] if null is given, uses options.key; otherwise a string of 32 characters
 * @param {String} [secrethash=null] if null is given, uses options.hashkey
 * @param {Buffer} [iv=null] if null is given, uses the IV from the block
 * @param {String} [encoding=null] can be 'base64' or 'hex', if null, uses options.encoding
 * @returns {String}
 */
decenc.prototype.decode = function(block,secretpass,secrethash,iv,encoding) {
	block = block.trim();
	if (typeof encoding==='undefined' || encoding===null) {
		encoding = this.options.encoding;
	} else {
		this.options.encoding = encoding;
	}
	if (typeof iv==='undefined') {
		iv = null;
	}
	if (typeof secrethash==='undefined' || secrethash===null) {
		secrethash = this.options.hashkey;
	} else {
		this.options.hashkey = secrethash;
	}
	if (typeof secretpass==='undefined' || secretpass===null) {
		secretpass = this.options.key;
	} else {
		this.options.key = secretpass;
	}
	if (secretpass.length!==32) {
		this.lastError = 'key_length';
		return null;
	}
	var ivlen,diglen;
	if (this.options.encoding==='base64') {
		ivlen = 24;
		diglen = 44;
	}
	else if (this.options.encoding==='hex') {
		ivlen = 32;
		diglen = 64;
	}
	var digest = block.substr(0-diglen,diglen);
	var ivstr = iv===null ? block.substr(0-(diglen+ivlen),ivlen) : iv.toString(this.options.encoding);
	var done = block.substr(0,block.length-(diglen+ivlen));
	var hmac = crypto.createHmac('sha256', secrethash);
	hmac.update(done+ivstr);
	var checkdigest = hmac.digest(this.options.encoding); 
	if (checkdigest!==digest) {
		this.lastError = 'checksum_fail';
		return null;
	}
	var crypt = crypto.createDecipheriv(this.options.algo, secretpass, Buffer.from(ivstr,this.options.encoding));
	var text = crypt.update(done, this.options.encoding, 'utf8');
	text += crypt.final('utf8');
	this.lastError = '';
	return text;
};

module.exports = decenc;
