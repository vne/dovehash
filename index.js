var crypto = require('crypto');
// var	crypt3 = require('crypt3');

module.exports = exports = Dovehash;

var DEFAULT_ENCODING = 'base64',
	HASH = {
		PLAIN:     { size: null, salted: false, encoded: false, algorithm: null,     crypt: false  },
		CLEARTEXT: { size: null, salted: false, encoded: false, algorithm: null,     crypt: false  },
		"PLAIN.HEX":     { size: null, salted: false, encoded: true, algorithm: null,     crypt: false  },
		"CLEARTEXT.HEX": { size: null, salted: false, encoded: true, algorithm: null,     crypt: false  },
		MD5:       { size: 16,   salted: false, encoded: true,  algorithm: 'md5',    crypt: '$1$'  },
		SHA:       { size: 20,   salted: false, encoded: true,  algorithm: 'sha1',   crypt: false  },
		SHA1:      { size: 20,   salted: false, encoded: true,  algorithm: 'sha1',   crypt: false  },
		SHA256:    { size: 32,   salted: false, encoded: true,  algorithm: 'sha256', crypt: false  },
		SHA512:    { size: 64,   salted: false, encoded: true,  algorithm: 'sha512', crypt: false  },
		SMD5:      { size: 16,   salted: true,  encoded: true,  algorithm: 'md5',    crypt: false  },
		SSHA:      { size: 20,   salted: true,  encoded: true,  algorithm: 'sha1',   crypt: false  },
		SSHA256:   { size: 32,   salted: true,  encoded: true,  algorithm: 'sha256', crypt: false  },
		SSHA512:   { size: 64,   salted: true,  encoded: true,  algorithm: 'sha512', crypt: false  }
	};

function Dovehash(str) {
	this.encoded = str;
	this.parse();
}
Dovehash.prototype.parse = function() {
	if (!this.encoded) { return; }

	this.scheme = null;                   // hash name (e.g. SSHA)
	this.salt = null;                     // password salt as hex
	this.encoding = DEFAULT_ENCODING;     // input string encoding (either hex or base64)
	this.pwhash = null;                   // hex-encoded hash of the password (after decoding and stripping of scheme and salt)
	this.hash = this.encoded;             // original input hash (before decoding)

	var ridx, didx;
	// strip scheme from input string to this.scheme (e.g., "SSHA" from "{SSHA}somehashfollows")
	if ((this.encoded.charAt(0) === '{') && ((ridx = this.encoded.indexOf('}')) > 0)) {
		this.scheme = this.encoded.substring(1, ridx).toUpperCase();
		this.hash = this.encoded.substr(ridx + 1);
	}
	if (HASH[this.scheme] && !HASH[this.scheme].encoded) {
		this.encoding = null;
	}
	// if scheme defines some custom encoding, strip this encoding to this.encoding
	if (this.scheme && (didx = this.scheme.indexOf('.')) > 0) {
		this.encoding = this.scheme.substr(didx + 1);
		this.scheme = this.scheme.substr(0, didx);
	}
	this.conf = HASH[this.scheme + '.' + this.encoding] || HASH[this.scheme] || {};
	// decode original password hash and strip salt to this.salt if there is any
	this.decode(this.hash);
	// if (this.has_salt(this.scheme) && HASHSIZE[this.scheme]) {
	// 	this.salt =
	// }
};
Dovehash.prototype.decode = function(hash) {
	if (!this.encoding) {
		this.pwhash = hash;
		return;
	}
	var e = this.encoding.toLowerCase(),
		buf;
	if (['b64', 'base64', 'hex'].indexOf(e) < 0) { return; }
	if (e === 'hex') {
		buf = new Buffer(hash, 'hex');
	} else {
		buf = new Buffer(hash, 'base64');
	}
	this.pwhash = this.conf.encoded ? buf.toString('hex') : buf.toString();
	// console.log('decode', this.pwhash);
	if (this.conf.crypt && hash.indexOf(this.conf.crypt) === 0) {
		throw new Error("Dovehash: crypt hashes are currently not supported");
		// console.log('crypt');
		var rpw = buf.toString().substr(this.conf.crypt.length),
			rsidx = Math.min(rpw.indexOf('$'), 8),
			rsalt = rpw.substr(0, rsidx),
			rhash = rpw.substr(rsidx + 1);
		this.pwhash = rhash;
		this.salt = rsalt;
	}
	// console.log('salt bytes', 138, 33, 110, 86);
	// console.log('before stripping', e, hash, buf);
	if (this.conf.salted) {
		this.pwhash = buf.toString('hex', 0, this.conf.size);
		this.salt = new Buffer(buf.toString('hex', this.conf.size), 'hex');
		// this.salt = this.pwhash.substr(HASH[this.scheme].size * 2);
		// console.log('salted sub', this.scheme, this.encoding, this.conf.size, this.pwhash, this.salt, this.salt.readUInt32BE(0));
		// var sbuf = new Buffer(sub, 'hex');
		// this.salt = sbuf.readUInt32LE(0);
		// this.pwhash = this.pwhash.substr(0, HASH[this.scheme].size * 2);
	}
};
Dovehash.prototype.toJSON = function() {
	return {
		input: this.encoded,
		scheme: this.scheme,
		encoding: this.encoding,
		salt: this.salt && this.salt.readUInt32BE ? this.salt.readUInt32BE(0) : this.salt,
		password: this.pwhash
	};
};
Dovehash.prototype.equals = function(pw) {
	// console.log(this.toJSON());
	if (!this.scheme || !this.conf || !this.conf.algorithm) {
		if (this.conf.encoded) {
			var b = new Buffer(pw);
			return this.pwhash === b.toString(this.encoding.toUpperCase() === "HEX" ? 'hex' : 'base64');
		} else {
			return this.pwhash === pw;
		}
	}
	var hash, digest;
	if (this.conf.crypt) {
		throw new Error("Dovehash: crypt hashes are currently not supported");
		// var x = crypt3(pw, this.salt);
		// console.log('x', pw, this.salt, x, this.pwhash);
	} else {
		hash = crypto.createHash(HASH[this.scheme].algorithm);
		hash.update(pw);
		if (this.salt) {
			hash.update(this.salt);
		}
		digest = hash.digest('hex');
		// console.log('equals', this.conf.algorithm, pw, this.salt, digest, digest === this.pwhash);
		return digest === this.pwhash;
	}
};
Dovehash.prototype.encode = function(pw, enc) {
	return Dovehash.encode(this.scheme, pw, this.salt, enc);
};

Dovehash.int2buffer = function(int) {
	if (typeof int === "undefined" || int === null) { return; }
	if (int.constructor === Buffer) { return int; }
	var b = new Buffer(4);
	b.writeUInt32BE(int, 0);
	return b;
};

Dovehash.buffer2int = function(buf) {
	if (typeof buf === "undefined" || buf === null) { return; }
	if (buf.constructor !== Buffer) { return buf; }
	return buf.readUInt32BE(0);
};

Dovehash.getSalt = function(hash) {
	var dh = new Dovehash(hash);
	return dh.salt;
};

Dovehash.encode = function(scheme, pw, salt, enc) {
	scheme = scheme.toUpperCase();
	if (scheme.indexOf('.') > 0) {
		if (typeof enc === "undefined") {
			enc = scheme.substr(scheme.indexOf('.') + 1);
		}
		scheme = scheme.substr(0, scheme.indexOf('.'));
	}
	var conf = HASH[scheme + '.' + enc] || HASH[scheme];
	enc = enc ? enc.toLowerCase() : enc;
	if (!conf) { throw new Error("Dovehash.encode: wrong scheme " + scheme); }
	var hex = enc === "hex" ? true : false,
		salted = conf.salted && typeof salt !== "undefined",
		prefix = hex ? scheme + '.hex' : scheme,
		s = Dovehash.int2buffer(salt),
		hash, len, encoded, buf, hd;
	// console.log('conf', conf, enc, hex);

	len = (conf.size || pw.length) + (salted && s ? s.length : 0);
	buf = new Buffer(len);

	if (conf.algorithm) {
		hash = crypto.createHash(conf.algorithm);

		hash.update(pw);
		if (salted) { hash.update(s); }
		hd = hash.digest();
		// console.log('encode', len, buf.length, s.length, hd.length);
		hd.copy(buf);
		if (salted) {
			s.copy(buf, hd.length);
		}
	} else {
		buf.write(pw);
		// console.log('not encoded', buf, pw, len);
	}

	encoded = '{' + prefix + '}';
	if (conf.encoded) {
		encoded += buf.toString(hex ? 'hex' : 'base64');
	} else {
		encoded += buf.toString();
	}
	// console.log('encoded', encoded);
	return encoded;
};

Dovehash.equals = function(hash, pw) {
	return new Dovehash(hash).equals(pw);
};
