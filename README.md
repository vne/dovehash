dovehash
==========

Node.JS library for working with Dovecot password hashes

Written by Vladimir Neverov <sanguini@gmail.com> in 2015

Homepage: [https://github.com/vne/dovehash/wiki](https://github.com/vne/dovehash/wiki)

Synopsis
--------

Dovecot mail server uses its own special data format to store hashed passwords in databases. This is covered in details
in [Dovecot wiki](http://wiki2.dovecot.org/Authentication/PasswordSchemes). This library is intended to support
this kind of password encoding in Node.JS applications, because it is convenient to have one common password storage
format.

As for now, Dovehash works only with a subset of hashing schemes supported by Dovecot:
PLAIN, CLEARTEXT, SHA, SHA1, SHA256, SHA512, SMD5, SSHA, SSHA256 and SSHA512.
Pull requests are welcomed. Support for more hashing schemes is planned.

Simple MD5 is **NOT** supported due to weird calculation scheme used in Dovecot (see password\_generate\_md5\_crypt function in Dovecot sources at [src/auth/password-scheme-md5crypt.c](http://hg.dovecot.org/dovecot-2.2/file/3d612ade5d75/src/auth/password-scheme-md5crypt.c) for more).

Both base64 and hex encodings are supported, base64 is the default (as it is in Dovecot).

Library makes use of Node.JS Buffer class and can not be used in browser without some helper library (e.g., [this one](https://github.com/feross/buffer)).
This behavior is not tested yet.

Usage
-----

First, you should require the library

	var Dovehash = require('dovehash');

Then, if you have some hashed and, probably, salted password in Dovecot style
(e.g. "{SSHA}PTggDCOUPEVj5h7bZjhxfKWQBpey47nF") and a plain password, supplied by user, (e.g. "abcdef")
you can easily check them for equivalence:

	var passwordsMatch = Dovehash.equals(hashedPassword, userSuppliedPassword);

If you have a plain password and want to encode it using one of the supported schemes:

	var encoded = Dovehash.encode('SSHA', yourPlainPassword, salt);

Note that currently salt is not generated automatically if nothing is supplied.

Finally, you can create a Dovehash instance for hashed password:

	var dh = new Dovehash(hashedPassword);
	console.log(dh.toJSON());

This will parse hashed password and give you access to hashing algorithm, encoding, password hash and salt.

Testing
-------

Some examples of library usage can be found in **test.js** file. To run tests you will
need [Mocha](http://visionmedia.github.io/mocha/), the tests themselves use built-in
NodeJS [assert](http://nodejs.org/api/assert.html) module
