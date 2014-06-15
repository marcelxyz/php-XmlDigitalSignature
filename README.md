# XML Digital Signature for PHP

This library was created to sign arbitrary data and whole XML documents using XML digital signatures as per the [W3 recommendation](http://www.w3.org/TR/xmldsig-core/) using PHP. The code for this class was inspired by the [xmlseclibs library](https://code.google.com/p/xmlseclibs/), which I found impossible to work with due to its lack of documentation and the fact that the signed documents it produced did not validate properly.

Should this class generate documents that do not validate (as there are many different specs for these signatures, of which I have tested only a handful), please contact me and I will do my best to provide support for your needs.

## Options for generating and signing documents (AKA how to use this lib)

### Digest (hashing) methods

This library currently supports four digest methods, those being:

- [SHA1](http://www.w3.org/2000/09/xmldsig#sha1) (`XmlDsig\XmlDigitalSignature::DIGEST_SHA1`)
- [SHA256](http://www.w3.org/2001/04/xmlenc#sha256) (`XmlDsig\XmlDigitalSignature::DIGEST_SHA256`)
- [SHA512](http://www.w3.org/2001/04/xmlenc#sha512) (`XmlDsig\XmlDigitalSignature::DIGEST_SHA512`)
- [RIPMED-160](http://www.w3.org/2001/04/xmlenc#ripemd160) (`XmlDsig\XmlDigitalSignature::DIGEST_RIPEMD160`)

Your version of PHP must provide support for the digest method you choose. This library will check this automatically, but you can also do this yourself by calling PHP's `hash_algos()` function.

By default, the SHA1 digest is used. If you wish to use a different digest, call the `XmlDsig\XmlDigitalSignature::setDigestMethod()` method with the appropriate `XmlDsig\XmlDigitalSignature::DIGEST_*` constant.

If you would like to add support for a different hashing method (provided, of course, that your version of PHP supports it), add a new `XmlDsig\XmlDigitalSignature::DIGEST_*` const with a value defined in `hash_algos()`. Remember to add the proper mapping values to the following class properties: `$digestMethodUriMapping`, `$openSSLAlgoMapping`, `$digestSignatureAlgoMapping` (read the `@see` notes in the comments of these properties for more information).

### Canonicalization (C14N) methods

This lib currently supports the following canonicalization methods:

- [Canonical XML](http://www.w3.org/TR/2001/REC-xml-c14n-20010315) (`XmlDsig\XmlDigitalSignature::C14N`)
- [Canonical XML with comments](http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments) (`XmlDsig\XmlDigitalSignature::C14N_COMMENTS`)
- [Exclusive canonical XML](http://www.w3.org/2001/10/xml-exc-c14n#) (`XmlDsig\XmlDigitalSignature::C14N_EXCLUSIVE`)
- [CExclusive canonical XML with comments](http://www.w3.org/2001/10/xml-exc-c14n#WithComments) (`XmlDsig\XmlDigitalSignature::C14N_EXCLUSIVE_COMMENTS`)

These can be extended as needed, by adding the necessary class constants. If you do add a new canonicaliation method, remember to add its specific options to the `XmlDsig\XmlDigitalSignature::$c14nOptionMapping` array.

By default, the Canonical XML method is used. In order to specify a different C14N method, call the `XmlDsig\XmlDigitalSignature::setCanonicalMethod()` method, with the appropriate `XmlDsig\XmlDigitalSignature::C14N_*` constant as the argument.

### Standalone XML

By default, the generated XML document is created with the standalone pseudo-attribute set to `no`. In order to change this, simply call the `XmlDsig\XmlDigitalSignature::forceStandalone()` method.

### Node namespace prefixes

By default, all nodes in the generated XML document have a namespace prefix of `dsig:`. If you would like to specify a different ns prefix (or you don't want to use one at all), simply pass the appropriate value to the `XmlDsig\XmlDigitalSignature::setNodeNsPrefix()` method.

## Public/private key pair generation

There are many ways to generate a key pair, however below are examples of RSA key generation using OpenSSL (unix terminal).

### Private RSA key

	openssl genrsa -aes256 -out private.pem 2048

The above command will generate a private AES256 RSA key with a 2048 modulus. Setting a passphrase is highly recommended.

### Public key (PEM format)

	openssl rsa -in private.pem -pubout -out public.pem

The above command generates a public certificate in PEM format, based on the previously generated (or already existing) private key.

### Public key (X.509 format)

	openssl req -x509 -new -key private.pem -days 3650 -out public.crt

The above command generates a public X.509 certificate valid for 3650 days. You will also be prompted for some trivial information needed to generate this certificate (CSR). The resulting key is also known as a self signed certificate.

### Public key (XML format)

If you need the public key to be attached to the signed XML document in XML format, you will first have to generate a public certificate (either in PEM or X.509 format). Once you have done this, you can convert your key to an XML format.

Public RSA X.509 certificates can be converted to XML format using [http://tools.ailon.org/tools/XmlKey](http://tools.ailon.org/tools/XmlKey).

Public RSA PEM certificates, on the other hand, can be converted to XML format using [https://superdry.apphb.com/tools/online-rsa-key-converter](https://superdry.apphb.com/tools/online-rsa-key-converter).

### Loading the generated keys

Once you have generated the appropriate private, public and XML keys (if necessary), you can load them using the `XmlDsig\XmlDigitalSignature::loadPrivateKey()`, `XmlDsig\XmlDigitalSignature::loadPublicKey()`, `XmlDsig\XmlDigitalSignature::loadPublicXmlKey()` methods, respectively.

## Adding objects

Object data (strings or DOMNodes) can be added to the XML document using the `XmlDsig\XmlDigitalSignature::addObject()` method. If the value of the object needs to be hashed, be sure to pass `true` as the third paramater of the aforementioned method.

The resulting data will be placed inside of an `<Object/>` node, and an appropriate `<Reference/>` element set will be generated, containing the digest of the object.

## Signing the document

What may seem trivial by now, you sign the generated XML document using the `XmlDsig\XmlDigitalSignature::sign()` method. Of course, be sure to watch out for the return values of the method and any exceptions it might throw.

## Verifying the signatures

In turn, signatures may be verified using the `XmlDsig\XmlDigitalSignature::verify()` method.

## Returning the document

`XmlDsig\XmlDigitalSignature::getSignedDocument()` returns the canonicalized XML markup, as a string.

## Verifying the document validity

Other than writing a whole parser to verify the generated document, I recommend that you use this online tool: [http://www.aleksey.com/xmlsec/xmldsig-verifier.html](http://www.aleksey.com/xmlsec/xmldsig-verifier.html).