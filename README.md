# XML Digital Signature for PHP

This library was created to sign arbitrary data and whole XML documents using XML digital signatures as per the [W3 recommendation](http://www.w3.org/TR/xmldsig-core/) using PHP. The code for this class was inspired by the [xmlseclibs library](https://code.google.com/p/xmlseclibs/), which I found impossible to work with due to its lack of documentation and the fact that the signed documents it produced did not validate properly.

Should this class generate documents that do not validate (as there are many different specs for these signatures, of which I have tested only a handful), please contact me and I will do my best to provide support for your needs.

# Installation

Using composer:

    php composer.phar require "marcelxyz/php-xml-digital-signature"

Alternatively require the `src/XmlDigitalSignature.php` file in your project.

# Examples

Here's a basic overview of how to use this library:

```php
$dsig = new XmlDsig\XmlDigitalSignature();

$dsig->loadPrivateKey('path/to/private/key', 'passphrase');
$dsig->loadPublicKey('path/to/public/key');

$dsig->addObject('I am a data blob.');
$dsig->sign();

$result = $dsig->getSignedDocument();
```

Please see the `examples/` folder for more elaborate examples.

# API docs

To sign an XML document you need to answer the following questions:

1. Which signature algorithm (RSA/DSA/ECDSA etc.) will you be using?
2. Which digest (hashing) method will you be using?
3. Which C14N (canonicalization) method will you be using?
4. Do you want to include public key information within the resulting XML document?

These are covered in the following subsections.

## Configuration

### Signature algorithm

The following signature algorithms are currently supported:

- [DSA](https://www.w3.org/TR/xmlsec-algorithms/#DSA) (`XmlDsig\XmlDigitalSignature::DSA_ALGORITHM`)
- [RSA](https://www.w3.org/TR/xmlsec-algorithms/#RSA) (`XmlDsig\XmlDigitalSignature::RSA_ALGORITHM`)
- [Elliptic Curve DSA](https://www.w3.org/TR/xmlsec-algorithms/#ECDSA) (`XmlDsig\XmlDigitalSignature::ECDSA_ALGORITHM`)
- [HMAC](https://www.w3.org/TR/xmlsec-algorithms/#hmac) (`XmlDsig\XmlDigitalSignature::HMAC_ALGORITHM`)

Specify the appropriate one using the `XmlDsig\XmlDigitalSignature.setCryptoAlgorithm(algo)` method with the appropriate `XmlDsig\XmlDigitalSignature::*_ALGORITHM` constant.

Default: RSA.

### Digest method

This library currently supports four digest methods, those being:

- [SHA1](http://www.w3.org/2000/09/xmldsig#sha1) (`XmlDsig\XmlDigitalSignature::DIGEST_SHA1`)
- [SHA256](http://www.w3.org/2001/04/xmlenc#sha256) (`XmlDsig\XmlDigitalSignature::DIGEST_SHA256`)
- [SHA512](http://www.w3.org/2001/04/xmlenc#sha512) (`XmlDsig\XmlDigitalSignature::DIGEST_SHA512`)
- [RIPMED-160](http://www.w3.org/2001/04/xmlenc#ripemd160) (`XmlDsig\XmlDigitalSignature::DIGEST_RIPEMD160`)

Your version of PHP must provide support for the digest method you choose. This library will check this automatically, but you can also do this yourself by calling PHP's [hash_algos()](http://php.net/manual/en/function.hash-algos.php) function.

Specify the appropriate digest by calling the `XmlDsig\XmlDigitalSignature.setDigestMethod(digest)` method with the appropriate `XmlDsig\XmlDigitalSignature::DIGEST_*` constant.

To add support for a different hashing method (provided your version of PHP supports it), add a new `XmlDsig\XmlDigitalSignature::DIGEST_*` const with a value defined in `hash_algos()`. Remember to add the proper mapping values to the following class properties: `$digestMethodUriMapping`, `$openSSLAlgoMapping`, `$digestSignatureAlgoMapping` (read the `@see` notes in the comments of these properties for more information).

Default: SHA1.

### C14N methods

This lib currently supports the following canonicalization methods:

- [Canonical XML](http://www.w3.org/TR/2001/REC-xml-c14n-20010315) (`XmlDsig\XmlDigitalSignature::C14N`)
- [Canonical XML with comments](http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments) (`XmlDsig\XmlDigitalSignature::C14N_COMMENTS`)
- [Exclusive canonical XML](http://www.w3.org/2001/10/xml-exc-c14n#) (`XmlDsig\XmlDigitalSignature::C14N_EXCLUSIVE`)
- [Exclusive canonical XML with comments](http://www.w3.org/2001/10/xml-exc-c14n#WithComments) (`XmlDsig\XmlDigitalSignature::C14N_EXCLUSIVE_COMMENTS`)

These can be extended by adding the necessary class constants. If you do add a new C14N method, remember to add its specific options to the `XmlDsig\XmlDigitalSignature::$c14nOptionMapping` array.

In order to specify a different C14N method, call the `XmlDsig\XmlDigitalSignature.setCanonicalMethod(c14n)` method with the appropriate `XmlDsig\XmlDigitalSignature::C14N_*` constant.

Default: Canonical XML.

### Standalone XML

To force the resulting XML to contain the standalone pseudo-attribute set to `yes` simply call the `XmlDsig\XmlDigitalSignature.forceStandalone()` method.

Default: `no`.

### Node namespace prefixes

To specify a different ns prefix (or you don't want to use one at all), simply pass the appropriate value to the `XmlDsig\XmlDigitalSignature.setNodeNsPrefix(prefix)` method.

Default: `dsig`.

## Public/private key generation

Skip this section and go to [usage](#usage) if your key pairs are already generated.

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

## Usage

Once you have generated your keys and configured the environment then you are ready to start loading keys and adding objects. The methods are explained below.

### Loading the generated keys

Once you have generated the appropriate private, public and XML keys (if necessary), you can load them using the `XmlDsig\XmlDigitalSignature.loadPrivateKey()`, `XmlDsig\XmlDigitalSignature.loadPublicKey()`, `XmlDsig\XmlDigitalSignature.loadPublicXmlKey()` methods, respectively.

### Adding objects

Object data (strings or DOMNodes) can be added to the XML document using the `XmlDsig\XmlDigitalSignature.addObject()` method. If the value of the object needs to be hashed, be sure to pass `true` as the third paramater of the aforementioned method.

The resulting data will be placed inside of an `<Object/>` node, and an appropriate `<Reference/>` element set will be generated, containing the digest of the object.

### Signing the document

What may seem trivial by now, you sign the generated XML document using the `XmlDsig\XmlDigitalSignature.sign()` method. Of course, be sure to watch out for the return values of the method and any exceptions it might throw.

### Verifying the signatures

In turn, signatures may be verified using the `XmlDsig\XmlDigitalSignature.verify()` method.

Additionally you can use the [Aleksey validator](http://www.aleksey.com/xmlsec/xmldsig-verifier.html) to check dsigs. However, be aware that this validator is faulty. Namely:

1. The public key must be embedded into the XML markup.
2. Valid documents that are "pretty-printed" fail validation, but pass once the extra tabs/newlines are removed.
3. It only works with RSA encryption.

### Returning the document

`XmlDsig\XmlDigitalSignature.getSignedDocument()` returns the canonicalized XML markup as a string.