<?php

namespace XmlDsig\Test;

use \PHPUnit\Framework\Error\Warning;
use \PHPUnit\Framework\TestCase;
use \PHPUnit\Util\Xml;
use XmlDsig\XmlDigitalSignature;

class XmlDigitalSignatureTest extends TestCase {
    const PRIVATE_KEY_PASSPHRASE = 'MrMarchello';
    const DATA_DIR = __DIR__ . '/data/';
    const PRIVATE_KEY = self::DATA_DIR . 'keys/private.pem';
    const PUBLIC_KEY = self::DATA_DIR . 'keys/public.pem';
    const PUBLIC_XML_KEY = self::DATA_DIR . 'keys/public.xml';

    /**
     * @var XmlDigitalSignature
     */
    private $dsig;

    /**
     * @var \DOMDocument
     */
    private $doc;

    protected function setUp() {
        $this->dsig = new XmlDigitalSignature();
    }

    /**
     * Test whether a malformed reference causes an exception.
     */
    public function testAddBadReference() {
        $this->expectException(\UnexpectedValueException::class);
        $node = $this
            ->getMockBuilder(\DOMNode::class)
            ->setMethods(['C14N'])
            ->getMock();
        $this->dsig->addReference($node);
    }

    /**
     * Test whether keys load successfully.
     */
    public function testLoadKeys() {
        $result = $this->dsig->loadPrivateKey(self::PRIVATE_KEY, self::PRIVATE_KEY_PASSPHRASE);
        $this->assertTrue($result);

        $result = $this->dsig->loadPrivateKey(file_get_contents(self::PRIVATE_KEY), self::PRIVATE_KEY_PASSPHRASE, false);
        $this->assertTrue($result);

        $result = $this->dsig->loadPublicKey(self::PUBLIC_KEY);
        $this->assertTrue($result);

        $result = $this->dsig->loadPublicKey(file_get_contents(self::PUBLIC_KEY), false);
        $this->assertTrue($result);

        $result = $this->dsig->loadPublicXmlKey(file_get_contents(self::PUBLIC_XML_KEY), false);
        $this->assertTrue($result);

        $result = $this->dsig->loadPublicXmlKey(self::PUBLIC_XML_KEY);
        $this->assertTrue($result);
    }

    /**
     * Test whether a malformed private key causes an exception.
     */
    public function testBadPrivateKey() {
        $this->expectException(\UnexpectedValueException::class);
        $this->dsig->loadPrivateKey('abc', null, false);
    }

    /**
     * Test whether a nonexistent private key path causes an exception.
     */
    public function testBadPrivateKeyPath() {
        $this->expectException(\UnexpectedValueException::class);
        $this->dsig->loadPrivateKey(self::PRIVATE_KEY . 'a');
    }

    /**
     * Test whether an incorrect private key passphrase causes an exception.
     */
    public function testBadPrivateKeyPassphrase() {
        $this->expectException(\UnexpectedValueException::class);
        $this->dsig->loadPrivateKey(self::PRIVATE_KEY, self::PRIVATE_KEY_PASSPHRASE . 'a');
    }

    /**
     * Test whether a malformed public key causes an exception.
     */
    public function testBadPublicKey() {
        $this->expectException(\UnexpectedValueException::class);
        $this->dsig->loadPublicKey('abc', false);
    }

    /**
     * Test whether a nonexistent public key path causes an exception.
     */
    public function testBadPublicKeyPath() {
        $this->expectException(\UnexpectedValueException::class);
        $this->dsig->loadPublicKey(self::PUBLIC_KEY . 'a');
    }

    /**
     * Test whether a malformed public XML key causes an exception.
     */
    public function testBadPublicXmlKey() {
        $this->expectException(\UnexpectedValueException::class);
        $this->dsig->loadPublicXmlKey('abc', false);
    }

    /**
     * Test whether loading from a nonexistent public XML key path causes an exception.
     */
    public function testBadPublicXmlKeyPath() {
        $this->expectException(\UnexpectedValueException::class);
        $this->dsig->loadPublicXmlKey(self::PUBLIC_XML_KEY . 'a');
    }

    /**
     * Test whether setting a malformed crypto algorithm causes an exception.
     */
    public function testSetBadCryptoAlgorithm() {
        $this->expectException(Warning::class);
        $this->dsig->setCryptoAlgorithm(-1);
    }

    /**
     * Test whether setting a malformed canonical method causes an exception.
     */
    public function testSetBadCanonicalMethod() {
        $this->expectException(Warning::class);
        $this->dsig->setCanonicalMethod(XmlDigitalSignature::C14N_EXCLUSIVE . 'a');
    }

    /**
     * Test whether setting a malformed digest method causes an exception.
     */
    public function testSetBadDigestMethod() {
        $this->expectException(Warning::class);
        $this->dsig->setDigestMethod(XmlDigitalSignature::DIGEST_SHA512 . 'a');
    }

    /**
     * Test whether a valid object is successfully added.
     */
    public function testAddObject() {
        $result = $this->dsig->addObject('a');
        $this->assertTrue($result);
    }

    /**
     * Test whether adding an empty object causes an exception.
     */
    public function testAddEmptyObjectString() {
        $this->expectException(\UnexpectedValueException::class);
        $this->dsig->addObject('');
    }

    /**
     * Test whether adding a malformed object causes an exception.
     */
    public function testAddBadObject() {
        $this->expectException(\UnexpectedValueException::class);
        $this->dsig->addObject(new \stdClass());
    }

    /**
     * Test whether a valid reference is successfully added.
     */
    public function testAddReference() {
        $result = $this->dsig->addReference(Xml::load('<foo></foo>'));
        $this->assertTrue($result);
    }

    /**
     * Test the whole signing process, with all the options.
     */
    public function testSigningProcess() {
        $this->dsig->setCanonicalMethod(XmlDigitalSignature::C14N_EXCLUSIVE_COMMENTS);
        $this->dsig->setCryptoAlgorithm(XmlDigitalSignature::HMAC_ALGORITHM);
        $this->dsig->setDigestMethod(XmlDigitalSignature::DIGEST_SHA256);
        $this->dsig->setNodeNsPrefix('xyz');

        $result = $this->dsig->loadPrivateKey(self::PRIVATE_KEY, self::PRIVATE_KEY_PASSPHRASE);
        $this->assertTrue($result);

        $result = $this->dsig->loadPublicKey(self::PUBLIC_KEY);
        $this->assertTrue($result);

        $result = $this->dsig->loadPublicXmlKey(self::PUBLIC_XML_KEY);
        $this->assertTrue($result);

        $result = $this->dsig->addObject('a', 'objectA');
        $this->assertTrue($result);

        $result = $this->dsig->sign();
        $this->assertTrue($result);

        $result = $this->dsig->verify();
        $this->assertTrue($result);

        $this->assertEquals(
            Xml::loadFile(self::DATA_DIR . 'expected-signed.xml')->saveXML(),
            $this->dsig->getSignedDocument()
        );
    }
}