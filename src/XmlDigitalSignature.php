<?php

namespace XmlDsig;

/**
 * Produces an XML digital signature compatible with the recommendations of the W3.
 * 
 * Based on the chosen canonicalization method (one of the class constants), the final
 * document is properly canonicalized and signed using one of the selected hashing (digest)
 * methods (also a class const).
 * 
 * @author		Marcel Tyszkiewicz
 * @license		MIT http://opensource.org/licenses/MIT
 * @link		https://github.com/marcelxyz/php-XmlDigitalSignature
 * @copyright	2014
 */
class XmlDigitalSignature
{
	/**
	 * Digital signature namespace, as required by the W3 recommendation
	 * @var string
	 */
	const XML_DSIG_NS = 'http://www.w3.org/2000/09/xmldsig#';
	
	/**
	 * SHA1 hashing algorithm
	 * @var string
	 */
	const DIGEST_SHA1 = 'sha1';
	
	/**
	 * SHA256 hashing algorithm
	 * @var string
	 */
	const DIGEST_SHA256 = 'sha256';
	
	/**
	 * SHA512 hashing algorithm
	 * @var string
	 */
	const DIGEST_SHA512 = 'sha512';
	
	/**
	 * RIPEMD-160 hashing algorithm
	 * @var string
	 */
	const DIGEST_RIPEMD160 = 'ripemd160';

	/**
	 * Standard XML canonicalization method, as per the W3 spec
	 * @var string
	 */
	const C14N = 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315';

	/**
	 * Standard XML canonicalization method with comments, as per the W3 spec
	 * @var string
	 */
	const C14N_COMMENTS = 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments';

	/**
	 * Exclusive XML canonicalization method, as per the W3 spec
	 * @var string
	 */
	const C14N_EXCLUSIVE = 'http://www.w3.org/2001/10/xml-exc-c14n#';

	/**
	 * Exclusive XML canonicalization method with comments, as per the W3 spec
	 * @var string
	 */
	const C14N_EXCLUSIVE_COMMENTS = 'http://www.w3.org/2001/10/xml-exc-c14n#WithComments';
	
	/**
	 * RSA algorithm
	 * @var int
	 */
	const RSA_ALGORITHM = 1;
	
	/**
	 * DSA algorithm
	 * @var int
	 */
	const DSA_ALGORITHM = 2;
	
	/**
	 * Elliptic Curve DSA algorithm
	 * @var int
	 */
	const ECDSA_ALGORITHM = 3;
	
	/**
	 *  HMAC algoritm (keyed-hash message authentication code)
	 * @var int
	 */
	const HMAC_ALGORITHM = 4;
	
	/**
	 * Mapping of digest algorithms to their W3 spec URIs. Based on the selected
	 * digest algorithm, one of these values will be placed inside the Algorithm
	 * attribute of the <DigestMethod/> node (allowing the receiving party to
	 * properly verify the integrity of the received data).
	 * 
	 * @see http://www.w3.org/TR/xmlsec-algorithms/#digest-method-uris
	 * @var array
	 */
	protected $digestMethodUriMapping = array(
		self::DIGEST_SHA1		=> 'http://www.w3.org/2000/09/xmldsig#sha1',
		self::DIGEST_SHA256		=> 'http://www.w3.org/2001/04/xmlenc#sha256',
		self::DIGEST_SHA512		=> 'http://www.w3.org/2001/04/xmlenc#sha512',
		self::DIGEST_RIPEMD160	=> 'http://www.w3.org/2001/04/xmlenc#ripemd160',
	);
	
	/**
	 * Mapping of digest methods to their appropriate OpenSSL hashing algorithms.
	 * These values must be compatible with the openssl_sign() and openssl_verify()
	 * functions.
	 * 
	 * @see http://www.php.net/manual/en/openssl.signature-algos.php
	 * @var array
	 */
	protected $openSSLAlgoMapping = array(
		self::DIGEST_SHA1		=> OPENSSL_ALGO_SHA1,
		self::DIGEST_SHA256		=> OPENSSL_ALGO_SHA256,
		self::DIGEST_SHA512		=> OPENSSL_ALGO_SHA512,
		self::DIGEST_RIPEMD160	=> OPENSSL_ALGO_RMD160,
	);
	
	/**
	 * Mapping of key cryptography algorithms to their respective W3 spec URIs,
	 * based on the selected digest method and crypto algorithm.
	 * 
	 * @see http://www.w3.org/TR/xmlsec-algorithms/#signature-method-uris
	 * @var array
	 */
	protected $digestSignatureAlgoMapping = array(
		self::RSA_ALGORITHM		=> array(
			self::DIGEST_SHA1		=> 'http://www.w3.org/2000/09/xmldsig#rsa-sha1',
			self::DIGEST_SHA256		=> 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
			self::DIGEST_SHA512		=> 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512',
			self::DIGEST_RIPEMD160	=> 'http://www.w3.org/2001/04/xmldsig-more#rsa-ripemd160',
		),
		self::DSA_ALGORITHM		=> array(
			self::DIGEST_SHA1		=> 'http://www.w3.org/2000/09/xmldsig#dsa-sha1',
			self::DIGEST_SHA256		=> 'http://www.w3.org/2009/xmldsig11#dsa-sha256',
			// DSA does not support SHA512 or RIPMED160
			// see http://tools.ietf.org/html/rfc5754#section-3.1 for more info
		),
		self::ECDSA_ALGORITHM	=> array(
			self::DIGEST_SHA1		=> 'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha1',
			self::DIGEST_SHA256		=> 'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256',
			self::DIGEST_SHA512		=> 'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384',
			self::DIGEST_RIPEMD160	=> 'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha51',
		),
		self::HMAC_ALGORITHM	=> array(
			self::DIGEST_SHA1		=> 'http://www.w3.org/2000/09/xmldsig#hmac-sha1',
			self::DIGEST_SHA256		=> 'http://www.w3.org/2001/04/xmldsig-more#hmac-sha256',
			self::DIGEST_SHA512		=> 'http://www.w3.org/2001/04/xmldsig-more#hmac-sha512',
			self::DIGEST_RIPEMD160	=> 'http://www.w3.org/2001/04/xmldsig-more#hmac-ripemd160',
		),
	);
	
	/**
	 * Mapping of canonicalization attributes, based on the selected C14N method.
	 * These must match those required by the DOMNode::C14N() method and the
	 * W3 recommendations.
	 * 
	 * @var array
	 */
	protected $c14nOptionMapping = array(
		self::C14N						=> array('exclusive' => false, 'withComments' => false),
		self::C14N_COMMENTS				=> array('exclusive' => false, 'withComments' => true),
		self::C14N_EXCLUSIVE			=> array('exclusive' => true, 'withComments' => false),
		self::C14N_EXCLUSIVE_COMMENTS	=> array('exclusive' => true, 'withComments' => true),
	);
	
	/**
	 * XML document to sign
	 * @var DOMDocument
	 */
	protected $doc;
	
	/**
	 * OpenSSL handle to the private key used to sign the XML document
	 * @var resource
	 */
	protected $privateKey;
	
	/**
	 * OpenSSL handle to the public key to include in the XML document
	 * @var resource
	 */
	protected $publicKey;
	
	/**
	 * XML canonicalization method to use to canonicalize the document
	 * @var string
	 */
	protected $canonicalMethod = self::C14N;
	
	/**
	 * Hashing algorithm to use for the digest
	 * @var string
	 */
	protected $digestMethod = self::DIGEST_SHA1;
	
	/**
	 * Cryptography algorithm of the private key
	 * @var int
	 */
	protected $cryptoAlgorithm = self::RSA_ALGORITHM;
	
	/**
	 * XML standalone declaration
	 * @var bool
	 */
	protected $standalone = false;
	
	/**
	 * Namespace prefix for each node name
	 * @var string
	 */
	protected $nodeNsPrefix = 'dsig:';
	
	/**
	 * Sets the cryptography algorithm used to generate the private key.
	 * 
	 * @param	int					$algo	Algorithm type (class const)
	 * @return	XmlDigitalSignature
	 */
	public function setCryptoAlgorithm($algo)
	{
		if (!array_key_exists($algo, $this->digestSignatureAlgoMapping))
		{
			trigger_error('The chosen crypto algorithm does not appear to be predefined', E_USER_WARNING);
		}
		else if (!array_key_exists($this->digestMethod, $this->digestSignatureAlgoMapping[$algo]))
		{
			trigger_error('The chosen crypto algorithm does not support the chosen digest method', E_USER_WARNING);
		}
		else
		{
			$this->cryptoAlgorithm = $algo;
		}
		
		return $this;
	}
	
	/**
	 * Sets the namespace prefix for each generated node name.
	 * For example, to create an XML tree with node names of
	 * type <foo:element/>, simply pass the value 'foo' to this method.
	 * 
	 * @param	string				$prefix	The namespace prefix
	 * @return	XmlDigitalSignature
	 */
	public function setNodeNsPrefix($prefix)
	{
		if (is_string($prefix) && strlen($prefix))
		{
			$this->nodeNsPrefix = rtrim($prefix, ':') . ':';
		}
		else
		{			
			$this->nodeNsPrefix = '';
		}
		
		return $this;
	}
	
	/**
	 * Forces the signed XML document to be standalone
	 * 
	 * @return	XmlDigitalSignature
	 */
	public function forceStandalone()
	{
		$this->standalone = true;
		return $this;
	}
	
	/**
	 * Sets the canonical method used to canonicalize the document
	 * 
	 * @param	string				$method	Canonicalization method (class const)
	 * @return	XmlDigitalSignature
	 */
	public function setCanonicalMethod($method)
	{
		if (array_key_exists($method, $this->c14nOptionMapping))
		{
			$this->canonicalMethod = $method;
		}
		else
		{
			trigger_error(sprintf('The chosen canonical method (%s) is not supported', $method), E_USER_WARNING);
		}
		
		return $this;
	}
	
	/**
	 * Sets the digest method (hashing algo) used to calculate the digest of the document
	 * 
	 * @param	string				$method	Digest method (class const)
	 * @return	XmlDigitalSignature
	 */
	public function setDigestMethod($method)
	{
		if (array_key_exists($method, $this->openSSLAlgoMapping) &&
			array_key_exists($method, $this->digestMethodUriMapping))
		{
			$this->digestMethod = $method;
		}
		else
		{
			trigger_error(sprintf('The chosen digest method (%s) is not supported', $method), E_USER_WARNING);
		}
		
		$this->checkDigestSupport();
		
		return $this;
	}
	
	/**
	 * Returns the signed XML document
	 * 
	 * @return	string	Signed XML document
	 */
	public function getSignedDocument()
	{
		return $this->doc->saveXML();
	}
	
	/**
	 * Loads a PEM formatted private key.
	 * 
	 * @param	string	$key				The private key in PEM format or a path to the key (see openssl_pkey_get_private)
	 * @param	string	$passphrase			Password to the key file (if there is one)
	 * @param	bool	$isFile				Whether the key is a path to a file
	 * @return	bool						True if the key was successfully loaded, false otherwise
	 * @throws	\UnexpectedValueException	Thrown if the key cannot be loaded
	 */
	public function loadPrivateKey($key, $passphrase = null, $isFile = true)
	{
		return $this->loadKey($key, $isFile, true, $passphrase);
	}
	
	/**
	 * Loads a public key, either an X.509 cert or PEM formatted key
	 * 
	 * @param	mixed						$key	X.509 cert resource, path to the key, or the key (see openssl_pkey_get_public)
	 * @throws	\UnexpectedValueException			Thrown if the key cannot be loaded
	 * @return	bool								True if the key was successfully loaded, false otherwise
	 */
	public function loadPublicKey($key, $isFile = true)
	{
		return $this->loadKey($key, $isFile);
	}
	
	/**
	 * Loads a public/private key into memory.
	 * 
	 * @param	string						$key		Either the path to the key, or the key as a string
	 * @param	bool						$isFile		Whether the first arg is a path that needs to be opened
	 * @param 	bool						$isPrivate	Whether the key is private
	 * @param	string						$passphrase	If the key is private and has a passphrase, this is the place to give it
	 * @throws	\UnexpectedValueException				Thrown if the key cannot be read, or if OpenSSL does not like it
	 * @return	bool									True if the key is successfully loaded, false otherwise
	 */
	protected function loadKey($key, $isFile, $isPrivate = false, $passphrase = null)
	{
		// load the key from the file, if that's what they say
		if (true === $isFile)
		{
			try
			{
				$key = $this->loadFile($key);
			}
			catch (\UnexpectedValueException $e)
			{
				// up, up and away!
				throw $e;
			}
		}
		
		// handle the key based on whether it's public or private
		if (true === $isPrivate)
		{
			$privKey = openssl_pkey_get_private($key, $passphrase);
			
			if (false === $privKey)
			{
				throw new \UnexpectedValueException('Unable to load the private key');
			}
			
			$this->privateKey = $privKey;
		}
		// good ol' public key
		else
		{
			$pubKey = openssl_pkey_get_public($key);
			
			if (false === $pubKey)
			{
				throw new \UnexpectedValueException('Unable to load the public key');
			}
			
			$this->publicKey = $pubKey;
		}
		
		return true;
	}
	
	/**
	 * Loads a key from a specified file location.
	 * 
	 * @param	string						$filePath	Location of the key to be loaded
	 * @throws	\UnexpectedValueException				Thrown if the file cannot be loaded or is empty
	 * @return	string|bool								False on failure, the key as a string otherwise
	 */
	protected function loadFile($filePath)
	{
		if (!file_exists($filePath) || !is_readable($filePath))
		{
			throw new \UnexpectedValueException(sprintf('Unable to open the "%s" file', $filePath));
		}
			
		$key = @file_get_contents($filePath);
			
		if (!is_string($key) || 0 === strlen($key))
		{
			throw new \UnexpectedValueException(sprintf('File "%s" appears to be empty', $filePath));
		}
		
		return $key;
	}

	/**
	 * Loads a public key in an XML format.
	 * 
	 * The first argument provided to this function can be a path to the key (the second arg must be set to true).
	 * Otherwise, you may pass the actual XML string as the first argument (set the second argument to false).
	 * The third argument is needed to create a reference between the created <KeyValue/> element and its <Reference/>.
	 *
	 * @param	DOMDocument|string			$publicKey	The DOMDocument containing the key, or a path to the key's location, or the key as a string
	 * @param	string						$isFile		If set to true, the key will be loaded from the given path
	 * @param	string						$objectId	ID attribute of the key (used to create a reference between the key and its <Reference/> node)
	 * @throws	\UnexpectedValueException				Thrown when the provided key is in an unsupported format
	 * @return	bool									True if the key was successfully loaded, false otherwise
	 */
	public function loadPublicXmlKey($publicKey, $isFile = true, $objectId = null)
	{
		if (true === $isFile)
		{
			try
			{
				$publicKey = $this->loadFile($publicKey);
			}
			catch (\UnexpectedValueException $e)
			{
				throw $e;
			}
		}
		
		$keyNode = null;
		
		// if the key is a string, assume that it's valid XML markup and load it into a dom docuemnt
		if (is_string($publicKey) && strlen($publicKey))
		{
			$keyNode = new \DOMDocument;
			
			if (!@$keyNode->loadXML($publicKey))
			{
				throw new \UnexpectedValueException('The provided public XML key does not appear to be well structured XML');
			}
		}
		// DOM nodes are sexy as fuck
		else if (is_object($publicKey) && $publicKey instanceof DOMDocument)
		{
			$keyNode = $publicKey;
		}
		// woops, a bad key was provided :(
		else
		{
			throw new \UnexpectedValueException('Unsupported XML public key provided');
		}
		
		// add the key to the DOM
		return $this->appendXmlPublicKey($keyNode, $objectId);
	}
	
	/**
	 * Appends the public XML key to the DOM document.
	 * 
	 * @param	\DOMDocument				$keyDoc		The DOM document containing the public key information
	 * @param	string						$objectId	ID attribute of the key
	 * @throws	\UnexpectedValueException				If the XML tree is not intact
	 * @return	bool									True if the key was successfully appended, false otherwise
	 */
	protected function appendXmlPublicKey(\DOMDocument $keyDoc, $objectId)
	{
		// create the document structure if necessary
		if (is_null($this->doc))
		{
			$this->createXmlStructure();
		}
		
		// local the node to which the key will be appended
		$keyValue = $this->doc->getElementsByTagName($this->nodeNsPrefix . 'KeyValue')->item(0);
		if (is_null($keyValue))
		{
			throw new \UnexpectedValueException('Unabled to locate the KeyValue node');
		}
		
		// we have to add the proper namespace prefixes to all of the nodes in the public key DOM
		$publicKeyNode = $this->doc->createElement($this->nodeNsPrefix . $keyDoc->firstChild->nodeName);
		$keyValue->appendChild($publicKeyNode);
		
		foreach ($keyDoc->firstChild->childNodes as $node)
		{
			$newNode = $this->doc->createElement($this->nodeNsPrefix . $node->nodeName, $node->nodeValue);
			$publicKeyNode->appendChild($newNode);
		}
		
		// add the id attribute, if its provided
		if (is_string($objectId) && strlen($objectId))
		{
			$keyValue->parentNode->setAttribute('Id', $objectId);
		}
		
		return true;
	}
	
	/**
	 * Appends a reference to the XML document of the provided node,
	 * by canonicalizing it first and then digesting (hashing) it.
	 * The actual digest is appended to the DOM.
	 * 
	 * @param	\DOMNode	$node	The node that is to be referenced
	 * @param	string					$uri	Reference URI attribute
	 * @return	bool
	 */
	public function addReference(\DOMNode $node, $uri = null)
	{
        if (is_null($this->doc))
        {
            $this->createXmlStructure();
        }

		// references are appended to the SignedInfo node
		$signedInfo = $this->doc->getElementsByTagName($this->nodeNsPrefix . 'SignedInfo')->item(0);
		
		$reference = $this->doc->createElement($this->nodeNsPrefix . 'Reference');
		$signedInfo->appendChild($reference);
		
		if (is_string($uri) && strlen($uri))
		{
			// if the URI is a simple string (i.e. it's an ID that's a reference to an object in the DOM)
			// prepend it with a hash
			// otherwise (if the uri is URL-like), do nothing
			if (!filter_var($uri, FILTER_VALIDATE_URL))
			{
				$uri = '#' . $uri;
			}
			
			$reference->setAttribute('URI', $uri);
		}
		
		// specify the digest (hashing) algorithm used
		$digestMethod = $this->doc->createElement($this->nodeNsPrefix . 'DigestMethod');
		$digestMethod->setAttribute('Algorithm', $this->digestMethodUriMapping[$this->digestMethod]);
		$reference->appendChild($digestMethod);
		
		// first we must try to canonicalize the element(s)
		try
		{
			$c14nData = $this->canonicalize($node);
		}
		catch (\UnexpectedValueException $e)
		{
			throw $e;
		}
		
		// references are stored as digests, so we must do that as well
		$referenceDigest = $this->calculateDigest($c14nData);
		
		$digestValue = $this->doc->createElement($this->nodeNsPrefix . 'DigestValue', $referenceDigest);
		$reference->appendChild($digestValue);
		
		return true;
	}
	
	/**
	 * Signs the XML document with an XML digital signature
	 * 
	 * @throws	\UnexpectedValueException	If the XML tree is not intact or if there is no OpenSSL mapping set
	 * @return	bool						True if the document was successfully signed, false otherwise
	 */
	public function sign()
	{
		// the document must be set up
		if (is_null($this->doc))
		{
			return new \UnexpectedValueException('No document structure to sign');
		}
		
		// find the SignedInfo element, which is what we will actually sign
		$signedInfo = $this->doc->getElementsByTagName($this->nodeNsPrefix . 'SignedInfo')->item(0);		
		if (is_null($signedInfo))
		{
			throw new \UnexpectedValueException('Unabled to locate the SignedInfo node');
		}
		
		// canonicalize the SignedInfo element for signing
		$c14nSignedInfo = $this->canonicalize($signedInfo);

		// make sure that we know which OpenSSL algo type to use
		if (!array_key_exists($this->digestMethod, $this->openSSLAlgoMapping))
		{
			throw new \UnexpectedValueException('No OpenSSL algorithm has been defined for digest of type ' . $this->digestMethod);
		}
		
		// sign the SignedInfo element using the private key
		if (!openssl_sign($c14nSignedInfo, $signature, $this->privateKey, $this->openSSLAlgoMapping[$this->digestMethod]))
		{
			throw new \UnexpectedValueException('Unable to sign the document. Error: ' . openssl_error_string());
		}
		
		$signature = base64_encode($signature);
		
		// find the signature value node, to which we will append the base64 encoded signature
		$signatureNode = $this->doc->getElementsByTagName($this->nodeNsPrefix . 'SignatureValue')->item(0);		
		if (is_null($signatureNode))
		{
			throw new \UnexpectedValueException('Unabled to locate the SingatureValue node');
		}
		
		$signatureNode->appendChild($this->doc->createTextNode($signature));
		
		return true;
	}
	
	/**
	 * Verifies the XML digital signature
	 * 
	 * @throws	\UnexpectedValueException	If the XML tree is not intact
	 * @return	bool						Verification result
	 */
	public function verify()
	{
		if (is_null($this->publicKey))
		{
			trigger_error('Cannot verify XML digital signature without public key', E_USER_WARNING);
			return false;
		}
		
		// find the SignedInfo element which was signed
		$signedInfo = $this->doc->getElementsByTagName($this->nodeNsPrefix . 'SignedInfo')->item(0);
		if (is_null($signedInfo))
		{
			throw new \UnexpectedValueException('Unable to locate the SignedInfo node');
		}
		
		// canonicalize the SignedInfo element for signature checking
		$c14nSignedInfo = $this->canonicalize($signedInfo);

		// find the signature value to verify
		$signatureValue = $this->doc->getElementsByTagName($this->nodeNsPrefix . 'SignatureValue')->item(0);
		if (is_null($signatureValue))
		{
			throw new \UnexpectedValueException('Unable to locate the SignatureValue node');
		}
		
		$signature = base64_decode($signatureValue->nodeValue);	
		
		return 1 === openssl_verify($c14nSignedInfo, $signature, $this->publicKey, $this->openSSLAlgoMapping[$this->digestMethod]);
	}
	
	/**
	 * Prepares the XML skeleton structure for the signature
	 * 
	 * return	void
	 */
	protected function createXmlStructure()
	{
		$this->doc = new \DOMDocument('1.0', 'UTF-8');
		$this->doc->xmlStandalone = $this->standalone;
		
		// Signature node
		$signature = $this->doc->createElementNS(self::XML_DSIG_NS, $this->nodeNsPrefix . 'Signature');
		$this->doc->appendChild($signature);
		
		// SignedInfo node
		$signedInfo = $this->doc->createElement($this->nodeNsPrefix . 'SignedInfo');
		$signature->appendChild($signedInfo);
		
		// canonicalization method node
		$c14nMethod = $this->doc->createElement($this->nodeNsPrefix . 'CanonicalizationMethod');
		$c14nMethod->setAttribute('Algorithm', $this->canonicalMethod);
		$signedInfo->appendChild($c14nMethod);
		
		// specify the hash algorithm used
		$sigMethod = $this->doc->createElement($this->nodeNsPrefix . 'SignatureMethod');
		$sigMethod->setAttribute('Algorithm', $this->chooseSignatureMethod());
		$signedInfo->appendChild($sigMethod);
		
		// create the node that will hold the signature
		$sigValue = $this->doc->createElement($this->nodeNsPrefix . 'SignatureValue');
		$signature->appendChild($sigValue);
		
		// the KeyInfo and KeyValue nodes will contain information about the public key
		$keyInfo = $this->doc->createElement($this->nodeNsPrefix . 'KeyInfo');
		$signature->appendChild($keyInfo);
		
		$keyValue = $this->doc->createElement($this->nodeNsPrefix . 'KeyValue');
		$keyInfo->appendChild($keyValue);
	}
	
	/**
	 * Chooses the appropriate W3 signature URI, based on
	 * the chosen crypto algorithm and digest method.
	 * 
	 * @return	string	Signature method URI
	 */
	protected function chooseSignatureMethod()
	{
		return $this->digestSignatureAlgoMapping[$this->cryptoAlgorithm][$this->digestMethod];
	}
	
	/**
	 * Canonicalizes a DOM document or a single DOM node
	 * 
	 * @param	\DOMNode					$data	Node(s) to be canonicalized
	 * @throws	\UnexpectedValueException			If the canonicalization process failed
	 * @return	string|bool							Canonicalized node(s), or false on failure
	 */
	protected function canonicalize(\DOMNode $object)
	{		
		$options = $this->c14nOptionMapping[$this->canonicalMethod];
		
		// canonicalize the provided data with the preset options
		$c14nData = $object->C14N($options['exclusive'], $options['withComments']);
		
		if (is_string($c14nData) && strlen($c14nData))
		{
			return $c14nData;
		}
		
		throw new \UnexpectedValueException('Unable to canonicalize the provided DOM document');
	}
	
	/**
	 * Appends an object to the signed XML documents
	 * 
	 * @param	DOMNode|string				$data			Data to add to the object node
	 * @param	string						$objectId		ID attribute of the object
	 * @param 	bool						$digestObject	Whether the object data should be digested
	 * @throws	\UnexpectedValueException					If the canonicalization process failed
	 */
	public function addObject($data, $objectId = null, $digestObject = false)
	{
		if (is_null($this->doc))
		{
			$this->createXmlStructure();
		}
		
		if (is_string($data) && strlen($data))
		{
			$data = $this->doc->createTextNode($data);
		}
		else if (!is_object($data) || !$data instanceof \DOMNode)
		{
			throw new \UnexpectedValueException(sprintf('Digested data must be a non-empty string or DOMNode, %s was given', gettype($data)));
		}
		
		// if the object is meant to be digested, do so
		if (true === $digestObject)
		{
			$digestedData = $this->calculateDigest($this->canonicalize($data));
			$data = $this->doc->createTextNode($digestedData);
		}
		else
		{
			$data = $this->doc->importNode($data, true);
		}
		
		// add the object to the dom
		$object = $this->doc->createElement($this->nodeNsPrefix . 'Object');
		$object->appendChild($data);
		$this->doc->getElementsByTagName('Signature')->item(0)->appendchild($object);
		
		// objects must have an id attribute which will
		// correspond to the reference URI attribute
		if (!is_string($objectId) || !strlen($objectId) || is_numeric($objectId[0]))
		{
			// generate a random ID
			$objectId = rtrim(base64_encode(mt_rand()), '=');
		}

		// if the ID was provided, add it
		$object->setAttribute('Id', $objectId);

		// objects also need to be digested and stored as references
		// so that they can be signed later
		$this->addReference($object, $objectId);
		
		return true;
	}
	
	/**
	 * Calculates the digest (hash) of a given input value, based on the chosen hashing algorithm.
	 * 
	 * @param	string	$data	Data to the hashed
	 * @return	string			Digested string encoded in base64
	 */
	protected function calculateDigest($data)
	{
		$this->checkDigestSupport();
		
		return base64_encode(hash($this->digestMethod, $data, true));
	}
	
	/**
	 * Ensures that the current installation of PHP supports the selected digest method.
	 * If it does not, a fatal error is triggered.
	 * 
	 * @return	void
	 */
	protected function checkDigestSupport()
	{
		// ensure that the selected digest method is supported by the current PHP version
		if (!in_array($this->digestMethod, hash_algos()))
		{
			trigger_error(sprintf('This installation of PHP does not support the %s hashing algorithm', $this->digestMethod), E_USER_ERROR);
		}
	}
}
