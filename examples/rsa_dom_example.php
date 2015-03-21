<?php

	require_once __DIR__ . '/../src/XmlDigitalSignature.php';

	$dsig = new XmlDsig\XmlDigitalSignature();

	$dsig
		->setCryptoAlgorithm(XmlDsig\XmlDigitalSignature::RSA_ALGORITHM)
		->setDigestMethod(XmlDsig\XmlDigitalSignature::DIGEST_SHA512)
		->forceStandalone();

	// load the private and public keys
	try
	{
		$dsig->loadPrivateKey(__DIR__ . '/keys/private.pem', 'MrMarchello');		
		$dsig->loadPublicKey(__DIR__ . '/keys/public.pem');
		$dsig->loadPublicXmlKey(__DIR__ . '/keys/public.xml');
	}
	catch (\UnexpectedValueException $e)
	{
		print_r($e);
		exit(1);
	}
	
	$fakeXml = new \DOMDocument();
	$fakeXml->loadXML('<?xml version="1.0" encoding="UTF-8"?><foo><bar><baz>I am a happy camper</baz></bar></foo>');
	
	$node = $fakeXml->getElementsByTagName('baz')->item(0);

	try
	{
		$dsig->addObject($node, 'object', true);
		$dsig->sign();
		$dsig->verify();
	}
	catch (\UnexpectedValueException $e)
	{
		print_r($e);
		exit(1);
	}

	var_dump($dsig->getSignedDocument());