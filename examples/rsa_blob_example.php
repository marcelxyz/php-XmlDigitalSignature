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

	try
	{
		$dsig->addObject('Lorem ipsum dolor sit amet');
		$dsig->sign();
		$dsig->verify();
	}
	catch (\UnexpectedValueException $e)
	{
		print_r($e);
		exit(1);
	}

	var_dump($dsig->getSignedDocument());