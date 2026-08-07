<?php

declare(strict_types=1);

namespace XadesBesSigner;

use XadesBesSigner\KeyProvider\PrivateKeySignerInterface;
use XadesBesSigner\Signature\SignatureContext;
use XadesBesSigner\Signature\SignatureValueCalculator;
use XadesBesSigner\Xml\SignatureBuilder;
use XadesBesSigner\Xml\XmlDocument;

/**
 * Signs an XML document with a XAdES-BES enveloped signature.
 */
final class Signer
{
    public function __construct(
        private readonly PrivateKeySignerInterface $key
    ) {
    }

    public function signFromString(string $xml, ?SignatureContext $context = null): string
    {
        $document = XmlDocument::fromString($xml);

        return $this->signDocument($document, $context);
    }

    public function signFromFile(string $path, ?SignatureContext $context = null): string
    {
        $document = XmlDocument::fromFile($path);

        return $this->signDocument($document, $context);
    }

    private function signDocument(XmlDocument $document, ?SignatureContext $context = null): string
    {
        $context ??= new SignatureContext();

        $calculator = new SignatureValueCalculator($this->key);
        SignatureBuilder::sign($document, $context, $this->key->getCertificate(), $calculator);

        return $document->toString();
    }
}