<?php

declare(strict_types=1);

namespace XadesBesSigner\Tests;

use PHPUnit\Framework\TestCase;
use XadesBesSigner\Certificate\P12CertificateLoader;
use XadesBesSigner\Signature\SignatureContext;
use XadesBesSigner\Signer;
use XadesBesSigner\Xml\DigestCalculator;
use XadesBesSigner\Xml\Namespaces;

/**
 * Structure of the produced XAdES-BES envelope (SRI / XAdES4J mirror).
 */
final class XadesSignerTest extends TestCase
{
    protected function setUp(): void
    {
        Fixtures::p12();
    }

    private function sign(?SignatureContext $context = null): string
    {
        $key = P12CertificateLoader::fromFile(Fixtures::p12(), Fixtures::P12_PASSWORD);
        $context ??= new SignatureContext();

        return (new Signer($key))->signFromFile(Fixtures::unsignedFactura(), $context);
    }

    private function xpath(string $xml): \DOMXPath
    {
        $dom = new \DOMDocument();
        $dom->loadXML($xml);
        $xpath = new \DOMXPath($dom);
        $xpath->registerNamespace('ds', Namespaces::XMLDSIG);
        $xpath->registerNamespace('xades', Namespaces::XADES);

        return $xpath;
    }

    public function testSignedDocumentHasAnEnvelopedSignature(): void
    {
        $xpath = $this->xpath($this->sign());

        self::assertSame(1, $xpath->query('//ds:Signature')->length);
        // The signature is attached to the root element.
        self::assertSame(1, $xpath->query('/factura/ds:Signature')->length);
    }

    public function testSignedInfoReferencesSignedPropertiesKeyInfoAndDocumentInOrder(): void
    {
        $xpath = $this->xpath($this->sign());

        $references = $xpath->query('//ds:SignedInfo/ds:Reference');
        self::assertSame(3, $references->length);

        // 1. SignedProperties reference.
        self::assertSame(
            Namespaces::XADES_TYPE_SIGNED_PROPERTIES,
            $references->item(0)?->getAttribute('Type')
        );

        // 2. KeyInfo reference.
        $keyInfoId = $xpath->query('//ds:KeyInfo')->item(0)?->getAttribute('Id');
        self::assertNotSame('', $keyInfoId);
        self::assertSame('#' . $keyInfoId, $references->item(1)?->getAttribute('URI'));
        self::assertSame('', $references->item(1)?->getAttribute('Type'));

        // 3. Document reference, with the enveloped-signature transform.
        self::assertSame('', $references->item(2)?->getAttribute('Type'));
        self::assertSame(
            '#' . $xpath->query('/factura')->item(0)?->getAttribute('id'),
            $references->item(2)?->getAttribute('URI')
        );
        self::assertSame(1, $xpath->query('//ds:SignedInfo/ds:Reference[3]/ds:Transforms/ds:Transform[@Algorithm="' . Namespaces::TRANSFORM_ENVELOPED . '"]')->length);
    }

    public function testKeyInfoEmbedsCertificateAndPublicKey(): void
    {
        $xpath = $this->xpath($this->sign());

        self::assertSame(1, $xpath->query('//ds:KeyInfo/ds:X509Data/ds:X509Certificate')->length);
        self::assertSame(1, $xpath->query('//ds:KeyInfo/ds:KeyValue/ds:RSAKeyValue/ds:Modulus')->length);
        self::assertSame(1, $xpath->query('//ds:KeyInfo/ds:KeyValue/ds:RSAKeyValue/ds:Exponent')->length);
    }

    public function testSignedPropertiesCarrySigningTimeAndCertificateData(): void
    {
        $xpath = $this->xpath($this->sign());

        self::assertSame(1, $xpath->query('//xades:SignedProperties/xades:SignedSignatureProperties/xades:SigningTime')->length);
        self::assertSame(1, $xpath->query('//xades:SignedProperties/xades:SignedSignatureProperties/xades:SigningCertificate/xades:Cert')->length);
        self::assertSame(1, $xpath->query('//xades:SignedProperties/xades:SignedDataObjectProperties/xades:DataObjectFormat/xades:Description')->length);
        self::assertSame('contenido comprobante', $xpath->query('//xades:DataObjectFormat/xades:Description')->item(0)?->textContent);
        self::assertSame('text/xml', $xpath->query('//xades:DataObjectFormat/xades:MimeType')->item(0)?->textContent);
    }

    public function testBase64PayloadsAreWrappedAt76Columns(): void
    {
        $xml = $this->sign();

        foreach (['ds:SignatureValue', 'ds:KeyInfo/ds:X509Data/ds:X509Certificate', 'ds:KeyInfo/ds:KeyValue/ds:RSAKeyValue/ds:Modulus'] as $query) {
            $xpath = $this->xpath($xml);
            $text = $xpath->query('//' . $query)->item(0)?->textContent ?? '';
            self::assertNotSame('', $text, 'expected a value for ' . $query);
            foreach (preg_split('/\r?\n/', $text) as $line) {
                self::assertLessThanOrEqual(76, strlen($line), 'wrap exceeded 76 columns in ' . $query);
            }
        }
    }

    public function testNamespacesAreDeclaredOnceOnTheSignatureRoot(): void
    {
        $xpath = $this->xpath($this->sign());
        $signature = $xpath->query('//ds:Signature')->item(0);

        self::assertInstanceOf(\DOMElement::class, $signature);
        self::assertTrue($signature->hasAttribute('xmlns:ds'));
        self::assertTrue($signature->hasAttribute('xmlns:xades'));

        // No redundant declarations deeper inside the signature.
        $descendants = $signature->getElementsByTagName('*');
        foreach ($descendants as $element) {
            self::assertFalse($element->hasAttribute('xmlns:ds'), 'redundant xmlns:ds inside the signature');
            self::assertFalse($element->hasAttribute('xmlns:xades'), 'redundant xmlns:xades inside the signature');
        }
    }

    public function testSha256ContextProducesSha256SignatureMethodAndDigests(): void
    {
        $context = new SignatureContext(DigestCalculator::SHA256);
        $xpath = $this->xpath($this->sign($context));

        $signatureMethod = $xpath->query('//ds:SignatureMethod')->item(0)?->getAttribute('Algorithm');
        $signatureDigest = $xpath->query('//ds:Reference/ds:DigestMethod')->item(0)?->getAttribute('Algorithm');

        self::assertSame(Namespaces::SIG_METHOD_RSA_SHA256, $signatureMethod);
        self::assertSame(Namespaces::DIGEST_SHA256, $signatureDigest);
    }

    public function testDefaultContextUsesSha1(): void
    {
        $xpath = $this->xpath($this->sign());

        self::assertSame(Namespaces::SIG_METHOD_RSA_SHA1, $xpath->query('//ds:SignatureMethod')->item(0)?->getAttribute('Algorithm'));
    }
}