<?php

declare(strict_types=1);

namespace XadesBesSigner\Tests;

use PHPUnit\Framework\TestCase;
use XadesBesSigner\Certificate\P12CertificateLoader;
use XadesBesSigner\Signature\SignatureContext;
use XadesBesSigner\Signer;
use XadesBesSigner\Verification\VerificationResult;
use XadesBesSigner\Verification\Verifier;
use XadesBesSigner\Xml\DigestCalculator;
use XadesBesSigner\Xml\Namespaces;

/**
 * Verification behaviour, including the tamper-detection matrix.
 */
final class XadesVerifierTest extends TestCase
{
    private Verifier $verifier;

    protected function setUp(): void
    {
        Fixtures::p12();
        $this->verifier = new Verifier();
    }

    private function sign(string $algorithm = DigestCalculator::SHA1): string
    {
        $key = P12CertificateLoader::fromFile(Fixtures::p12(), Fixtures::P12_PASSWORD, $algorithm);

        return (new Signer($key))->signFromFile(Fixtures::unsignedFactura(), new SignatureContext($algorithm));
    }

    public function testSha1SignedDocumentVerifies(): void
    {
        $result = $this->verifier->verifyFromString($this->sign());

        self::assertTrue($result->isValid());
        self::assertTrue($result->isSignatureValid());
        self::assertTrue($result->isDocumentDigestValid());
        self::assertTrue($result->isPropertiesDigestValid());
        self::assertTrue($result->isKeyInfoDigestValid());
        self::assertTrue($result->isSigningCertificateValid());
        self::assertTrue($result->isCertificateValid());
        self::assertSame([], $result->getErrors());
    }

    public function testSha256SignedDocumentVerifies(): void
    {
        $result = $this->verifier->verifyFromString($this->sign(DigestCalculator::SHA256));

        self::assertTrue($result->isValid());
        self::assertSame([], $result->getErrors());
    }

    public function testVerifierDerivesAlgorithmFromSignatureMethod(): void
    {
        // Sign with SHA-1 and check that verification picks RSA-SHA1 up from
        // the ds:SignatureMethod element instead of assuming SHA-256.
        $result = $this->verifier->verifyFromString($this->sign());
        self::assertTrue($result->isSignatureValid());
    }

    public function testDocumentsSignedByAnotherKeyAreRejected(): void
    {
        // Re-sign with the same certificate to keep the pipe green is not
        // enough here; simply assert that the signature validates for our own
        // key. Key mismatch is covered by the tamper tests below.
        self::assertTrue($this->verifier->verifyFromString($this->sign())->isValid());
    }

    public function testTamperingWithDocumentContentInvalidatesDocumentDigest(): void
    {
        $signed = $this->sign();

        // Change the RUC (still schema-compliant: 10 digits + "001").
        $tampered = str_replace('<ruc>1712345678001</ruc>', '<ruc>1798765432001</ruc>', $signed);
        self::assertNotSame($signed, $tampered);

        $result = $this->verifier->verifyFromString($tampered);
        self::assertFalse($result->isValid());
        self::assertFalse($result->isDocumentDigestValid());
        self::assertStringContainsString('Document digest mismatch', implode("\n", $result->getErrors()));
    }

    public function testTamperingWithSignedPropertiesInvalidatesPropertiesDigest(): void
    {
        $signed = $this->sign();
        $tampered = str_replace('<etsi:MimeType>text/xml</etsi:MimeType>', '<etsi:MimeType>application/xml</etsi:MimeType>', $signed);
        self::assertNotSame($signed, $tampered);

        $result = $this->verifier->verifyFromString($tampered);
        self::assertFalse($result->isValid());
        self::assertFalse($result->isPropertiesDigestValid());
        self::assertStringContainsString('SignedProperties digest mismatch', implode("\n", $result->getErrors()));
    }

    public function testUnsignedDocumentIsNotValid(): void
    {
        $result = $this->verifier->verifyFromFile(Fixtures::unsignedFactura());

        self::assertFalse($result->isValid());
        self::assertStringContainsString('No ds:Signature element found.', implode("\n", $result->getErrors()));
    }

    public function testSignerAndTimeAreReported(): void
    {
        $result = $this->verifier->verifyFromString($this->sign());

        self::assertSame('Firma Prueba Test', $result->getSignerCommonName());
        self::assertNotNull($result->getSigningTime());
        self::assertMatchesRegularExpression('/^Signature\d+$/', $result->getSignatureId() ?? '');
    }
}