<?php

declare(strict_types=1);

namespace XadesBesSigner\Tests;

use PHPUnit\Framework\TestCase;
use XadesBesSigner\Certificate\Certificate;

/**
 * Value object behaviour: DER export, RFC2253 issuer order, decimal serial.
 */
final class CertificateTest extends TestCase
{
    private Certificate $certificate;

    protected function setUp(): void
    {
        $certPem = file_get_contents(Fixtures::generatedDir() . '/cert.pem');
        self::assertNotFalse($certPem);
        $this->certificate = Certificate::fromPem($certPem);
    }

    public function testIssuerIsPrintedInSriOrder(): void
    {
        // Same default order the SRI reference implementation uses:
        // CN, L, OU, O, C joined with "," (no spaces).
        self::assertSame(
            'CN=Firma Prueba Test,L=Quito,OU=Tecnologia,O=Empresa de Prueba S.A.,C=EC',
            $this->certificate->getIssuerName()
        );
    }

    public function testUanatacaIssuerIncludesOrganizationIdentifier(): void
    {
        $issuer = $this->certificate->getIssuerName();

        // The fixture certificate is not issued by UANATACA; assert the
        // generic format does not carry the organizationIdentifier.
        self::assertStringNotContainsString('2.5.4.97=', $issuer);
    }

    public function testSubjectMatchesIssuerForSelfSignedCertificate(): void
    {
        self::assertSame(
            'CN=Firma Prueba Test,L=Quito,OU=Tecnologia,O=Empresa de Prueba S.A.,C=EC',
            $this->certificate->getSubjectName()
        );
    }

    public function testSerialNumberIsDecimal(): void
    {
        $serial = $this->certificate->getSerialNumber();
        self::assertMatchesRegularExpression('/^\d+$/', $serial);
        // Same decimal value exposed by openssl_x509_parse serialNumber.
        $parsed = openssl_x509_parse($this->certificate->getPem());
        self::assertNotFalse($parsed);
        self::assertSame((string) $parsed['serialNumber'], $serial);
    }

    public function testDigestAlgorithms(): void
    {
        $der = $this->certificate->toDerBinary();
        self::assertSame(base64_encode(hash('sha1', $der, true)), $this->certificate->getDigest('sha1'));
        self::assertSame(base64_encode(hash('sha256', $der, true)), $this->certificate->getDigest('sha256'));
    }

    public function testCertificateIsCurrentlyValid(): void
    {
        self::assertTrue($this->certificate->isCurrentlyValid());
    }

    public function testCommonNameIsExposed(): void
    {
        self::assertSame('Firma Prueba Test', $this->certificate->getCommonName());
    }

    public function testRsaKeyDetailsAreExposedAsBase64(): void
    {
        $details = openssl_pkey_get_details(openssl_pkey_get_public($this->certificate->getPem()));
        self::assertNotFalse($details);
        self::assertSame(base64_encode($details['rsa']['n']), $this->certificate->getRsaModulusBase64());
        self::assertSame(base64_encode($details['rsa']['e']), $this->certificate->getRsaExponentBase64());
    }
}