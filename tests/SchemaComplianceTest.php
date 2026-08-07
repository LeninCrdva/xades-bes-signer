<?php

declare(strict_types=1);

namespace XadesBesSigner\Tests;

use PHPUnit\Framework\TestCase;
use XadesBesSigner\Certificate\P12CertificateLoader;
use XadesBesSigner\Signature\SignatureContext;
use XadesBesSigner\Signer;
use XadesBesSigner\Xml\DigestCalculator;

/**
 * The signed document must still comply with the SRI XSD scheme.
 */
final class SchemaComplianceTest extends TestCase
{
    protected function setUp(): void
    {
        Fixtures::p12();
    }

    private function assertValidatesAgainstSrinSchema(string $xml): void
    {
        libxml_use_internal_errors(true);
        $dom = new \DOMDocument('1.0', 'UTF-8');
        self::assertTrue($dom->loadXML($xml), 'XML must be well-formed');
        $valid = $dom->schemaValidate(Fixtures::schema());
        $errors = array_map(static fn (\LibXMLError $e) => trim($e->message), libxml_get_errors());
        libxml_clear_errors();
        libxml_use_internal_errors(false);

        self::assertTrue($valid, 'XSD validation failed: ' . implode(' | ', $errors));
    }

    public function testUnsignedFixtureIsSchemaCompliant(): void
    {
        $xml = (string) file_get_contents(Fixtures::unsignedFactura());
        $this->assertValidatesAgainstSchema($xml);
    }

    public function testSha1SignedDocumentIsSchemaCompliant(): void
    {
        $key = P12CertificateLoader::fromFile(Fixtures::p12(), Fixtures::P12_PASSWORD);
        $signed = (new Signer($key))->signFromFile(Fixtures::unsignedFactura(), new SignatureContext());

        $this->assertValidatesAgainstSchema($signed);
    }

    public function testSha256SignedDocumentIsSchemaCompliant(): void
    {
        $key = P12CertificateLoader::fromFile(Fixtures::p12(), Fixtures::P12_PASSWORD, DigestCalculator::SHA256);
        $signed = (new Signer($key))->signFromFile(Fixtures::unsignedFactura(), new SignatureContext(DigestCalculator::SHA256));

        $this->assertValidatesAgainstSchema($signed);
    }
}