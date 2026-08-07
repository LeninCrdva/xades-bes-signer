<?php

declare(strict_types=1);

namespace XadesBesSigner\Tests;

use PHPUnit\Framework\TestCase;
use XadesBesSigner\BatchSigner;
use XadesBesSigner\Certificate\P12CertificateLoader;
use XadesBesSigner\Signature\SignatureContext;
use XadesBesSigner\Verification\Verifier;
use XadesBesSigner\Xml\DigestCalculator;

/**
 * Batch signing of directories and file lists.
 */
final class BatchSignerTest extends TestCase
{
    private string $tempDir;

    protected function setUp(): void
    {
        Fixtures::p12();
        $this->tempDir = sys_get_temp_dir() . '/xades-bes-' . bin2hex(random_bytes(4));
        mkdir($this->tempDir . '/in', 0777, true);
        mkdir($this->tempDir . '/out', 0777, true);

        $base = file_get_contents(Fixtures::unsignedFactura());
        self::assertIsString($base);
        file_put_contents($this->tempDir . '/in/factura-1.xml', $base);
        file_put_contents($this->tempDir . '/in/factura-2.xml', $base);
    }

    protected function tearDown(): void
    {
        foreach (glob($this->tempDir . '/in/*') ?: [] as $file) {
            @unlink($file);
        }
        @unlink($this->tempDir . '/out/*-signed.xml');
        @rmdir($this->tempDir . '/out');
        @rmdir($this->tempDir . '/in');
        @rmdir($this->tempDir);
    }

    public function testSignDirectorySignsEveryXmlFile(): void
    {
        $key = P12CertificateLoader::fromFile(Fixtures::p12(), Fixtures::P12_PASSWORD);
        $results = BatchSigner::with($key)->signDirectory(
            $this->tempDir . '/in',
            $this->tempDir . '/out',
            new SignatureContext()
        );

        self::assertCount(2, $results);

        foreach ($results as $target) {
            self::assertFileExists($target);
            self::assertTrue((new Verifier())->verifyFromFile($target)->isValid());
        }
    }

    public function testSignFilesSupportsSha256(): void
    {
        $key = P12CertificateLoader::fromFile(Fixtures::p12(), Fixtures::P12_PASSWORD, DigestCalculator::SHA256);
        [$source] = array_values(BatchSigner::with($key)->signFiles(
            [$this->tempDir . '/in/factura-1.xml'],
            $this->tempDir . '/out',
            new SignatureContext(DigestCalculator::SHA256)
        ));

        self::assertFileExists($source);
        self::assertTrue((new Verifier())->verifyFromFile($source)->isValid());
    }
}