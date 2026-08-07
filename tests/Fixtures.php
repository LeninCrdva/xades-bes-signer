<?php

declare(strict_types=1);

namespace XadesBesSigner\Tests;

/**
 * Locates test fixtures and generates the throwaway .p12 certificate on
 * demand (certificates are never committed to the repository).
 */
final class Fixtures
{
    public const P12_PASSWORD = 'secret';

    private const GENERATOR = __DIR__ . '/fixtures/generate-test-cert.php';

    public static function baseDir(): string
    {
        return __DIR__;
    }

    public static function generatedDir(): string
    {
        return __DIR__ . '/fixtures/generated';
    }

    public static function p12(): string
    {
        $path = self::generatedDir() . '/test-cert.p12';
        if (! is_file($path) || filesize($path) === 0) {
            self::generateCertificate();
        }

        return $path;
    }

    public static function unsignedFactura(): string
    {
        return __DIR__ . '/fixtures/sri-factura-unsigned.xml';
    }

    public static function schema(): string
    {
        return __DIR__ . '/fixtures/schemas/factura_V1.1.0.xsd';
    }

    public static function schemasDir(): string
    {
        return __DIR__ . '/fixtures/schemas';
    }

    private static function generateCertificate(): void
    {
        $output = [];
        $exitCode = 0;
        exec(PHP_BINARY . ' ' . escapeshellarg(self::GENERATOR) . ' --force 2>&1', $output, $exitCode);
        if ($exitCode !== 0 || ! is_file(self::p12())) {
            throw new \RuntimeException('Could not generate the test certificate: ' . implode("\n", $output));
        }
    }
}