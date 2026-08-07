<?php

declare(strict_types=1);

namespace XadesBesSigner\Certificate;

use XadesBesSigner\Exception\CertificateException;
use XadesBesSigner\KeyProvider\OpensslPrivateKeySigner;
use XadesBesSigner\Xml\DigestCalculator;

/**
 * Loads a signer (certificate + private key) from a PKCS#12 (.p12) container.
 */
final class P12CertificateLoader
{
    /**
     * Load a signer from a .p12 file.
     */
    public static function fromFile(
        string $path,
        string $passphrase,
        string $digestAlgorithm = DigestCalculator::SHA256
    ): OpensslPrivateKeySigner {
        if (! is_file($path) || ! is_readable($path)) {
            throw new CertificateException('P12 file is not readable: ' . $path);
        }

        $content = file_get_contents($path);
        if ($content === false) {
            throw new CertificateException('Could not read P12 file: ' . $path);
        }

        return self::fromString($content, $passphrase, $digestAlgorithm);
    }

    /**
     * Load a signer from raw PKCS#12 bytes.
     */
    public static function fromString(
        string $content,
        string $passphrase,
        string $digestAlgorithm = DigestCalculator::SHA256
    ): OpensslPrivateKeySigner {
        $certs = [];
        $ok = openssl_pkcs12_read($content, $certs, $passphrase);
        if (! $ok) {
            throw new CertificateException('Could not decrypt PKCS#12 container (wrong password or corrupt file?).');
        }

        if (! isset($certs['cert'], $certs['pkey'])) {
            throw new CertificateException('PKCS#12 container does not include a certificate and private key.');
        }

        $certificate = Certificate::fromPem($certs['cert']);
        $key = openssl_pkey_get_private($certs['pkey'], '');
        if ($key === false) {
            throw new CertificateException('Could not load private key from PKCS#12 container.');
        }

        return new OpensslPrivateKeySigner($key, $certificate, $digestAlgorithm);
    }
}