<?php

declare(strict_types=1);

namespace XadesBesSigner\KeyProvider;

use XadesBesSigner\Certificate\Certificate;
use XadesBesSigner\Exception\SignatureException;

/**
 * Local signer backed by a private key in memory (from a .p12 container).
 */
final class OpensslPrivateKeySigner implements PrivateKeySignerInterface
{
    private \OpenSSLAsymmetricKey $privateKey;

    private Certificate $certificate;

    private int $opensslSignatureAlgorithm;

    public function __construct(
        \OpenSSLAsymmetricKey $privateKey,
        Certificate $certificate,
        string $digestAlgorithm = 'sha256'
    ) {
        $this->privateKey = $privateKey;
        $this->certificate = $certificate;

        $this->opensslSignatureAlgorithm = match ($digestAlgorithm) {
            'sha1' => \OPENSSL_ALGO_SHA1,
            'sha256' => \OPENSSL_ALGO_SHA256,
            default => throw new SignatureException('Unsupported digest algorithm: ' . $digestAlgorithm),
        };
    }

    public function sign(string $data): string
    {
        $signature = null;
        $ok = openssl_sign($data, $signature, $this->privateKey, $this->opensslSignatureAlgorithm);
        if (! $ok || $signature === null) {
            throw new SignatureException('Could not compute the signature value.');
        }

        return $signature;
    }

    public function getCertificate(): Certificate
    {
        return $this->certificate;
    }
}