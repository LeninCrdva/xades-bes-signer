<?php

declare(strict_types=1);

namespace XadesBesSigner\KeyProvider;

use XadesBesSigner\Certificate\Certificate;

/**
 * Abstraction over any key/certificate origin.
 *
 * - Local mode: backed by a PKCS#12 file (see OpensslPrivateKeySigner).
 * - Remote/HSM mode: implement this interface delegating sign() and
 *   getCertificate() to your hardware token, API or cloud KMS. The signing
 *   pipeline is identical either way.
 */
interface PrivateKeySignerInterface
{
    /**
     * Sign the given bytes using the private key.
     *
     * MUST return the raw (bin2hex-free) PKCS#1 v1.5 signature bytes or a
     * PSS signature according to the chosen algorithm. For interoperability
     * with the SRI, RSA-PKCS1-v1.5 over SHA-256 is assumed.
     */
    public function sign(string $data): string;

    /**
     * The signer certificate to embed inside ds:KeyInfo.
     */
    public function getCertificate(): Certificate;
}