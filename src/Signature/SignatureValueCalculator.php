<?php

declare(strict_types=1);

namespace XadesBesSigner\Signature;

use XadesBesSigner\KeyProvider\PrivateKeySignerInterface;

/**
 * Computes the ds:SignatureValue (RSA over canonicalized SignedInfo).
 */
final class SignatureValueCalculator
{
    public function __construct(
        private readonly PrivateKeySignerInterface $key
    ) {
    }

    public function calculate(string $canonicalizedSignedInfo): string
    {
        return base64_encode($this->key->sign($canonicalizedSignedInfo));
    }
}