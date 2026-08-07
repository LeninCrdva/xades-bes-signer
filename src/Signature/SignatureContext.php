<?php

declare(strict_types=1);

namespace XadesBesSigner\Signature;

use XadesBesSigner\Xml\DigestCalculator;

/**
 * Immutable configuration for a signing operation.
 */
final class SignatureContext
{
    public function __construct(
        public readonly string $digestAlgorithm = DigestCalculator::SHA1,
        public readonly ?\DateTimeImmutable $signingTime = null,
        public readonly string $mimeType = 'text/xml',
        public readonly bool $includeDataObjectFormat = true,
        public readonly ?string $signatureId = null,
    ) {
    }

    public function getSigningTime(): \DateTimeImmutable
    {
        return $this->signingTime ?? new \DateTimeImmutable('now', new \DateTimeZone('UTC'));
    }

    public function toXsdDateTime(): string
    {
        return $this->getSigningTime()->format('Y-m-d\TH:i:s\Z');
    }

    public function generateSignatureId(): string
    {
        return $this->signatureId ?? 'Signature-' . bin2hex(random_bytes(4));
    }
}