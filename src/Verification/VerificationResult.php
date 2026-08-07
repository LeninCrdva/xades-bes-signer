<?php

declare(strict_types=1);

namespace XadesBesSigner\Verification;

/**
 * Result of a XAdES-BES verification.
 */
final class VerificationResult
{
    /**
     * @param list<string> $errors
     */
    public function __construct(
        private readonly bool $signatureValid,
        private readonly bool $documentDigestValid,
        private readonly bool $propertiesDigestValid,
        private readonly bool $certificateValid,
        private readonly array $errors = [],
        private readonly ?string $signerCommonName = null,
        private readonly ?\DateTimeImmutable $signingTime = null,
        private readonly ?string $signatureId = null,
        private readonly bool $keyInfoDigestValid = true,
        private readonly bool $signingCertificateValid = true,
    ) {
    }

    public static function valid(string $signerCommonName, \DateTimeImmutable $signingTime, string $signatureId): self
    {
        return new self(true, true, true, true, [], $signerCommonName, $signingTime, $signatureId);
    }

    public function isValid(): bool
    {
        return $this->signatureValid
            && $this->documentDigestValid
            && $this->propertiesDigestValid
            && $this->certificateValid
            && $this->keyInfoDigestValid
            && $this->signingCertificateValid;
    }

    /** @return list<string> */
    public function getErrors(): array
    {
        return $this->errors;
    }

    public function getSignerCommonName(): ?string
    {
        return $this->signerCommonName;
    }

    public function getSigningTime(): ?\DateTimeImmutable
    {
        return $this->signingTime;
    }

    public function getSignatureId(): ?string
    {
        return $this->signatureId;
    }

    public function isSignatureValid(): bool
    {
        return $this->signatureValid;
    }

    public function isDocumentDigestValid(): bool
    {
        return $this->documentDigestValid;
    }

    public function isPropertiesDigestValid(): bool
    {
        return $this->propertiesDigestValid;
    }

    public function isCertificateValid(): bool
    {
        return $this->certificateValid;
    }

    public function isKeyInfoDigestValid(): bool
    {
        return $this->keyInfoDigestValid;
    }

    public function isSigningCertificateValid(): bool
    {
        return $this->signingCertificateValid;
    }
}