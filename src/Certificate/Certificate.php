<?php

declare(strict_types=1);

namespace XadesBesSigner\Certificate;

use XadesBesSigner\Exception\CertificateException;
use XadesBesSigner\Xml\DigestCalculator;

/**
 * X.509 certificate value object with the data points needed by XAdES-BES:
 * DER payload, digest, RFC2253 issuer name and decimal serial number.
 */
final class Certificate
{
    /**
     * Order used by Java's X500Principal (and therefore XAdES4J) when printing
     * an RFC2253 DN: most-specific attribute first.
     */
    private const RFC2253_ORDER = [
        'CN', 'OU', 'O', 'L', 'ST', 'C', 'T', 'SERIALNUMBER', 'E', 'EMAILADDRESS', 'STREET', 'POSTALCODE', 'UID',
    ];

    private const RFC2253_ALIASES = [
        'emailAddress' => 'EMAILADDRESS',
        'serialNumber' => 'SERIALNUMBER',
    ];

    private \OpenSSLCertificate $certificate;

    /** @var array<string, mixed> */
    private array $parsed;

    private function __construct(\OpenSSLCertificate $certificate, array $parsed)
    {
        $this->certificate = $certificate;
        $this->parsed = $parsed;
    }

    public static function fromPem(string $pem): self
    {
        $certificate = openssl_x509_read($pem);
        if ($certificate === false) {
            throw new CertificateException('Could not read X.509 certificate from PEM.');
        }

        $parsed = openssl_x509_parse($certificate);
        if ($parsed === false) {
            throw new CertificateException('Could not parse X.509 certificate.');
        }

        return new self($certificate, $parsed);
    }

    /**
     * Base64-encoded DER payload (used inside ds:X509Certificate).
     */
    public function toDerBase64(): string
    {
        $exported = null;
        $ok = openssl_x509_export($this->certificate, $exported);
        if (! $ok || $exported === null) {
            throw new CertificateException('Could not export X.509 certificate.');
        }

        $pemLines = preg_split('/\r?\n/', trim($exported)) ?: [];
        $body = '';
        foreach ($pemLines as $line) {
            if (str_starts_with($line, '-----') || $line === '') {
                continue;
            }
            $body .= $line;
        }

        return $body;
    }

    /**
     * DER bytes as binary string.
     */
    public function toDerBinary(): string
    {
        $decoded = base64_decode($this->toDerBase64(), true);
        if ($decoded === false) {
            throw new CertificateException('Could not decode certificate DER payload.');
        }

        return $decoded;
    }

    /**
     * Base64 digest of the DER certificate, as required by xades:CertDigest.
     */
    public function getDigest(string $algorithm = DigestCalculator::SHA256): string
    {
        return DigestCalculator::digestString($this->toDerBinary(), $algorithm);
    }

    public function getPem(): string
    {
        $exported = null;
        $ok = openssl_x509_export($this->certificate, $exported);
        if (! $ok || $exported === null) {
            throw new CertificateException('Could not export X.509 certificate.');
        }

        return $exported;
    }

    /**
     * Issuer distinguished name in RFC2253 form (ds:X509IssuerName).
     */
    public function getIssuerName(): string
    {
        return $this->buildRfc2253($this->parsed['issuer'] ?? []);
    }

    /**
     * Subject distinguished name in RFC2253 form.
     */
    public function getSubjectName(): string
    {
        return $this->buildRfc2253($this->parsed['subject'] ?? []);
    }

    /**
     * Decimal serial number (ds:X509SerialNumber).
     */
    public function getSerialNumber(): string
    {
        $hex = isset($this->parsed['serialNumberHex'])
            ? (string) $this->parsed['serialNumberHex']
            : ltrim((string) ($this->parsed['serialNumber'] ?? '0'), '0x');

        if ($hex === '') {
            return '0';
        }

        return self::hexToDecimal($hex);
    }

    public function getValidFrom(): \DateTimeImmutable
    {
        return $this->dateFromAsn1((string) ($this->parsed['validFrom'] ?? ''));
    }

    public function getValidTo(): \DateTimeImmutable
    {
        return $this->dateFromAsn1((string) ($this->parsed['validTo'] ?? ''));
    }

    /**
     * Whether the certificate is currently within its validity window.
     */
    public function isCurrentlyValid(?\DateTimeInterface $now = null): bool
    {
        $now ??= new \DateTimeImmutable('now', new \DateTimeZone('UTC'));
        $now = \DateTimeImmutable::createFromInterface($now);

        return $now >= $this->getValidFrom() && $now <= $this->getValidTo();
    }

    public function getCommonName(): string
    {
        return (string) ($this->parsed['subject']['CN'] ?? '');
    }

    public function getOrganization(): string
    {
        return (string) ($this->parsed['subject']['O'] ?? '');
    }

    public function getRaw(): \OpenSSLCertificate
    {
        return $this->certificate;
    }

    public function getPublicKey(): \OpenSSLAsymmetricKey
    {
        $key = openssl_pkey_get_public($this->getPem());
        if ($key === false) {
            throw new CertificateException('Could not extract public key from certificate.');
        }

        return $key;
    }

    /**
     * Base64-encoded RSA modulus (ds:Modulus inside ds:RSAKeyValue).
     */
    public function getRsaModulusBase64(): string
    {
        return $this->getRsaDetails()['n'];
    }

    /**
     * Base64-encoded RSA public exponent (ds:Exponent inside ds:RSAKeyValue).
     */
    public function getRsaExponentBase64(): string
    {
        return $this->getRsaDetails()['e'];
    }

    /**
     * @return array{n: string, e: string} base64-encoded modulus and exponent.
     */
    private function getRsaDetails(): array
    {
        $details = openssl_pkey_get_details($this->getPublicKey());
        if ($details === false || ! isset($details['rsa']['n'], $details['rsa']['e'])) {
            throw new CertificateException('Could not extract RSA public key details.');
        }

        return ['n' => base64_encode($details['rsa']['n']), 'e' => base64_encode($details['rsa']['e'])];
    }

    /**
     * Build an RFC2253 string from the parsed subject/issuer array using a
     * canonical attribute order and RFC2253 escaping.
     *
     * @param array<string, mixed> $fields
     */
    private function buildRfc2253(array $fields): string
    {
        $normalized = [];
        foreach ($fields as $key => $value) {
            $normalized[self::RFC2253_ALIASES[$key] ?? strtoupper((string) $key)] = (string) $value;
        }

        $parts = [];
        foreach (self::RFC2253_ORDER as $key) {
            if (! isset($normalized[$key])) {
                continue;
            }
            $parts[] = $key . '=' . self::escapeRfc2253($normalized[$key]);
        }

        foreach ($normalized as $key => $value) {
            if (in_array($key, self::RFC2253_ORDER, true)) {
                continue;
            }
            $parts[] = $key . '=' . self::escapeRfc2253($value);
        }

        return implode(', ', $parts);
    }

    private static function escapeRfc2253(string $value): string
    {
        return (string) preg_replace('/([,+"\\\\<>;])/', '\\\\$1', $value);
    }

    private function dateFromAsn1(string $asn1): \DateTimeImmutable
    {
        /*
         * ASN.1 TIME comes in two flavors:
         *  - UTCTime        YYMMDDHHMMSSZ (12 digits) for years up to 2049
         *  - GeneralizedTime YYYYMMDDHHMMSSZ (14 digits) for later years
         * openssl_x509_parse() returns whichever the certificate carries.
         */
        if (preg_match('/^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/', $asn1, $m) === 1) {
            $year = (int) $m[1];
            $year += $year < 50 ? 2000 : 1900;
            $yearString = sprintf('%04d', $year);
        } elseif (preg_match('/^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/', $asn1, $m) === 1) {
            $yearString = $m[1];
        } else {
            throw new CertificateException('Unexpected ASN.1 date format: ' . $asn1);
        }

        $date = \DateTimeImmutable::createFromFormat('Y-m-d H:i:s', sprintf(
            '%s-%02d-%02d %02d:%02d:%02d',
            $yearString, (int) $m[2], (int) $m[3], (int) $m[4], (int) $m[5], (int) $m[6]
        ), new \DateTimeZone('UTC'));

        if ($date === false) {
            throw new CertificateException('Could not parse certificate date: ' . $asn1);
        }

        return $date;
    }

    /**
     * Convert an uppercase hex string to a decimal string without relying on
     * bcmath or gmp (keeps the library dependency-free).
     */
    private static function hexToDecimal(string $hex): string
    {
        $decimal = '0';
        $hex = strtoupper($hex);

        for ($i = 0, $len = strlen($hex); $i < $len; $i++) {
            $digit = hexdec($hex[$i]);
            $carry = $digit;
            $result = '';
            for ($j = strlen($decimal) - 1; $j >= 0; $j--) {
                $carry += ((int) $decimal[$j]) * 16;
                $result = (string) ($carry % 10) . $result;
                $carry = intdiv($carry, 10);
            }
            while ($carry > 0) {
                $result = (string) ($carry % 10) . $result;
                $carry = intdiv($carry, 10);
            }
            $decimal = $result;
        }

        return ltrim($decimal, '0') ?: '0';
    }
}