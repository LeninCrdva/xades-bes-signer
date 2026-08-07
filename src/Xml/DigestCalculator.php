<?php

declare(strict_types=1);

namespace XadesBesSigner\Xml;

use XadesBesSigner\Exception\SignatureException;

/**
 * Digest computation over canonicalized XML.
 */
final class DigestCalculator
{
    public const SHA1 = 'sha1';

    public const SHA256 = 'sha256';

    /**
     * Compute the base64 digest of a canonicalized node subset.
     */
    public static function digestNode(\DOMNode $node, string $algorithm = self::SHA256): string
    {
        $c14n = Canonicalizer::canonicalize($node);

        return self::digestString($c14n, $algorithm);
    }

    /**
     * Compute the base64-encoded hash of an arbitrary string.
     */
    public static function digestString(string $data, string $algorithm = self::SHA256): string
    {
        return base64_encode(hash($algorithm, $data, true));
    }

    public static function digestAlgoUri(string $algorithm = self::SHA256): string
    {
        if ($algorithm === self::SHA1) {
            return Namespaces::DIGEST_SHA1;
        }

        if ($algorithm === self::SHA256) {
            return Namespaces::DIGEST_SHA256;
        }

        throw new SignatureException('Unsupported digest algorithm: ' . $algorithm);
    }

    public static function signatureAlgoUri(string $algorithm = self::SHA256): string
    {
        return $algorithm === self::SHA1
            ? Namespaces::SIG_METHOD_RSA_SHA1
            : Namespaces::SIG_METHOD_RSA_SHA256;
    }
}