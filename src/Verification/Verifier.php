<?php

declare(strict_types=1);

namespace XadesBesSigner\Verification;

use XadesBesSigner\Certificate\Certificate;
use XadesBesSigner\Xml\Canonicalizer;
use XadesBesSigner\Xml\DigestCalculator;
use XadesBesSigner\Xml\Namespaces;
use XadesBesSigner\Xml\XmlDocument;

/**
 * Verifies a XAdES-BES enveloped signature:
 *
 *  1. RSA signature of the canonicalized SignedInfo (algorithm derived from
 *     the ds:SignatureMethod element: SHA-1 or SHA-256).
 *  2. Digest of the document with the ds:Signature element removed.
 *  3. Digest of the etsi:SignedProperties element.
 *  4. Digest of the ds:KeyInfo element.
 *  5. etsi:CertDigest / etsi:IssuerSerial inside SignedProperties match the
 *     certificate embedded in ds:KeyInfo.
 *  6. Embedded certificate validity window.
 */
final class Verifier
{
    private const DS_PREFIX = 'ds';

    private const XADES_PREFIX = 'etsi';

    public function verifyFromString(string $signedXml): VerificationResult
    {
        return $this->verifyDocument(XmlDocument::fromString($signedXml));
    }

    public function verifyFromFile(string $path): VerificationResult
    {
        return $this->verifyDocument(XmlDocument::fromFile($path));
    }

    private function verifyDocument(XmlDocument $xml): VerificationResult
    {
        $dom = $xml->getDom();
        $xpath = new \DOMXPath($dom);
        $xpath->registerNamespace(self::DS_PREFIX, Namespaces::XMLDSIG);
        $xpath->registerNamespace(self::XADES_PREFIX, Namespaces::XADES);

        $signature = $this->findSignature($xpath);
        if ($signature === null) {
            return new VerificationResult(false, false, false, false, ['No ds:Signature element found.']);
        }

        $signatureId = $signature->getAttribute('Id');
        $signedInfo = $this->findChild($signature, ['SignedInfo'])[0] ?? null;
        $signatureValueNode = $this->findChild($signature, ['SignatureValue'])[0] ?? null;

        if (! $signedInfo instanceof \DOMElement || ! $signatureValueNode instanceof \DOMElement) {
            return new VerificationResult(false, false, false, false, ['SignedInfo or SignatureValue is missing.']);
        }

        $errors = [];

        $signatureValid = $this->verifyRsaSignature($signedInfo, $signatureValueNode, $xpath);
        if (! $signatureValid) {
            $errors[] = 'SignatureValue does not validate over SignedInfo (RSA).';
        }

        $documentDigestOk = $this->verifyDocumentDigest($dom, $signature, $xpath);
        if (! $documentDigestOk) {
            $errors[] = 'Document digest mismatch (reference content changed since signing).';
        }

        $propertiesOk = $this->verifySignedPropertiesDigest($xpath);
        if (! $propertiesOk) {
            $errors[] = 'SignedProperties digest mismatch.';
        }

        $keyInfoOk = $this->verifyKeyInfoDigest($xpath);
        if (! $keyInfoOk) {
            $errors[] = 'KeyInfo digest mismatch.';
        }

        $signingCertificateOk = $this->verifySigningCertificate($xpath);
        if (! $signingCertificateOk) {
            $errors[] = 'SigningCertificate (CertDigest/IssuerSerial) does not match the embedded certificate.';
        }

        $certificateOk = $this->verifyCertificateIntegrity($xpath);
        if (! $certificateOk) {
            $errors[] = 'Certificate mismatch or outside its validity window.';
        }

        return new VerificationResult(
            $signatureValid,
            $documentDigestOk,
            $propertiesOk,
            $certificateOk,
            $errors,
            $this->extractSignerCommonName($xpath),
            $this->extractSigningTime($xpath),
            $signatureId,
            $keyInfoOk,
            $signingCertificateOk
        );
    }

    private function findSignature(\DOMXPath $xpath): ?\DOMElement
    {
        $nodes = $xpath->query('//' . self::DS_PREFIX . ':Signature');
        if ($nodes === false || $nodes->length === 0) {
            return null;
        }

        return $nodes->item(0) instanceof \DOMElement ? $nodes->item(0) : null;
    }

    /**
     * @return list<\DOMElement>
     */
    private function findChild(\DOMElement $parent, array $names): array
    {
        $found = [];
        foreach ($parent->childNodes as $child) {
            if ($child instanceof \DOMElement && in_array($child->localName, $names, true)
                && $child->namespaceURI === Namespaces::XMLDSIG) {
                $found[] = $child;
            }
        }

        return $found;
    }

    private function findFirstChild(\DOMElement $parent, array $names): ?\DOMElement
    {
        $found = $this->findChild($parent, $names);

        return $found[0] ?? null;
    }

    private function verifyRsaSignature(\DOMElement $signedInfo, \DOMElement $signatureValueNode, \DOMXPath $xpath): bool
    {
        $certificate = $this->extractEmbeddedCertificate($xpath);
        if ($certificate === null) {
            return false;
        }

        $base64 = trim($signatureValueNode->textContent);
        $signature = base64_decode($base64, true);
        if ($signature === false || $signature === '') {
            return false;
        }

        $canonicalizedSignedInfo = Canonicalizer::canonicalize($signedInfo);

        $method = $this->findFirstChild($signedInfo, ['SignatureMethod']);
        $algorithm = $method?->getAttribute('Algorithm') ?? '';
        $opensslAlgorithm = $algorithm === Namespaces::SIG_METHOD_RSA_SHA1
            ? \OPENSSL_ALGO_SHA1
            : \OPENSSL_ALGO_SHA256;

        $result = openssl_verify($canonicalizedSignedInfo, $signature, $certificate->getPublicKey(), $opensslAlgorithm);

        return $result === 1;
    }

    private function verifyDocumentDigest(\DOMDocument $dom, \DOMElement $signature, \DOMXPath $xpath): bool
    {
        $reference = $this->findDocumentReference($xpath);
        if ($reference === null) {
            return false;
        }

        $digestValue = $this->findChild($reference, ['DigestValue'])[0] ?? null;
        if (! $digestValue instanceof \DOMElement) {
            return false;
        }

        $algorithm = $this->resolveDigestAlgorithm($reference);

        $canonicalized = Canonicalizer::canonicalizeDocumentExcluding($dom, $signature);
        $expected = DigestCalculator::digestString($canonicalized, $algorithm);

        return hash_equals(trim($digestValue->textContent), $expected);
    }

    private function verifySignedPropertiesDigest(\DOMXPath $xpath): bool
    {
        $reference = $this->findReferenceByType($xpath, Namespaces::XADES_TYPE_SIGNED_PROPERTIES);
        $digestValue = $reference === null ? null : $this->findFirstChild($reference, ['DigestValue']);
        if ($reference === null || $digestValue === null) {
            return false;
        }

        $uri = $reference->getAttribute('URI');
        if ($uri === '' || $uri[0] !== '#') {
            return false;
        }

        $target = $this->findById($xpath, substr($uri, 1));
        if ($target === null || $target->localName !== 'SignedProperties'
            || $target->namespaceURI !== Namespaces::XADES) {
            return false;
        }

        $algorithm = $this->resolveDigestAlgorithm($reference);
        $expected = DigestCalculator::digestNode($target, $algorithm);

        return hash_equals(trim($digestValue->textContent), $expected);
    }

    private function verifyKeyInfoDigest(\DOMXPath $xpath): bool
    {
        $keyInfo = $this->findFirstElementByLocalName($xpath, 'KeyInfo');
        if (! $keyInfo instanceof \DOMElement) {
            return false;
        }

        $id = $keyInfo->getAttribute('Id');
        if ($id !== '') {
            $reference = $this->findReferenceByUri($xpath, '#' . $id);
        } else {
            $reference = $this->findUnclassifiedReference($xpath);
        }

        if ($reference === null) {
            return false;
        }

        $digestValue = $this->findFirstChild($reference, ['DigestValue']);
        if ($digestValue === null) {
            return false;
        }

        $algorithm = $this->resolveDigestAlgorithm($reference);
        $expected = DigestCalculator::digestNode($keyInfo, $algorithm);

        return hash_equals(trim($digestValue->textContent), $expected);
    }

    private function verifySigningCertificate(\DOMXPath $xpath): bool
    {
        $certificate = $this->extractEmbeddedCertificate($xpath);
        if ($certificate === null) {
            return false;
        }

        $cert = $this->findElementByLocalName($xpath, 'Cert');
        if ($cert === null) {
            return false;
        }

        $certDigest = $this->findDescendantByLocalName($cert, 'CertDigest');
        if ($certDigest === null) {
            return false;
        }

        $digestMethod = $this->findDescendantByLocalName($certDigest, 'DigestMethod');
        $algorithm = $digestMethod?->getAttribute('Algorithm') === Namespaces::DIGEST_SHA1
            ? DigestCalculator::SHA1
            : DigestCalculator::SHA256;

        $digestValue = $this->findDescendantByLocalName($certDigest, 'DigestValue');
        if ($digestValue === null
            || ! hash_equals(trim($digestValue->textContent), $certificate->getDigest($algorithm))) {
            return false;
        }

        $issuerSerial = $this->findDescendantByLocalName($cert, 'IssuerSerial');
        if ($issuerSerial === null) {
            return false;
        }

        $issuerName = $this->findDescendantByLocalName($issuerSerial, 'X509IssuerName');
        if ($issuerName === null || trim($issuerName->textContent) !== $certificate->getIssuerName()) {
            return false;
        }

        $serialNumber = $this->findDescendantByLocalName($issuerSerial, 'X509SerialNumber');
        if ($serialNumber === null || trim($serialNumber->textContent) !== $certificate->getSerialNumber()) {
            return false;
        }

        return true;
    }

    private function verifyCertificateIntegrity(\DOMXPath $xpath): bool
    {
        $certificate = $this->extractEmbeddedCertificate($xpath);
        if ($certificate === null) {
            return false;
        }

        return $certificate->isCurrentlyValid();
    }

    private function extractEmbeddedCertificate(\DOMXPath $xpath): ?Certificate
    {
        $nodes = $xpath->query('//' . self::DS_PREFIX . ':X509Certificate');
        if ($nodes === false || $nodes->length === 0) {
            return null;
        }

        $base64 = trim($nodes->item(0)->textContent);
        if ($base64 === '') {
            return null;
        }

        $pem = $this->base64ToPem($base64);

        try {
            return Certificate::fromPem($pem);
        } catch (\Throwable) {
            return null;
        }
    }

    /**
     * The document reference is the one carrying the enveloped-signature
     * transform, regardless of whether its URI points to the whole document
     * (empty) or to the root element id (#comprobante).
     */
    private function findDocumentReference(\DOMXPath $xpath): ?\DOMElement
    {
        $nodes = $xpath->query('//' . self::DS_PREFIX . ':Reference');
        if ($nodes === false) {
            return null;
        }

        foreach ($nodes as $node) {
            if (! $node instanceof \DOMElement) {
                continue;
            }

            $transforms = $this->findChild($node, ['Transforms'])[0] ?? null;
            if ($transforms === null) {
                continue;
            }

            foreach ($this->findChild($transforms, ['Transform']) as $transform) {
                if ($transform->getAttribute('Algorithm') === Namespaces::TRANSFORM_ENVELOPED) {
                    return $node;
                }
            }
        }

        return null;
    }

    private function findReferenceByUri(\DOMXPath $xpath, string $uri): ?\DOMElement
    {
        $nodes = $xpath->query('//' . self::DS_PREFIX . ':Reference[@URI="' . $uri . '"]');
        if ($nodes === false || $nodes->length === 0) {
            return null;
        }

        return $nodes->item(0) instanceof \DOMElement ? $nodes->item(0) : null;
    }

    private function findReferenceByType(\DOMXPath $xpath, string $type): ?\DOMElement
    {
        $nodes = $xpath->query('//' . self::DS_PREFIX . ':Reference[@Type="' . $type . '"]');
        if ($nodes === false || $nodes->length === 0) {
            return null;
        }

        return $nodes->item(0) instanceof \DOMElement ? $nodes->item(0) : null;
    }

    /**
     * Reference used when ds:KeyInfo has no Id: any reference that is neither
     * the document reference nor a SignedProperties reference.
     */
    private function findUnclassifiedReference(\DOMXPath $xpath): ?\DOMElement
    {
        $document = $this->findDocumentReference($xpath);
        $properties = $this->findReferenceByType($xpath, Namespaces::XADES_TYPE_SIGNED_PROPERTIES);

        $nodes = $xpath->query('//' . self::DS_PREFIX . ':Reference');
        if ($nodes === false) {
            return null;
        }

        foreach ($nodes as $node) {
            if ($node instanceof \DOMElement && $node !== $document && $node !== $properties) {
                return $node;
            }
        }

        return null;
    }

    private function findById(\DOMXPath $xpath, string $id): ?\DOMElement
    {
        $nodes = $xpath->query('//*[@Id="' . $id . '"]');
        if ($nodes === false || $nodes->length === 0) {
            return null;
        }

        return $nodes->item(0) instanceof \DOMElement ? $nodes->item(0) : null;
    }

    private function findFirstElementByLocalName(\DOMXPath $xpath, string $localName): ?\DOMElement
    {
        $nodes = $xpath->query('//*[local-name()="' . $localName . '" and namespace-uri()="' . Namespaces::XMLDSIG . '"]');
        if ($nodes === false || $nodes->length === 0) {
            return null;
        }

        return $nodes->item(0) instanceof \DOMElement ? $nodes->item(0) : null;
    }

    private function findElementByLocalName(\DOMXPath $xpath, string $localName): ?\DOMElement
    {
        $nodes = $xpath->query('//*[local-name()="' . $localName . '" and namespace-uri()="' . Namespaces::XADES . '"]');
        if ($nodes === false || $nodes->length === 0) {
            return null;
        }

        return $nodes->item(0) instanceof \DOMElement ? $nodes->item(0) : null;
    }

    private function findDescendantByLocalName(\DOMElement $parent, string $localName): ?\DOMElement
    {
        $element = $parent->getElementsByTagNameNS('*', $localName)->item(0);

        return $element instanceof \DOMElement ? $element : null;
    }

    private function resolveDigestAlgorithm(\DOMElement $reference): string
    {
        $digestMethod = $this->findFirstChild($reference, ['DigestMethod']);
        if ($digestMethod !== null) {
            $algorithm = $digestMethod->getAttribute('Algorithm');

            return $algorithm === Namespaces::DIGEST_SHA1
                ? DigestCalculator::SHA1
                : DigestCalculator::SHA256;
        }

        return DigestCalculator::SHA1;
    }

    private function base64ToPem(string $base64): string
    {
        $body = preg_replace('/\s+/', '', $base64) ?: '';

        return "-----BEGIN CERTIFICATE-----\n"
            . implode("\n", str_split($body, 64))
            . "\n-----END CERTIFICATE-----\n";
    }

    private function extractSigningTime(\DOMXPath $xpath): ?\DateTimeImmutable
    {
        $nodes = $xpath->query('//' . self::XADES_PREFIX . ':SigningTime');
        if ($nodes === false || $nodes->length === 0) {
            return null;
        }

        $text = trim($nodes->item(0)->textContent);
        $date = \DateTimeImmutable::createFromFormat('Y-m-d\TH:i:sP', $text);
        if ($date === false) {
            $date = \DateTimeImmutable::createFromFormat('Y-m-d\TH:i:s\Z', $text, new \DateTimeZone('UTC'));
        }
        if ($date === false) {
            $date = \DateTimeImmutable::createFromFormat(\DateTime::ATOM, $text);
        }
        if ($date === false) {
            return null;
        }

        return $date;
    }

    private function extractSignerCommonName(\DOMXPath $xpath): ?string
    {
        return $this->extractEmbeddedCertificate($xpath)?->getCommonName();
    }
}