<?php

declare(strict_types=1);

namespace XadesBesSigner\Xml;

use XadesBesSigner\Certificate\Certificate;
use XadesBesSigner\Signature\SignatureContext;
use XadesBesSigner\Signature\SignatureValueCalculator;

/**
 * Builds the ds:Signature envelope that makes up the XAdES-BES signature.
 *
 * The structure mirrors the SRI reference implementation (XAdES4J): three
 * references inside ds:SignedInfo (xades:SignedProperties, ds:KeyInfo and the
 * document), a ds:KeyValue with the RSA public key next to ds:X509Data, and
 * base64 payloads wrapped at 76 characters per line.
 *
 * Resolving the circular references of an enveloping signature implies the
 * following construction order:
 *
 *  1. Build the skeleton (empty DigestValue / SignatureValue placeholders and
 *     the xades:SignedProperties block in place).
 *  2. Compute the digest of the document. Since only the *original* document
 *     is the reference input (the enveloped-signature transform removes the
 *     ds:Signature element before hashing), the digest is computed BEFORE the
 *     signature element is appended to the root.
 *  3. Compute the digest of xades:SignedProperties from its document node.
 *  4. Compute the digest of ds:KeyInfo from its document node.
 *  5. Fill the DigestValue placeholders in SignedInfo.
 *  6. Canonicalize SignedInfo and compute the SignatureValue.
 *  7. Fill SignatureValue and append the whole signature under the root.
 */
final class SignatureBuilder
{
    private const DS_PREFIX = 'ds';

    private const XADES_PREFIX = 'xades';

    private const BASE64_LINE_LENGTH = 76;

    private \DOMDocument $doc;

    private \DOMElement $signedInfo;

    private \DOMElement $signatureValue;

    private \DOMElement $referenceDocument;

    private \DOMElement $referenceKeyInfo;

    private \DOMElement $referenceProperties;

    private \DOMElement $signedProperties;

    private \DOMElement $keyInfo;

    private string $signatureId;

    private string $signedPropertiesId;

    private string $keyInfoId;

    public function __construct(
        private readonly XmlDocument $xml,
        private readonly SignatureContext $context,
        private readonly Certificate $certificate
    ) {
        $this->doc = $xml->getDom();
        $this->signatureId = $context->generateSignatureId();
        $this->signedPropertiesId = $this->signatureId . '-SignedProperties';
        $this->keyInfoId = 'Certificate' . bin2hex(random_bytes(4));
    }

    public static function sign(
        XmlDocument $xml,
        SignatureContext $context,
        Certificate $certificate,
        SignatureValueCalculator $calculator
    ): void {
        (new self($xml, $context, $certificate))->run($calculator);
    }

    private function run(SignatureValueCalculator $calculator): void
    {
        $root = $this->xml->getRootElement();

        /*
         * Attach the (still empty) signature skeleton to the document tree
         * FIRST: DOMDocument only emits compact namespace declarations when
         * children are created while the parent is already in the tree.
         * Building detached would force a redundant xmlns:* on every node.
         */
        $signature = $this->createSignatureElement();
        $root->appendChild($signature);

        $this->signedInfo = $this->buildSignedInfo();
        $signature->appendChild($this->signedInfo);

        $this->signatureValue = $this->createSignatureValue();
        $signature->appendChild($this->signatureValue);

        $this->keyInfo = $this->buildKeyInfo();
        $signature->appendChild($this->keyInfo);

        $signature->appendChild($this->buildQualifyingProperties());

        /*
         * Namespace normalization MUST run before digest/signature
         * computation: C14N renders the namespace declarations that are in
         * scope, so sign and verify must see identical canonical forms.
         */
        $this->normalizeNamespaces($signature);

        /*
         * Document digest: the enveloped-signature transform removes the whole
         * ds:Signature before hashing, so its reference input is the document
         * without the signature element.
         */
        $documentDigest = DigestCalculator::digestString(
            Canonicalizer::canonicalizeDocumentExcluding($this->doc, $signature),
            $this->context->digestAlgorithm
        );
        $this->setDigestValue($this->referenceDocument, $documentDigest);

        $propertiesDigest = DigestCalculator::digestNode($this->signedProperties, $this->context->digestAlgorithm);
        $this->setDigestValue($this->referenceProperties, $propertiesDigest);

        $keyInfoDigest = DigestCalculator::digestNode($this->keyInfo, $this->context->digestAlgorithm);
        $this->setDigestValue($this->referenceKeyInfo, $keyInfoDigest);

        $canonicalizedSignedInfo = Canonicalizer::canonicalize($this->signedInfo);
        $signatureValue = $calculator->calculate($canonicalizedSignedInfo);
        $this->signatureValue->appendChild($this->doc->createTextNode($this->wrapBase64($signatureValue)));
    }

    /**
     * DOMDocument::createElementNS() binds a namespaced prefix to every node
     * it creates, which leads to redundant xmlns:* declarations once the
     * elements are assembled. Emitted XML is valid either way, but the SRI
     * reference implementation (XAdES4J) produces a single declaration pair on
     * ds:Signature. This pass re-declares both prefixes on the signature root
     * and strips the redundant per-node declarations.
     */
    private function normalizeNamespaces(\DOMElement $signature): void
    {
        $declared = [];
        foreach ($signature->attributes as $attribute) {
            if ($attribute->namespaceURI === 'http://www.w3.org/2000/xmlns/'
                && in_array($attribute->localName, [self::DS_PREFIX, self::XADES_PREFIX], true)) {
                $declared[$attribute->localName] = true;
            }
        }

        foreach ([self::DS_PREFIX, self::XADES_PREFIX] as $prefix) {
            if (! isset($declared[$prefix])) {
                $signature->setAttributeNS(
                    'http://www.w3.org/2000/xmlns/',
                    'xmlns:' . $prefix,
                    $prefix === self::DS_PREFIX ? Namespaces::XMLDSIG : Namespaces::XADES
                );
            }
        }

        $elements = [];
        foreach ($signature->getElementsByTagName('*') as $element) {
            $elements[] = $element;
        }

        foreach ($elements as $element) {
            $element->removeAttribute('xmlns:' . self::DS_PREFIX);
            $element->removeAttribute('xmlns:' . self::XADES_PREFIX);
        }
    }

    private function createSignatureElement(): \DOMElement
    {
        $element = $this->doc->createElementNS(Namespaces::XMLDSIG, self::DS_PREFIX . ':Signature');
        $element->setAttribute('Id', $this->signatureId);

        return $element;
    }

    private function buildSignedInfo(): \DOMElement
    {
        $signedInfo = $this->doc->createElementNS(Namespaces::XMLDSIG, self::DS_PREFIX . ':SignedInfo');

        $canonicalizationMethod = $this->doc->createElementNS(Namespaces::XMLDSIG, self::DS_PREFIX . ':CanonicalizationMethod');
        $canonicalizationMethod->setAttribute('Algorithm', Namespaces::C14N_INCLUSIVE);
        $signedInfo->appendChild($canonicalizationMethod);

        $signatureMethod = $this->doc->createElementNS(Namespaces::XMLDSIG, self::DS_PREFIX . ':SignatureMethod');
        $signatureMethod->setAttribute('Algorithm', DigestCalculator::signatureAlgoUri($this->context->digestAlgorithm));
        $signedInfo->appendChild($signatureMethod);

        $this->referenceProperties = $this->createReferenceSignedProperties();
        $this->referenceKeyInfo = $this->createReferenceKeyInfo();
        $this->referenceDocument = $this->createReferenceDocument();

        $signedInfo->appendChild($this->referenceProperties);
        $signedInfo->appendChild($this->referenceKeyInfo);
        $signedInfo->appendChild($this->referenceDocument);

        return $signedInfo;
    }

    private function createReferenceDocument(): \DOMElement
    {
        $reference = $this->doc->createElementNS(Namespaces::XMLDSIG, self::DS_PREFIX . ':Reference');
        $reference->setAttribute('Id', $this->signatureId . '-Reference');

        $rootId = $this->xml->getRootElement()->getAttribute('id');
        if ($rootId === '') {
            $rootId = $this->xml->getRootElement()->getAttribute('Id');
        }

        if ($rootId !== '') {
            $reference->setAttribute('URI', '#' . $rootId);
        }

        $transforms = $this->doc->createElementNS(Namespaces::XMLDSIG, self::DS_PREFIX . ':Transforms');
        $transform = $this->doc->createElementNS(Namespaces::XMLDSIG, self::DS_PREFIX . ':Transform');
        $transform->setAttribute('Algorithm', Namespaces::TRANSFORM_ENVELOPED);
        $transforms->appendChild($transform);
        $reference->appendChild($transforms);

        $reference->appendChild($this->createDigestMethod());
        $reference->appendChild($this->createEmptyDigestValue());

        return $reference;
    }

    private function createReferenceKeyInfo(): \DOMElement
    {
        $reference = $this->doc->createElementNS(Namespaces::XMLDSIG, self::DS_PREFIX . ':Reference');
        $reference->setAttribute('Id', $this->signatureId . '-Reference-KeyInfo');
        $reference->setAttribute('URI', '#' . $this->keyInfoId);

        $reference->appendChild($this->createDigestMethod());
        $reference->appendChild($this->createEmptyDigestValue());

        return $reference;
    }

    private function createReferenceSignedProperties(): \DOMElement
    {
        $reference = $this->doc->createElementNS(Namespaces::XMLDSIG, self::DS_PREFIX . ':Reference');
        $reference->setAttribute('Id', $this->signatureId . '-Reference-SignedProperties');
        $reference->setAttribute('Type', Namespaces::XADES_TYPE_SIGNED_PROPERTIES);
        $reference->setAttribute('URI', '#' . $this->signedPropertiesId);

        $reference->appendChild($this->createDigestMethod());
        $reference->appendChild($this->createEmptyDigestValue());

        return $reference;
    }

    private function createDigestMethod(): \DOMElement
    {
        $digestMethod = $this->doc->createElementNS(Namespaces::XMLDSIG, self::DS_PREFIX . ':DigestMethod');
        $digestMethod->setAttribute('Algorithm', DigestCalculator::digestAlgoUri($this->context->digestAlgorithm));

        return $digestMethod;
    }

    private function createEmptyDigestValue(): \DOMElement
    {
        return $this->doc->createElementNS(Namespaces::XMLDSIG, self::DS_PREFIX . ':DigestValue');
    }

    private function createSignatureValue(): \DOMElement
    {
        return $this->doc->createElementNS(Namespaces::XMLDSIG, self::DS_PREFIX . ':SignatureValue');
    }

    private function buildKeyInfo(): \DOMElement
    {
        $keyInfo = $this->doc->createElementNS(Namespaces::XMLDSIG, self::DS_PREFIX . ':KeyInfo');
        $keyInfo->setAttribute('Id', $this->keyInfoId);

        $x509Data = $this->doc->createElementNS(Namespaces::XMLDSIG, self::DS_PREFIX . ':X509Data');
        $x509Certificate = $this->doc->createElementNS(Namespaces::XMLDSIG, self::DS_PREFIX . ':X509Certificate');
        $x509Certificate->appendChild($this->doc->createTextNode($this->wrapBase64($this->certificate->toDerBase64())));
        $x509Data->appendChild($x509Certificate);
        $keyInfo->appendChild($x509Data);

        $keyValue = $this->doc->createElementNS(Namespaces::XMLDSIG, self::DS_PREFIX . ':KeyValue');
        $rsaKeyValue = $this->doc->createElementNS(Namespaces::XMLDSIG, self::DS_PREFIX . ':RSAKeyValue');

        $modulus = $this->doc->createElementNS(Namespaces::XMLDSIG, self::DS_PREFIX . ':Modulus');
        $modulus->appendChild($this->doc->createTextNode($this->wrapBase64($this->certificate->getRsaModulusBase64())));
        $rsaKeyValue->appendChild($modulus);

        $exponent = $this->doc->createElementNS(Namespaces::XMLDSIG, self::DS_PREFIX . ':Exponent');
        $exponent->appendChild($this->doc->createTextNode($this->certificate->getRsaExponentBase64()));
        $rsaKeyValue->appendChild($exponent);

        $keyValue->appendChild($rsaKeyValue);
        $keyInfo->appendChild($keyValue);

        return $keyInfo;
    }

    private function buildQualifyingProperties(): \DOMElement
    {
        $object = $this->doc->createElementNS(Namespaces::XMLDSIG, self::DS_PREFIX . ':Object');

        $qualifyingProperties = $this->doc->createElementNS(Namespaces::XADES, self::XADES_PREFIX . ':QualifyingProperties');
        $qualifyingProperties->setAttribute('Target', '#' . $this->signatureId);

        $signedProperties = $this->doc->createElementNS(Namespaces::XADES, self::XADES_PREFIX . ':SignedProperties');
        $signedProperties->setAttribute('Id', $this->signedPropertiesId);
        $signedProperties->appendChild($this->buildSignedSignatureProperties());
        if ($this->context->includeDataObjectFormat) {
            $signedProperties->appendChild($this->buildSignedDataObjectProperties());
        }

        $qualifyingProperties->appendChild($signedProperties);
        $object->appendChild($qualifyingProperties);

        $this->signedProperties = $signedProperties;

        return $object;
    }

    private function buildSignedSignatureProperties(): \DOMElement
    {
        $properties = $this->doc->createElementNS(Namespaces::XADES, self::XADES_PREFIX . ':SignedSignatureProperties');

        $signingTime = $this->doc->createElementNS(Namespaces::XADES, self::XADES_PREFIX . ':SigningTime');
        $signingTime->appendChild($this->doc->createTextNode($this->context->toXsdDateTime()));
        $properties->appendChild($signingTime);

        $properties->appendChild($this->buildSigningCertificate());

        return $properties;
    }

    private function buildSigningCertificate(): \DOMElement
    {
        $signingCertificate = $this->doc->createElementNS(Namespaces::XADES, self::XADES_PREFIX . ':SigningCertificate');
        $cert = $this->doc->createElementNS(Namespaces::XADES, self::XADES_PREFIX . ':Cert');

        $certDigest = $this->doc->createElementNS(Namespaces::XADES, self::XADES_PREFIX . ':CertDigest');
        $certDigest->appendChild($this->createDigestMethod());

        $digestValue = $this->doc->createElementNS(Namespaces::XMLDSIG, self::DS_PREFIX . ':DigestValue');
        $digestValue->appendChild($this->doc->createTextNode($this->certificate->getDigest($this->context->digestAlgorithm)));
        $certDigest->appendChild($digestValue);

        $issuerSerial = $this->doc->createElementNS(Namespaces::XADES, self::XADES_PREFIX . ':IssuerSerial');

        $x509IssuerName = $this->doc->createElementNS(Namespaces::XMLDSIG, self::DS_PREFIX . ':X509IssuerName');
        $x509IssuerName->appendChild($this->doc->createTextNode($this->certificate->getIssuerName()));
        $issuerSerial->appendChild($x509IssuerName);

        $x509SerialNumber = $this->doc->createElementNS(Namespaces::XMLDSIG, self::DS_PREFIX . ':X509SerialNumber');
        $x509SerialNumber->appendChild($this->doc->createTextNode($this->certificate->getSerialNumber()));
        $issuerSerial->appendChild($x509SerialNumber);

        $cert->appendChild($certDigest);
        $cert->appendChild($issuerSerial);

        $signingCertificate->appendChild($cert);

        return $signingCertificate;
    }

    private function buildSignedDataObjectProperties(): \DOMElement
    {
        $properties = $this->doc->createElementNS(Namespaces::XADES, self::XADES_PREFIX . ':SignedDataObjectProperties');

        $dataObjectFormat = $this->doc->createElementNS(Namespaces::XADES, self::XADES_PREFIX . ':DataObjectFormat');
        $dataObjectFormat->setAttribute('ObjectReference', '#' . $this->signatureId . '-Reference');

        $description = $this->doc->createElementNS(Namespaces::XADES, self::XADES_PREFIX . ':Description');
        $description->appendChild($this->doc->createTextNode('contenido comprobante'));
        $dataObjectFormat->appendChild($description);

        $mimeType = $this->doc->createElementNS(Namespaces::XADES, self::XADES_PREFIX . ':MimeType');
        $mimeType->appendChild($this->doc->createTextNode($this->context->mimeType));
        $dataObjectFormat->appendChild($mimeType);

        $properties->appendChild($dataObjectFormat);

        return $properties;
    }

    private function setDigestValue(\DOMElement $reference, string $value): void
    {
        $digestValue = $reference->getElementsByTagNameNS(Namespaces::XMLDSIG, 'DigestValue')->item(0);
        if ($digestValue instanceof \DOMElement) {
            $digestValue->appendChild($this->doc->createTextNode($value));
        }
    }

    private function wrapBase64(string $base64): string
    {
        return chunk_split($base64, self::BASE64_LINE_LENGTH, "\n");
    }
}