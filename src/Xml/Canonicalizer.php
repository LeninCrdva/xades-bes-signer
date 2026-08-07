<?php

declare(strict_types=1);

namespace XadesBesSigner\Xml;

use XadesBesSigner\Exception\SignatureException;

/**
 * Canonicalization (C14N) helpers.
 *
 * The SRI requires inclusive canonicalization as defined by
 * http://www.w3.org/TR/2001/REC-xml-c14n-20010315. PHP exposes this natively
 * through \DOMNode::C14N().
 */
final class Canonicalizer
{
    private const LOAD_FLAGS = \LIBXML_NONET | \LIBXML_COMPACT;

    /**
     * Canonicalize a DOM node (inclusive C14N, no comments).
     *
     * @throws SignatureException when C14N fails.
     */
    public static function canonicalize(\DOMNode $node, bool $exclusive = false, bool $withComments = false): string
    {
        $output = $node->C14N($exclusive, $withComments);
        if ($output === false) {
            throw new SignatureException('Could not canonicalize XML node.');
        }

        return $output;
    }

    /**
     * Canonicalize the document excluding the given element.
     *
     * This is the input of the enveloped-signature transform: when a document
     * is signed with the enveloped signature transform, the ds:Signature
     * element itself is removed before computing the digest.
     */
    public static function canonicalizeDocumentExcluding(\DOMDocument $dom, \DOMElement $excluded): string
    {
        $clone = self::cloneDocument($dom);
        $cloneExcluded = self::findNodeById($clone, $excluded);

        if ($cloneExcluded !== null && $cloneExcluded->parentNode !== null) {
            $cloneExcluded->parentNode->removeChild($cloneExcluded);
        }

        $root = $clone->documentElement;
        if ($root === null) {
            throw new SignatureException('XML document has no root element.');
        }

        return self::canonicalize($root);
    }

    private static function cloneDocument(\DOMDocument $dom): \DOMDocument
    {
        $clone = new \DOMDocument('1.0', 'UTF-8');
        $clone->preserveWhiteSpace = true;
        $clone->formatOutput = false;

        $serialized = $dom->saveXML();
        if ($serialized === false || ! $clone->loadXML($serialized, self::LOAD_FLAGS) || $clone->documentElement === null) {
            throw new SignatureException('Could not clone XML document for canonicalization.');
        }

        return $clone;
    }

    private static function findNodeById(\DOMDocument $clone, \DOMElement $original): ?\DOMElement
    {
        $xpath = new \DOMXPath($clone);

        $id = $original->getAttribute('Id');
        if ($id !== '') {
            $nodes = $xpath->query('//*[@Id="' . $id . '"]');
            if ($nodes !== false && $nodes->length > 0) {
                $node = $nodes->item(0);

                return $node instanceof \DOMElement ? $node : null;
            }
        }

        $nodes = $xpath->query('//*[local-name()="Signature"]');
        if ($nodes !== false && $nodes->length > 0) {
            $node = $nodes->item(0);

            return $node instanceof \DOMElement ? $node : null;
        }

        return null;
    }
}