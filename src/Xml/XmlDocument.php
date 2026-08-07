<?php

declare(strict_types=1);

namespace XadesBesSigner\Xml;

use XadesBesSigner\Exception\SignatureException;

/**
 * Thin, secure wrapper around \DOMDocument.
 *
 * Loading is hardened against XXE (external entities and network access are
 * disabled) which is a mandatory safety concern when signing XML documents.
 */
final class XmlDocument
{
    public const LOAD_FLAGS = \LIBXML_NONET | \LIBXML_NOBLANKS | \LIBXML_COMPACT;

    private \DOMDocument $dom;

    private function __construct(\DOMDocument $dom)
    {
        $this->dom = $dom;
    }

    /**
     * Create an empty document.
     */
    public static function create(): self
    {
        $dom = new \DOMDocument('1.0', 'UTF-8');
        $dom->preserveWhiteSpace = true;
        $dom->formatOutput = false;

        return new self($dom);
    }

    /**
     * Load an XML document from a string.
     *
     * @throws SignatureException when the input is not well-formed XML.
     */
    public static function fromString(string $xml): self
    {
        $dom = new \DOMDocument('1.0', 'UTF-8');
        $dom->preserveWhiteSpace = true;
        $dom->formatOutput = false;

        $previous = libxml_use_internal_errors(true);
        $loaded = $dom->loadXML($xml, self::LOAD_FLAGS);
        $errors = libxml_get_errors();
        libxml_clear_errors();
        libxml_use_internal_errors($previous);

        if (! $loaded) {
            $message = self::formatLibxmlErrors($errors);
            throw new SignatureException('Could not parse XML document: ' . ($message ?: 'unknown error'));
        }

        if ($dom->documentElement === null) {
            throw new SignatureException('XML document has no root element.');
        }

        return new self($dom);
    }

    /**
     * Load an XML document from a file.
     *
     * @throws SignatureException when the file cannot be loaded.
     */
    public static function fromFile(string $path): self
    {
        if (! is_file($path) || ! is_readable($path)) {
            throw new SignatureException('XML file is not readable: ' . $path);
        }

        $content = file_get_contents($path);
        if ($content === false) {
            throw new SignatureException('Could not read XML file: ' . $path);
        }

        return self::fromString($content);
    }

    public function getDom(): \DOMDocument
    {
        return $this->dom;
    }

    public function getRootElement(): \DOMElement
    {
        $root = $this->dom->documentElement;
        if ($root === null) {
            throw new SignatureException('XML document has no root element.');
        }

        return $root;
    }

    /**
     * Serialize the document back to a string, always declaring UTF-8.
     */
    public function toString(): string
    {
        $this->dom->encoding = 'UTF-8';
        $xml = $this->dom->saveXML();
        if ($xml === false) {
            throw new SignatureException('Could not serialize the XML document.');
        }

        return $xml;
    }

    private static function formatLibxmlErrors(array $errors): string
    {
        $messages = [];
        foreach ($errors as $libxmlError) {
            $messages[] = trim($libxmlError->message);
        }

        return implode(' | ', array_filter($messages));
    }
}