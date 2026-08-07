<?php

declare(strict_types=1);

namespace XadesBesSigner;

use XadesBesSigner\Exception\SignatureException;
use XadesBesSigner\KeyProvider\PrivateKeySignerInterface;
use XadesBesSigner\Signature\SignatureContext;

/**
 * Signs several XML documents in one pass.
 *
 * Every document is handled independently and written to a destination
 * directory, so a failure in one file does not abort the rest.
 */
final class BatchSigner
{
    public function __construct(
        private readonly Signer $signer
    ) {
    }

    public static function with(PrivateKeySignerInterface $key): self
    {
        return new self(new Signer($key));
    }

    /**
     * Sign every *.xml file in a directory.
     *
     * @return array<string, string> map of source path => output file path.
     */
    public function signDirectory(string $inputDir, string $outputDir, ?SignatureContext $context = null): array
    {
        if (! is_dir($inputDir) || ! is_readable($inputDir)) {
            throw new SignatureException('Input directory is not readable: ' . $inputDir);
        }

        if (! is_dir($outputDir) && ! mkdir($outputDir, 0777, true) && ! is_dir($outputDir)) {
            throw new SignatureException('Could not create output directory: ' . $outputDir);
        }

        $files = glob(rtrim($inputDir, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . '*.xml') ?: [];

        return $this->signFiles($files, $outputDir, $context);
    }

    /**
     * Sign an arbitrary list of XML files. Output keeps the base name with a
     * "-signed" suffix unless $overwrite is true. When true, the source file
     * is replaced in place.
     *
     * @param list<string> $files
     * @return array<string, string> map of source path => output path.
     */
    public function signFiles(array $files, string $outputDir, ?SignatureContext $context = null, bool $overwrite = false): array
    {
        $results = [];
        foreach ($files as $file) {
            $baseName = pathinfo($file, PATHINFO_BASENAME);
            $target = $overwrite ? $file : rtrim($outputDir, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR
                . pathinfo($baseName, PATHINFO_FILENAME) . '-signed.xml';

            $signed = $this->signer->signFromFile($file, $context);
            file_put_contents($target, $signed);

            $results[$file] = $target;
        }

        return $results;
    }
}