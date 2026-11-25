<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Infrastructure\Native\Service\Encryption;

final readonly class PdfObjectGraph
{
    /**
     * @param  array<int, PdfIndirectObject>  $objects  keyed by object number
     */
    public function __construct(
        public string $version,
        public PdfDictionaryNode $trailer,
        public array $objects,
    ) {}
}
