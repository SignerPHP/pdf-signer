<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Infrastructure\Native\Service\Encryption;

final readonly class PdfIndirectObject
{
    public function __construct(
        public int $objectNumber,
        public int $generation,
        public PdfNode $value,
        public ?string $stream = null,
    ) {}
}
