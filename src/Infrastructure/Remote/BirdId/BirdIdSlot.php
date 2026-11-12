<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Infrastructure\Remote\BirdId;

final readonly class BirdIdSlot
{
    public function __construct(
        public string $alias,
        public string $label,
    ) {}
}
