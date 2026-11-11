<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Infrastructure\Remote\BirdId;

final readonly class BirdIdUserDiscoveryResult
{
    /** @param list<BirdIdSlot> $slots */
    public function __construct(
        public bool $hasCertificate,
        public array $slots = [],
    ) {}
}
