<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Infrastructure\Native\ValueObject;

final readonly class SignatureCryptoVerification
{
    public function __construct(
        public bool $valid,
        public ?string $message = null,
        /** Time asserted by a verified timestamp token (TSTInfo genTime); null for CMS signatures. */
        public ?\DateTimeImmutable $signingTime = null,
    ) {}
}
