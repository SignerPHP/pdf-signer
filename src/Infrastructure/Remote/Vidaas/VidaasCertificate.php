<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Infrastructure\Remote\Vidaas;

final readonly class VidaasCertificate
{
    public function __construct(
        public string $alias,
        public string $pem,
    ) {}
}
