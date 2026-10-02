<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Infrastructure\Remote\Vidaas;

final readonly class VidaasPushAuthorization
{
    public function __construct(public string $code) {}
}
