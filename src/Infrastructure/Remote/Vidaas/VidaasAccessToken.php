<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Infrastructure\Remote\Vidaas;

final readonly class VidaasAccessToken
{
    public function __construct(
        public string $value,
        public string $type = 'Bearer',
        public int $expiresIn = 0,
        public ?string $scope = null,
    ) {}
}
