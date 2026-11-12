<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Infrastructure\Remote\BirdId;

final readonly class BirdIdAccessToken
{
    public function __construct(
        public string $value,
        public string $type = 'Bearer',
        public int $expiresIn = 0,
        public ?string $scope = null,
        public ?string $authorizedIdentificationType = null,
        public ?string $authorizedIdentification = null,
    ) {}
}
