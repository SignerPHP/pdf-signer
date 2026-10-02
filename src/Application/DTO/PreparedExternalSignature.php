<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Application\DTO;

final readonly class PreparedExternalSignature
{
    public function __construct(
        public ExternalSigningPayload $payload,
        public string $state,
    ) {}
}
