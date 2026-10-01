<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Infrastructure\Native\Service\Cms;

use SignerPHP\PdfSigner\Application\DTO\HashAlgorithm;
use SignerPHP\PdfSigner\Application\DTO\SignatureAlgorithm;

final readonly class PreparedDetachedCms
{
    public function __construct(
        public string $certificatePem,
        public string $signedAttributes,
        public HashAlgorithm $digestAlgorithm,
        public SignatureAlgorithm $signatureAlgorithm,
    ) {}
}
