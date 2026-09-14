<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Infrastructure\Native\Contract;

use SignerPHP\PdfSigner\Application\DTO\SignatureAppearanceDto;

interface DefaultSignatureAppearanceProviderInterface
{
    public function makeDefault(): SignatureAppearanceDto;
}
