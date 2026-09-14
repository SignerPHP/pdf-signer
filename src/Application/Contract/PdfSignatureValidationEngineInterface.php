<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Application\Contract;

use SignerPHP\PdfSigner\Application\DTO\SignatureValidationResultDto;
use SignerPHP\PdfSigner\Application\DTO\ValidatePdfRequestDto;

interface PdfSignatureValidationEngineInterface
{
    public function validate(ValidatePdfRequestDto $request): SignatureValidationResultDto;
}
