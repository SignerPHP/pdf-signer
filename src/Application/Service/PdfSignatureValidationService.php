<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Application\Service;

use SignerPHP\PdfSigner\Application\Contract\PdfSignatureValidationEngineInterface;
use SignerPHP\PdfSigner\Application\DTO\SignatureValidationResultDto;
use SignerPHP\PdfSigner\Application\DTO\ValidatePdfRequestDto;

final readonly class PdfSignatureValidationService
{
    public function __construct(private PdfSignatureValidationEngineInterface $validationEngine) {}

    public function validate(ValidatePdfRequestDto $request): SignatureValidationResultDto
    {
        return $this->validationEngine->validate($request);
    }
}
