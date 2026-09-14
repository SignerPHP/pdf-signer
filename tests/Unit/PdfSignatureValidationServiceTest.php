<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Tests\Unit;

use PHPUnit\Framework\TestCase;
use SignerPHP\PdfSigner\Application\Contract\PdfSignatureValidationEngineInterface;
use SignerPHP\PdfSigner\Application\DTO\PdfContentDto;
use SignerPHP\PdfSigner\Application\DTO\SignatureValidationResultDto;
use SignerPHP\PdfSigner\Application\DTO\ValidatePdfRequestDto;
use SignerPHP\PdfSigner\Application\Service\PdfSignatureValidationService;

final class PdfSignatureValidationServiceTest extends TestCase
{
    public function test_service_delegates_to_validation_engine(): void
    {
        $capture = new class
        {
            public ?string $content = null;
        };

        $engine = new class($capture) implements PdfSignatureValidationEngineInterface
        {
            public function __construct(private object $capture) {}

            public function validate(ValidatePdfRequestDto $request): SignatureValidationResultDto
            {
                $this->capture->content = $request->pdf->content;

                return new SignatureValidationResultDto(false, false, []);
            }
        };

        $service = new PdfSignatureValidationService($engine);
        $service->validate(new ValidatePdfRequestDto(new PdfContentDto('pdf-content')));

        self::assertSame('pdf-content', $capture->content);
    }
}
