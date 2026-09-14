<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Infrastructure\Native;

use SignerPHP\PdfSigner\Application\Contract\PdfProtectionEngineInterface;
use SignerPHP\PdfSigner\Application\DTO\ProtectPdfRequestDto;
use SignerPHP\PdfSigner\Domain\Exception\ProtectionProcessException;
use SignerPHP\PdfSigner\Infrastructure\Native\Contract\PdfProtectionApplierInterface;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\QpdfPdfProtectionApplier;

final readonly class NativePdfProtectionEngine implements PdfProtectionEngineInterface
{
    public function __construct(
        private PdfProtectionApplierInterface $protectionApplier = new QpdfPdfProtectionApplier,
    ) {}

    public function protect(ProtectPdfRequestDto $request): string
    {
        try {
            return $this->protectionApplier->apply($request->pdf->content, $request->options);
        } catch (\Throwable $throwable) {
            throw new ProtectionProcessException(
                sprintf('Could not apply PDF protection using native v1 engine. Root cause: %s', $throwable->getMessage()),
                previous: $throwable,
            );
        }
    }
}
