<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Application\Service;

use SignerPHP\PdfSigner\Application\Contract\CertificateValidatorInterface;
use SignerPHP\PdfSigner\Application\Contract\PdfSigningEngineInterface;
use SignerPHP\PdfSigner\Application\DTO\LocalSigningContextDto;
use SignerPHP\PdfSigner\Application\DTO\SigningCertificateDto;
use SignerPHP\PdfSigner\Application\DTO\SigningContextDto;
use SignerPHP\PdfSigner\Application\DTO\SignPdfRequestDto;

final readonly class PdfSigningService
{
    public function __construct(
        private CertificateValidatorInterface $certificateValidator,
        private PdfSigningEngineInterface $signingEngine,
    ) {}

    public function sign(SignPdfRequestDto $request): string
    {
        $verified = $this->certificateValidator->validate($request->certificate);
        $certificate = new SigningCertificateDto(
            (string) ($verified->bundle['cert'] ?? ''),
            $this->certificateChain($verified->bundle['extracerts'] ?? []),
        );
        $context = new LocalSigningContextDto(
            new SigningContextDto($request->pdf, $request->options, $certificate),
            $verified,
        );

        return $this->signingEngine->sign($context);
    }

    /** @return list<string> */
    private function certificateChain(mixed $chain): array
    {
        if (is_string($chain)) {
            return [$chain];
        }

        return is_array($chain) ? array_values(array_filter($chain, 'is_string')) : [];
    }
}
