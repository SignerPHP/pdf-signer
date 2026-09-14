<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Presentation;

use SignerPHP\PdfSigner\Application\Service\PdfProtectionService;
use SignerPHP\PdfSigner\Application\Service\PdfSignatureValidationService;
use SignerPHP\PdfSigner\Application\Service\PdfSigningService;
use SignerPHP\PdfSigner\Application\Service\TimestampService;
use SignerPHP\PdfSigner\Infrastructure\Legacy\OpenSslCertificateValidator;
use SignerPHP\PdfSigner\Infrastructure\Native\NativePdfProtectionEngine;
use SignerPHP\PdfSigner\Infrastructure\Native\NativePdfSignatureValidationEngine;
use SignerPHP\PdfSigner\Infrastructure\Native\NativePdfSigningEngine;

final class Signer
{
    public static function signer(): SignerBuilder
    {
        $signingService = new PdfSigningService(
            new OpenSslCertificateValidator,
            new NativePdfSigningEngine,
        );
        $protectionService = new PdfProtectionService(new NativePdfProtectionEngine);

        return SignerBuilder::new($signingService, $protectionService);
    }

    public static function protection(): PdfProtectionBuilder
    {
        $service = new PdfProtectionService(new NativePdfProtectionEngine);

        return PdfProtectionBuilder::new($service);
    }

    public static function validation(): PdfSignatureValidatorBuilder
    {
        $service = new PdfSignatureValidationService(new NativePdfSignatureValidationEngine);

        return PdfSignatureValidatorBuilder::new($service);
    }

    public static function timestamp(): TimestampBuilder
    {
        return TimestampBuilder::new(new TimestampService);
    }
}
