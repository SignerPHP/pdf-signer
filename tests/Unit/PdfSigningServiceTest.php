<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Tests\Unit;

use PHPUnit\Framework\TestCase;
use SignerPHP\PdfSigner\Application\Contract\CertificateValidatorInterface;
use SignerPHP\PdfSigner\Application\Contract\PdfSigningEngineInterface;
use SignerPHP\PdfSigner\Application\DTO\CertificateCredentialsDto;
use SignerPHP\PdfSigner\Application\DTO\PdfContentDto;
use SignerPHP\PdfSigner\Application\DTO\SigningContextDto;
use SignerPHP\PdfSigner\Application\DTO\SigningOptionsDto;
use SignerPHP\PdfSigner\Application\DTO\SignPdfRequestDto;
use SignerPHP\PdfSigner\Application\Service\PdfSigningService;
use SignerPHP\PdfSigner\Domain\ValueObject\VerifiedCertificate;

final class PdfSigningServiceTest extends TestCase
{
    public function test_service_validates_certificate_and_signs(): void
    {
        $validator = new class implements CertificateValidatorInterface
        {
            public ?CertificateCredentialsDto $received = null;

            public function validate(CertificateCredentialsDto $credentials): VerifiedCertificate
            {
                $this->received = $credentials;

                return new VerifiedCertificate($credentials, ['validTo_time_t' => PHP_INT_MAX], ['cert' => '', 'pkey' => '', 'extracerts' => '']);
            }
        };

        $engine = new class implements PdfSigningEngineInterface
        {
            public ?SigningContextDto $context = null;

            public function sign(SigningContextDto $context): string
            {
                $this->context = $context;

                return 'signed-content';
            }
        };

        $service = new PdfSigningService($validator, $engine);

        $request = new SignPdfRequestDto(
            new PdfContentDto('pdf-content'),
            new CertificateCredentialsDto('/tmp/cert.pfx', 'secret'),
            SigningOptionsDto::empty(),
        );

        $result = $service->sign($request);

        self::assertSame('signed-content', $result);
        self::assertSame('/tmp/cert.pfx', $validator->received?->certificatePath);
        self::assertSame('pdf-content', $engine->context?->request->pdf->content);
    }
}
