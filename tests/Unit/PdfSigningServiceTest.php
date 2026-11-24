<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Tests\Unit;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SignerPHP\PdfSigner\Application\Contract\CertificateValidatorInterface;
use SignerPHP\PdfSigner\Application\Contract\PdfSigningEngineInterface;
use SignerPHP\PdfSigner\Application\DTO\CertificateCredentialsDto;
use SignerPHP\PdfSigner\Application\DTO\LocalSigningContextDto;
use SignerPHP\PdfSigner\Application\DTO\PdfContentDto;
use SignerPHP\PdfSigner\Application\DTO\SigningOptionsDto;
use SignerPHP\PdfSigner\Application\DTO\SignPdfRequestDto;
use SignerPHP\PdfSigner\Application\Service\PdfSigningService;
use SignerPHP\PdfSigner\Domain\ValueObject\VerifiedCertificate;

final class PdfSigningServiceTest extends TestCase
{
    #[DataProvider('certificateChains')]
    public function test_service_validates_certificate_and_signs(mixed $chain, array $expectedChain): void
    {
        $validator = new class($chain) implements CertificateValidatorInterface
        {
            public ?CertificateCredentialsDto $received = null;

            public function __construct(private readonly mixed $chain) {}

            public function validate(CertificateCredentialsDto $credentials): VerifiedCertificate
            {
                $this->received = $credentials;

                return new VerifiedCertificate($credentials, ['validTo_time_t' => PHP_INT_MAX], ['cert' => '', 'pkey' => '', 'extracerts' => $this->chain]);
            }
        };

        $engine = new class implements PdfSigningEngineInterface
        {
            public ?LocalSigningContextDto $context = null;

            public function sign(LocalSigningContextDto $context): string
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
        self::assertSame('pdf-content', $engine->context?->signingContext->pdf->content);
        self::assertSame($expectedChain, $engine->context?->signingContext->certificate->chainPem);
    }

    public static function certificateChains(): array
    {
        return [
            'single certificate' => ['chain certificate', ['chain certificate']],
            'list of certificates' => [['first certificate', 'second certificate'], ['first certificate', 'second certificate']],
            'sparse array' => [[2 => 'first certificate', 5 => null, 7 => 'second certificate'], ['first certificate', 'second certificate']],
            'invalid type' => [false, []],
        ];
    }
}
