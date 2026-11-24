<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Tests\Unit;

use PHPUnit\Framework\TestCase;
use SignerPHP\PdfCore\Buffer;
use SignerPHP\PdfCore\PdfDocument;
use SignerPHP\PdfCore\SignatureObject;
use SignerPHP\PdfSigner\Application\Contract\SignatureProviderInterface;
use SignerPHP\PdfSigner\Application\DTO\IcpBrasilPadesPolicy;
use SignerPHP\PdfSigner\Application\DTO\PdfContentDto;
use SignerPHP\PdfSigner\Application\DTO\SignaturePolicyIdentifierDto;
use SignerPHP\PdfSigner\Application\DTO\SignatureProfile;
use SignerPHP\PdfSigner\Application\DTO\SignatureValue;
use SignerPHP\PdfSigner\Application\DTO\SigningContextDto;
use SignerPHP\PdfSigner\Application\DTO\SigningOptionsDto;
use SignerPHP\PdfSigner\Application\DTO\SigningPayload;
use SignerPHP\PdfSigner\Application\DTO\TimestampOptionsDto;
use SignerPHP\PdfSigner\Infrastructure\Native\Contract\DocumentTimestampApplierInterface;
use SignerPHP\PdfSigner\Infrastructure\Native\Contract\LongTermValidationApplierInterface;
use SignerPHP\PdfSigner\Infrastructure\Native\Contract\Pkcs7SignerInterface;
use SignerPHP\PdfSigner\Infrastructure\Native\Contract\PolicyAwarePkcs7SignerInterface;
use SignerPHP\PdfSigner\Infrastructure\Native\Contract\ProfileAwarePkcs7SignerInterface;
use SignerPHP\PdfSigner\Infrastructure\Native\Contract\XrefContentResolverInterface;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\SignatureHandler;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\SignedBufferBuilder;

final class SignedBufferBuilderTest extends TestCase
{
    public function test_build_returns_original_buffer_when_signature_has_no_certificate(): void
    {
        $pdf = new PdfDocument;
        $pdf->setBufferFromString('%PDF-no-cert');

        $signature = SignatureHandler::new();
        $builder = new SignedBufferBuilder(
            new class implements XrefContentResolverInterface
            {
                public function resolve(PdfDocument $pdfDocument, array $objectOffsets, int $xrefOffset): Buffer
                {
                    return new Buffer('XREF');
                }
            },
            new class implements Pkcs7SignerInterface
            {
                public function sign(Buffer $signableDocument, SignatureProviderInterface $signatureProvider, string $certificatePem): string
                {
                    return 'AB';
                }
            },
        );

        $result = $builder->build($pdf, $signature, $this->makeContext(SignatureProfile::PdfBasic, null), $this->makeProvider());

        self::assertSame('%PDF-no-cert', $result->raw());
    }

    public function test_build_applies_timestamp_then_ltv_for_pades_lt(): void
    {
        $pdf = $this->makePdfDocumentForSigning();
        $signature = $this->makeSignatureHandlerWithCertificate();

        $calls = new class
        {
            public int $timestampCalls = 0;

            public int $ltvCalls = 0;
        };

        $builder = new SignedBufferBuilder(
            new class implements XrefContentResolverInterface
            {
                public function resolve(PdfDocument $pdfDocument, array $objectOffsets, int $xrefOffset): Buffer
                {
                    return new Buffer('XREF');
                }
            },
            new class implements ProfileAwarePkcs7SignerInterface
            {
                public function sign(Buffer $signableDocument, SignatureProviderInterface $signatureProvider, string $certificatePem): string
                {
                    return 'ABCD';
                }

                public function signWithProfile(Buffer $signableDocument, SignatureProviderInterface $signatureProvider, string $certificatePem, SignatureProfile $profile): string
                {
                    return $this->sign($signableDocument, $signatureProvider, $certificatePem);
                }
            },
            new class($calls) implements DocumentTimestampApplierInterface
            {
                public function __construct(private object $calls) {}

                public function apply(string $signedPdfContent, TimestampOptionsDto $options): string
                {
                    $this->calls->timestampCalls++;

                    return $signedPdfContent.'|T';
                }
            },
            new class($calls) implements LongTermValidationApplierInterface
            {
                public function __construct(private object $calls) {}

                public function apply(string $signedPdfContent): string
                {
                    $this->calls->ltvCalls++;

                    return $signedPdfContent.'|LT';
                }
            },
        );

        $result = $builder->build($pdf, $signature, $this->makeContext(SignatureProfile::PadesBaselineLT, new TimestampOptionsDto('https://tsa.example')), $this->makeProvider());

        self::assertSame(1, $calls->timestampCalls);
        self::assertSame(1, $calls->ltvCalls);
        self::assertStringContainsString('|T|LT', $result->raw());
    }

    public function test_build_applies_second_timestamp_for_pades_lta(): void
    {
        $pdf = $this->makePdfDocumentForSigning();
        $signature = $this->makeSignatureHandlerWithCertificate();

        $calls = new class
        {
            public int $timestampCalls = 0;

            public int $ltvCalls = 0;
        };

        $builder = new SignedBufferBuilder(
            new class implements XrefContentResolverInterface
            {
                public function resolve(PdfDocument $pdfDocument, array $objectOffsets, int $xrefOffset): Buffer
                {
                    return new Buffer('XREF');
                }
            },
            new class implements ProfileAwarePkcs7SignerInterface
            {
                public function sign(Buffer $signableDocument, SignatureProviderInterface $signatureProvider, string $certificatePem): string
                {
                    return 'ABCD';
                }

                public function signWithProfile(Buffer $signableDocument, SignatureProviderInterface $signatureProvider, string $certificatePem, SignatureProfile $profile): string
                {
                    return $this->sign($signableDocument, $signatureProvider, $certificatePem);
                }
            },
            new class($calls) implements DocumentTimestampApplierInterface
            {
                public function __construct(private object $calls) {}

                public function apply(string $signedPdfContent, TimestampOptionsDto $options): string
                {
                    $this->calls->timestampCalls++;

                    return $signedPdfContent.'|T';
                }
            },
            new class($calls) implements LongTermValidationApplierInterface
            {
                public function __construct(private object $calls) {}

                public function apply(string $signedPdfContent): string
                {
                    $this->calls->ltvCalls++;

                    return $signedPdfContent.'|LT';
                }
            },
        );

        $result = $builder->build($pdf, $signature, $this->makeContext(SignatureProfile::PadesBaselineLTA, new TimestampOptionsDto('https://tsa.example')), $this->makeProvider());

        self::assertSame(2, $calls->timestampCalls);
        self::assertSame(1, $calls->ltvCalls);
        self::assertStringContainsString('|T|LT|T', $result->raw());
    }

    public function test_basic_signing_preserves_legacy_pkcs7_signer_integration(): void
    {
        $builder = new SignedBufferBuilder(
            new class implements XrefContentResolverInterface
            {
                public function resolve(PdfDocument $pdfDocument, array $objectOffsets, int $xrefOffset): Buffer
                {
                    return new Buffer('XREF');
                }
            },
            new class implements Pkcs7SignerInterface
            {
                public function sign(Buffer $signableDocument, SignatureProviderInterface $signatureProvider, string $certificatePem): string
                {
                    return 'ABCD';
                }
            },
        );

        $result = $builder->build(
            $this->makePdfDocumentForSigning(),
            $this->makeSignatureHandlerWithCertificate(),
            $this->makeContext(SignatureProfile::PdfBasic, null),
            $this->makeProvider(),
        );

        self::assertStringContainsString('XREF', $result->raw());
    }

    public function test_pades_does_not_silently_use_a_profile_unaware_signer(): void
    {
        $builder = new SignedBufferBuilder(
            new class implements XrefContentResolverInterface
            {
                public function resolve(PdfDocument $pdfDocument, array $objectOffsets, int $xrefOffset): Buffer
                {
                    return new Buffer('XREF');
                }
            },
            new class implements Pkcs7SignerInterface
            {
                public function sign(Buffer $signableDocument, SignatureProviderInterface $signatureProvider, string $certificatePem): string
                {
                    return 'ABCD';
                }
            },
        );

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('PAdES signing requires a profile-aware CMS signer.');

        $builder->build(
            $this->makePdfDocumentForSigning(),
            $this->makeSignatureHandlerWithCertificate(),
            $this->makeContext(SignatureProfile::PadesBaselineB, null),
            $this->makeProvider(),
        );
    }

    private function makePdfDocumentForSigning(): PdfDocument
    {
        $pdf = new class extends PdfDocument
        {
            public function updateModifyDate(?\DateTime $date = null): bool
            {
                return true;
            }
        };
        $pdf->setBufferFromString('%PDF-base');

        return $pdf;
    }

    private function makeSignatureHandlerWithCertificate(): SignatureHandler
    {
        return new class extends SignatureHandler
        {
            public function hasCertificate(): bool
            {
                return true;
            }

            public function generateSignatureInDocument(): SignatureObject
            {
                return new SignatureObject(42);
            }
        };
    }

    public function test_build_passes_the_signature_policy_to_a_policy_aware_signer(): void
    {
        $captured = new class
        {
            public ?SignaturePolicyIdentifierDto $policy = null;

            public ?TimestampOptionsDto $signatureTimestamp = null;
        };

        $builder = new SignedBufferBuilder(
            $this->xrefResolver(),
            new class($captured) implements PolicyAwarePkcs7SignerInterface
            {
                public function __construct(private object $captured) {}

                public function sign(Buffer $signableDocument, SignatureProviderInterface $signatureProvider, string $certificatePem): string
                {
                    return 'ABCD';
                }

                public function signWithProfile(Buffer $signableDocument, SignatureProviderInterface $signatureProvider, string $certificatePem, SignatureProfile $profile): string
                {
                    return 'ABCD';
                }

                public function signWithPolicy(Buffer $signableDocument, SignatureProviderInterface $signatureProvider, string $certificatePem, SignatureProfile $profile, SignaturePolicyIdentifierDto $signaturePolicy, ?TimestampOptionsDto $signatureTimestamp = null): string
                {
                    $this->captured->policy = $signaturePolicy;
                    $this->captured->signatureTimestamp = $signatureTimestamp;

                    return 'ABCD';
                }
            },
            new class implements DocumentTimestampApplierInterface
            {
                public function apply(string $signedPdfContent, TimestampOptionsDto $options): string
                {
                    return $signedPdfContent;
                }
            },
        );

        $policy = IcpBrasilPadesPolicy::AdRtV1_3->toIdentifier();
        $tsa = new TimestampOptionsDto('https://tsa.example');
        $builder->build($this->makePdfDocumentForSigning(), $this->makeSignatureHandlerWithCertificate(), $this->makeContext(SignatureProfile::PadesBaselineB, $tsa, $policy), $this->makeProvider());

        self::assertSame($policy, $captured->policy);
        self::assertSame($tsa, $captured->signatureTimestamp, 'the TSA options reach the CMS signer for the signature timestamp');
    }

    public function test_build_rejects_a_signature_policy_without_a_policy_aware_signer(): void
    {
        $builder = new SignedBufferBuilder(
            $this->xrefResolver(),
            new class implements ProfileAwarePkcs7SignerInterface
            {
                public function sign(Buffer $signableDocument, SignatureProviderInterface $signatureProvider, string $certificatePem): string
                {
                    return 'ABCD';
                }

                public function signWithProfile(Buffer $signableDocument, SignatureProviderInterface $signatureProvider, string $certificatePem, SignatureProfile $profile): string
                {
                    return 'ABCD';
                }
            },
        );

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('policy-aware CMS signer');

        $builder->build(
            $this->makePdfDocumentForSigning(),
            $this->makeSignatureHandlerWithCertificate(),
            $this->makeContext(SignatureProfile::PadesBaselineB, null, IcpBrasilPadesPolicy::AdRbV1_3->toIdentifier()),
            $this->makeProvider(),
        );
    }

    private function xrefResolver(): XrefContentResolverInterface
    {
        return new class implements XrefContentResolverInterface
        {
            public function resolve(PdfDocument $pdfDocument, array $objectOffsets, int $xrefOffset): Buffer
            {
                return new Buffer('XREF');
            }
        };
    }

    private function makeContext(SignatureProfile $profile, ?TimestampOptionsDto $timestamp, ?SignaturePolicyIdentifierDto $signaturePolicy = null): SigningContextDto
    {
        return new SigningContextDto(
            pdf: new PdfContentDto('%PDF'),
            options: new SigningOptionsDto(
                timestamp: $timestamp,
                signatureProfile: $profile,
                signaturePolicy: $signaturePolicy,
            ),
            certificate: new \SignerPHP\PdfSigner\Application\DTO\SigningCertificateDto(''),
        );
    }

    private function makeProvider(): SignatureProviderInterface
    {
        return new class implements SignatureProviderInterface
        {
            public function sign(SigningPayload $payload): SignatureValue
            {
                return new SignatureValue('AB');
            }
        };
    }
}
