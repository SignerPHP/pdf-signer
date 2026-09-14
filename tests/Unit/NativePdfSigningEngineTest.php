<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Tests\Unit;

use PHPUnit\Framework\TestCase;
use RuntimeException;
use SignerPHP\PdfCore\Buffer;
use SignerPHP\PdfCore\PdfDocument;
use SignerPHP\PdfSigner\Application\Contract\SignatureProviderFactoryInterface;
use SignerPHP\PdfSigner\Application\Contract\SignatureProviderInterface;
use SignerPHP\PdfSigner\Application\DTO\CertificateCredentialsDto;
use SignerPHP\PdfSigner\Application\DTO\PdfContentDto;
use SignerPHP\PdfSigner\Application\DTO\SignatureValue;
use SignerPHP\PdfSigner\Application\DTO\SigningContextDto;
use SignerPHP\PdfSigner\Application\DTO\SigningOptionsDto;
use SignerPHP\PdfSigner\Application\DTO\SigningPayload;
use SignerPHP\PdfSigner\Application\DTO\SignPdfRequestDto;
use SignerPHP\PdfSigner\Domain\Exception\SignProcessException;
use SignerPHP\PdfSigner\Domain\ValueObject\VerifiedCertificate;
use SignerPHP\PdfSigner\Infrastructure\Native\Contract\PdfDocumentPreparerInterface;
use SignerPHP\PdfSigner\Infrastructure\Native\Contract\SignatureFactoryInterface;
use SignerPHP\PdfSigner\Infrastructure\Native\Contract\SignedBufferBuilderInterface;
use SignerPHP\PdfSigner\Infrastructure\Native\NativePdfSigningEngine;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\LocalPrivateKeySignatureProvider;
use SignerPHP\PdfSigner\Infrastructure\PdfCore\Signature;

final class NativePdfSigningEngineTest extends TestCase
{
    public function test_sign_orchestrates_preparer_factory_and_builder(): void
    {
        $preparer = new class implements PdfDocumentPreparerInterface
        {
            public ?string $receivedContent = null;

            public function prepare(string $pdfContent): PdfDocument
            {
                $this->receivedContent = $pdfContent;
                $document = new PdfDocument;
                $document->setBufferFromString($pdfContent);

                return $document;
            }
        };

        $factory = new class implements SignatureFactoryInterface
        {
            public ?PdfDocument $receivedDocument = null;

            public function create(SigningContextDto $context, PdfDocument $pdfDocument): Signature
            {
                $this->receivedDocument = $pdfDocument;

                return Signature::new();
            }
        };

        $builder = new class implements SignedBufferBuilderInterface
        {
            public ?PdfDocument $receivedDocument = null;

            public ?Signature $receivedSignature = null;

            public ?SigningContextDto $receivedContext = null;

            public ?SignatureProviderInterface $receivedProvider = null;

            public function build(
                PdfDocument $pdfDocument,
                Signature $signatureHandler,
                SigningContextDto $context,
                SignatureProviderInterface $signatureProvider,
            ): Buffer {
                $this->receivedDocument = $pdfDocument;
                $this->receivedSignature = $signatureHandler;
                $this->receivedContext = $context;
                $this->receivedProvider = $signatureProvider;

                return new Buffer('signed-content');
            }
        };

        $engine = new NativePdfSigningEngine($preparer, $factory, $builder);
        $result = $engine->sign($this->buildContext('input-pdf'));

        self::assertSame('signed-content', $result);
        self::assertSame('input-pdf', $preparer->receivedContent);
        self::assertSame('input-pdf', $factory->receivedDocument?->getBuffer()->raw());
        self::assertSame($factory->receivedDocument, $builder->receivedDocument);
        self::assertInstanceOf(Signature::class, $builder->receivedSignature);
        self::assertInstanceOf(SigningContextDto::class, $builder->receivedContext);
        self::assertInstanceOf(LocalPrivateKeySignatureProvider::class, $builder->receivedProvider);
    }

    public function test_sign_uses_injected_signature_provider_factory(): void
    {
        $provider = new class implements SignatureProviderInterface
        {
            public function sign(SigningPayload $payload): SignatureValue
            {
                return new SignatureValue('cms');
            }
        };

        $factory = new class($provider) implements SignatureProviderFactoryInterface
        {
            public function __construct(private SignatureProviderInterface $provider) {}

            public function create(VerifiedCertificate $certificate): SignatureProviderInterface
            {
                return $this->provider;
            }
        };

        $builder = new class implements SignedBufferBuilderInterface
        {
            public ?SignatureProviderInterface $receivedProvider = null;

            public function build(
                PdfDocument $pdfDocument,
                Signature $signatureHandler,
                SigningContextDto $context,
                SignatureProviderInterface $signatureProvider,
            ): Buffer {
                $this->receivedProvider = $signatureProvider;

                return new Buffer('signed-content');
            }
        };

        $engine = new NativePdfSigningEngine(
            new class implements PdfDocumentPreparerInterface
            {
                public function prepare(string $pdfContent): PdfDocument
                {
                    $document = new PdfDocument;
                    $document->setBufferFromString($pdfContent);

                    return $document;
                }
            },
            new class implements SignatureFactoryInterface
            {
                public function create(SigningContextDto $context, PdfDocument $pdfDocument): Signature
                {
                    return Signature::new();
                }
            },
            $builder,
            $factory,
        );

        $engine->sign($this->buildContext('input-pdf'));

        self::assertSame($provider, $builder->receivedProvider);
        self::assertNotInstanceOf(LocalPrivateKeySignatureProvider::class, $builder->receivedProvider);
    }

    public function test_sign_wraps_errors_from_native_flow(): void
    {
        $preparer = new class implements PdfDocumentPreparerInterface
        {
            public function prepare(string $pdfContent): PdfDocument
            {
                throw new RuntimeException('boom');
            }
        };

        $engine = new NativePdfSigningEngine(
            $preparer,
            new class implements SignatureFactoryInterface
            {
                public function create(SigningContextDto $context, PdfDocument $pdfDocument): Signature
                {
                    return Signature::new();
                }
            },
            new class implements SignedBufferBuilderInterface
            {
                public function build(
                    PdfDocument $pdfDocument,
                    Signature $signatureHandler,
                    SigningContextDto $context,
                    SignatureProviderInterface $signatureProvider,
                ): Buffer {
                    return new Buffer('never-called');
                }
            }
        );

        $this->expectException(SignProcessException::class);
        $this->expectExceptionMessage('Root cause: boom');
        $engine->sign($this->buildContext('invalid-pdf-content'));
    }

    private function buildContext(string $pdfContent): SigningContextDto
    {
        $request = new SignPdfRequestDto(
            new PdfContentDto($pdfContent),
            new CertificateCredentialsDto('/tmp/not-used.pfx', 'pwd'),
            SigningOptionsDto::empty(),
        );

        return new SigningContextDto(
            $request,
            new VerifiedCertificate($request->certificate, ['validTo_time_t' => PHP_INT_MAX], ['cert' => 'c', 'pkey' => 'p', 'extracerts' => '']),
        );
    }
}
