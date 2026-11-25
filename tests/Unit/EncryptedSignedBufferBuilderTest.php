<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Tests\Unit;

use PHPUnit\Framework\TestCase;
use SignerPHP\PdfCore\Buffer;
use SignerPHP\PdfCore\PdfDocument;
use SignerPHP\PdfCore\SignatureObject;
use SignerPHP\PdfSigner\Application\Contract\SignatureProviderInterface;
use SignerPHP\PdfSigner\Application\DTO\CertificateCredentialsDto;
use SignerPHP\PdfSigner\Application\DTO\LocalSigningContextDto;
use SignerPHP\PdfSigner\Application\DTO\PdfContentDto;
use SignerPHP\PdfSigner\Application\DTO\ProtectionOptionsDto;
use SignerPHP\PdfSigner\Application\DTO\SignatureProfile;
use SignerPHP\PdfSigner\Application\DTO\SignatureValue;
use SignerPHP\PdfSigner\Application\DTO\SigningCertificateDto;
use SignerPHP\PdfSigner\Application\DTO\SigningContextDto;
use SignerPHP\PdfSigner\Application\DTO\SigningOptionsDto;
use SignerPHP\PdfSigner\Application\DTO\SigningPayload;
use SignerPHP\PdfSigner\Application\DTO\TimestampOptionsDto;
use SignerPHP\PdfSigner\Domain\Exception\SignProcessException;
use SignerPHP\PdfSigner\Domain\ValueObject\VerifiedCertificate;
use SignerPHP\PdfSigner\Infrastructure\Native\Contract\DocumentTimestampApplierInterface;
use SignerPHP\PdfSigner\Infrastructure\Native\Contract\LongTermValidationApplierInterface;
use SignerPHP\PdfSigner\Infrastructure\Native\Contract\ProfileAwarePkcs7SignerInterface;
use SignerPHP\PdfSigner\Infrastructure\Native\Contract\SignedBufferBuilderInterface;
use SignerPHP\PdfSigner\Infrastructure\Native\Contract\SignerCertificateRevocationCheckerInterface;
use SignerPHP\PdfSigner\Infrastructure\Native\Contract\TimestampTokenProviderInterface;
use SignerPHP\PdfSigner\Infrastructure\Native\NativePdfSigningEngine;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\DocumentTimestampApplier;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\Encryption\EncryptedPdfDocument;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\PdfDocumentPreparer;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\SignatureHandler;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\SignedBufferBuilder;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\XrefContentResolver;
use SignerPHP\PdfSigner\Presentation\Signer;
use SignerPHP\PdfSigner\Tests\Support\PdfFixtureFactory;

final class EncryptedSignedBufferBuilderTest extends TestCase
{
    public function test_lta_appends_signature_timestamp_dss_and_archive_timestamp_encrypted(): void
    {
        $calls = new \ArrayObject;
        $document = self::encrypted();
        $builder = new SignedBufferBuilder(
            new XrefContentResolver,
            self::signer($calls),
            new DocumentTimestampApplier(timestampTokenProvider: self::tokenProvider($calls)),
            new class($calls) implements LongTermValidationApplierInterface
            {
                public function __construct(private \ArrayObject $calls) {}

                public function apply(string $signedPdfContent): string
                {
                    $this->calls[] = 'ltv';

                    return $signedPdfContent;
                }
            },
            self::revocationChecker($calls),
        );

        $result = (string) $builder->buildEncrypted(
            $document,
            (new PdfDocumentPreparer)->prepare($document->plainMirror()),
            self::handler(true),
            self::context(SignatureProfile::PadesBaselineLTA, new TimestampOptionsDto('https://tsa.example')),
            self::provider(),
        );

        self::assertSame(['revocation', 'cms', 'tsa', 'ltv', 'tsa'], $calls->getArrayCopy());
        self::assertStringStartsWith($document->content(), $result);
        self::assertSame(3, preg_match_all('/\/ByteRange \[0 \d+ \d+ \d+ *\]/', $result), 'signature plus two document timestamps');
        self::assertStringContainsString('<CAFE', $result);
        self::assertNotNull(EncryptedPdfDocument::open($result));
    }

    public function test_returns_the_document_unchanged_without_a_certificate(): void
    {
        $document = self::encrypted();
        $builder = new SignedBufferBuilder(new XrefContentResolver, self::signer(new \ArrayObject));

        $result = $builder->buildEncrypted($document, (new PdfDocumentPreparer)->prepare($document->plainMirror()), self::handler(false), self::context(SignatureProfile::PadesBaselineB, null), self::provider());

        self::assertSame($document->content(), (string) $result);
    }

    public function test_refuses_to_timestamp_with_an_applier_that_ignores_encryption(): void
    {
        $document = self::encrypted();
        $builder = new SignedBufferBuilder(new XrefContentResolver, self::signer(new \ArrayObject), new class implements DocumentTimestampApplierInterface
        {
            public function apply(string $signedPdfContent, TimestampOptionsDto $options): string
            {
                return $signedPdfContent;
            }
        });

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('requires an encryption-aware document timestamp applier');

        $builder->buildEncrypted($document, (new PdfDocumentPreparer)->prepare($document->plainMirror()), self::handler(true), self::context(SignatureProfile::PadesBaselineT, new TimestampOptionsDto('https://tsa.example')), self::provider());
    }

    public function test_engine_refuses_encrypted_input_with_a_builder_that_ignores_encryption(): void
    {
        $builder = new class implements SignedBufferBuilderInterface
        {
            public function build(PdfDocument $pdfDocument, SignatureHandler $signatureHandler, SigningContextDto $context, SignatureProviderInterface $signatureProvider): Buffer
            {
                return new Buffer('unused');
            }
        };
        $engine = new NativePdfSigningEngine(signedBufferBuilder: $builder);

        $this->expectException(SignProcessException::class);
        $this->expectExceptionMessage('requires an encryption-aware signed buffer builder');

        $engine->sign(new LocalSigningContextDto(
            self::context(SignatureProfile::PadesBaselineB, null, self::encrypted()->content()),
            new VerifiedCertificate(new CertificateCredentialsDto('/tmp/cert.pfx', 'x'), [], ['cert' => '', 'pkey' => '', 'extracerts' => '']),
        ));
    }

    private static function encrypted(): EncryptedPdfDocument
    {
        return EncryptedPdfDocument::open(Signer::protection()
            ->withPdfContent(PdfFixtureFactory::minimalPdf())
            ->withProtection(ProtectionOptionsDto::preventCopy(ownerPassword: 'owner'))
            ->protect()) ?? throw new \LogicException('not encrypted');
    }

    private static function handler(bool $hasCertificate): SignatureHandler
    {
        return new class($hasCertificate) extends SignatureHandler
        {
            public function __construct(private readonly bool $certificate) {}

            public function hasCertificate(): bool
            {
                return $this->certificate;
            }

            public function generateSignatureInDocument(): SignatureObject
            {
                return new SignatureObject(42);
            }
        };
    }

    private static function signer(\ArrayObject $calls): ProfileAwarePkcs7SignerInterface
    {
        return new class($calls) implements ProfileAwarePkcs7SignerInterface
        {
            public function __construct(private \ArrayObject $calls) {}

            public function sign(Buffer $signableDocument, SignatureProviderInterface $signatureProvider, string $certificatePem): string
            {
                return 'CAFE';
            }

            public function signWithProfile(Buffer $signableDocument, SignatureProviderInterface $signatureProvider, string $certificatePem, SignatureProfile $profile): string
            {
                $this->calls[] = 'cms';

                return str_pad('CAFE', SignatureObject::SIGNATURE_MAX_LENGTH, '0');
            }
        };
    }

    private static function tokenProvider(\ArrayObject $calls): TimestampTokenProviderInterface
    {
        return new class($calls) implements TimestampTokenProviderInterface
        {
            public function __construct(private \ArrayObject $calls) {}

            public function requestTokenHex(string $signedContent, array $byteRange, TimestampOptionsDto $options): string
            {
                $this->calls[] = 'tsa';

                return 'BEEF';
            }
        };
    }

    private static function revocationChecker(\ArrayObject $calls): SignerCertificateRevocationCheckerInterface
    {
        return new class($calls) implements SignerCertificateRevocationCheckerInterface
        {
            public function __construct(private \ArrayObject $calls) {}

            public function assertNotRevoked(string $certificatePem, array $chainPem): void
            {
                $this->calls[] = 'revocation';
            }
        };
    }

    private static function provider(): SignatureProviderInterface
    {
        return new class implements SignatureProviderInterface
        {
            public function sign(SigningPayload $payload): SignatureValue
            {
                return new SignatureValue('AB');
            }
        };
    }

    private static function context(SignatureProfile $profile, ?TimestampOptionsDto $timestamp, string $pdf = '%PDF'): SigningContextDto
    {
        return new SigningContextDto(
            pdf: new PdfContentDto($pdf),
            options: new SigningOptionsDto(timestamp: $timestamp, signatureProfile: $profile),
            certificate: new SigningCertificateDto(''),
        );
    }
}
