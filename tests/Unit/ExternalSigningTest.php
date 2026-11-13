<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Tests\Unit;

use InvalidArgumentException;
use PHPUnit\Framework\TestCase;
use SignerPHP\PdfSigner\Application\DTO\CertificationLevel;
use SignerPHP\PdfSigner\Application\DTO\ExternalSigningPayload;
use SignerPHP\PdfSigner\Application\DTO\SignatureAlgorithm;
use SignerPHP\PdfSigner\Application\DTO\SignatureAppearanceDto;
use SignerPHP\PdfSigner\Application\DTO\SignatureEncoding;
use SignerPHP\PdfSigner\Application\DTO\SignatureMetadataDto;
use SignerPHP\PdfSigner\Application\DTO\SigningInputType;
use SignerPHP\PdfSigner\Domain\Exception\SignerException;
use SignerPHP\PdfSigner\Domain\Exception\SignProcessException;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\Cms\X509Certificate;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\OpenSslCmsCertificateCollector;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\PdfSignatureExtractor;
use SignerPHP\PdfSigner\Presentation\ExternalSignerBuilder;
use SignerPHP\PdfSigner\Presentation\Signer;
use SignerPHP\PdfSigner\Tests\Support\PdfFixtureFactory;
use SignerPHP\PdfSigner\Tests\Support\Pkcs12Fixture;

final class ExternalSigningTest extends TestCase
{
    public function test_exposes_the_external_signer_through_the_public_facade(): void
    {
        expect(Signer::externalSigner())->toBeInstanceOf(ExternalSignerBuilder::class);
    }

    public function test_prepares_serializable_state_and_completes_a_valid_external_signature(): void
    {
        $bundle = Pkcs12Fixture::load();
        $builder = Signer::externalSigner()
            ->withPdfContent(PdfFixtureFactory::minimalPdf())
            ->withCertificate($bundle['cert'])
            ->withoutDefaultAppearance()
            ->withPadesBaselineB();

        $prepared = $builder->prepare();
        $state = serialize($prepared);
        $restored = unserialize($state, ['allowed_classes' => true]);

        expect($restored->payload->inputType)->toBe(SigningInputType::Digest)
            ->and($restored->payload->signatureAlgorithm)->toBe(SignatureAlgorithm::RsaPkcs1V15)
            ->and($restored->payload->signatureEncoding)->toBe(SignatureEncoding::RsaPkcs1);

        $signed = '';
        $signed = self::signRsaDigest($restored->payload->input(), $bundle['pkey'], 'sha256');

        $pdf = Signer::externalSigner()->complete($restored->state, $signed);
        $validation = Signer::validation()
            ->withPdfContent($pdf)
            ->disableTrustChainValidation()
            ->validate();

        expect($pdf)->toStartWith('%PDF-')
            ->and($pdf)->toContain('/ETSI.CAdES.detached')
            ->and($pdf)->toContain('/ByteRange')
            ->and($pdf)->toMatch('/\/M\s*\(/')
            ->and($validation->hasSignatures)->toBeTrue()
            ->and($validation->allValid)->toBeTrue();
    }

    public function test_keeps_an_existing_signature_valid_when_appending_another_one(): void
    {
        $bundle = Pkcs12Fixture::load();
        $sign = function (string $pdf) use ($bundle): string {
            $builder = Signer::externalSigner()
                ->withPdfContent($pdf)
                ->withCertificate($bundle['cert'])
                ->withoutDefaultAppearance();
            $prepared = $builder->prepare();
            $signature = self::signRsaDigest($prepared->payload->input(), $bundle['pkey'], 'sha256');

            return $builder->complete($prepared->state, $signature);
        };

        $twiceSigned = $sign($sign(PdfFixtureFactory::minimalPdf()));
        $validation = Signer::validation()
            ->withPdfContent($twiceSigned)
            ->disableTrustChainValidation()
            ->validate();

        expect($validation->entries)->toHaveCount(2)
            ->and($validation->allValid)->toBeTrue();
    }

    public function test_preserves_the_certificate_chain_through_preparation_and_completion(): void
    {
        $signer = Pkcs12Fixture::load();
        $chainCertificate = self::externalSigningChainCertificate();
        $builder = Signer::externalSigner()
            ->withPdfContent(PdfFixtureFactory::minimalPdf())
            ->withCertificate($signer['cert'], [$chainCertificate])
            ->withoutDefaultAppearance();
        $prepared = $builder->prepare();
        $state = json_decode($prepared->state, true, flags: JSON_THROW_ON_ERROR);
        $signature = self::signRsaDigest($prepared->payload->input(), $signer['pkey'], 'sha256');
        $signedPdf = $builder->complete($prepared->state, $signature);
        $extractedSignatures = (new PdfSignatureExtractor)->extract($signedPdf);
        $certificates = (new OpenSslCmsCertificateCollector)->collectDerCertificates($extractedSignatures[0]->signatureHex);

        expect($state['certificateChain'])->toBe([base64_encode($chainCertificate)])
            ->and($extractedSignatures)->toHaveCount(1)
            ->and($certificates)->toHaveCount(2)
            ->toContain(X509Certificate::fromPem($signer['cert'])->der)
            ->toContain(X509Certificate::fromPem($chainCertificate)->der);
    }

    public function test_rejects_modified_prepared_state(): void
    {
        $bundle = Pkcs12Fixture::load();
        $prepared = Signer::externalSigner()
            ->withPdfContent(PdfFixtureFactory::minimalPdf())
            ->withCertificate($bundle['cert'])
            ->withoutDefaultAppearance()
            ->prepare();

        $payload = json_decode($prepared->state, true, flags: JSON_THROW_ON_ERROR);
        $payload['digestAlgorithm'] = 'sha512';
        $modified = json_encode($payload, JSON_THROW_ON_ERROR);

        expect(fn () => Signer::externalSigner()->complete($modified, 'signature'))
            ->toThrow(\SignerPHP\PdfSigner\Domain\Exception\SignProcessException::class, 'checksum');
    }

    public function test_validates_required_builder_inputs_and_certificate_material(): void
    {
        expect(fn () => Signer::externalSigner()->prepare())
            ->toThrow(SignerException::class, 'PDF content')
            ->and(fn () => Signer::externalSigner()->withPdfContent('pdf')->prepare())
            ->toThrow(SignerException::class, 'Signing certificate')
            ->and(fn () => Signer::externalSigner()->withCertificate('invalid'))
            ->toThrow(SignerException::class, 'valid PEM');
    }

    public function test_accepts_external_signature_configuration_and_base64_completion(): void
    {
        $bundle = Pkcs12Fixture::load();
        $builder = Signer::externalSigner()
            ->withPdfContent(PdfFixtureFactory::minimalPdf())
            ->withCertificate($bundle['cert'])
            ->withMetadata(new SignatureMetadataDto(reason: 'Approval'))
            ->withAppearance(new SignatureAppearanceDto(null, [10, 10, 100, 50], 0))
            ->withCertificationLevel(CertificationLevel::FormFillAndSignatures)
            ->withHashAlgorithm('sha384');
        $prepared = $builder->prepare();
        $signature = self::signRsaDigest($prepared->payload->input(), $bundle['pkey'], 'sha384');

        expect($builder->completeBase64($prepared->state, base64_encode($signature)))->toStartWith('%PDF-')
            ->and(fn () => $builder->completeBase64($prepared->state, '***'))
            ->toThrow(SignerException::class, 'valid non-empty base64')
            ->and(fn () => $builder->withCertificationLevel(99))
            ->toThrow(SignerException::class, 'one of');
    }

    private static function signRsaDigest(string $digest, string $privateKeyPem, string $algorithm): string
    {
        $digestInfoPrefix = match ($algorithm) {
            'sha256' => hex2bin('3031300d060960864801650304020105000420'),
            'sha384' => hex2bin('3041300d060960864801650304020205000430'),
            default => false,
        };
        if (! is_string($digestInfoPrefix)) {
            throw new InvalidArgumentException('Unsupported test digest algorithm.');
        }

        $signature = '';
        expect(openssl_private_encrypt($digestInfoPrefix.$digest, $signature, $privateKeyPem, OPENSSL_PKCS1_PADDING))->toBeTrue();

        return $signature;
    }

    private static function externalSigningChainCertificate(): string
    {
        $key = openssl_pkey_new([
            'private_key_bits' => 2048,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ]);
        expect($key)->not->toBeFalse();

        $csr = openssl_csr_new(['CN' => 'external-signing-chain-test'], $key, ['digest_alg' => 'sha256']);
        expect($csr)->not->toBeFalse();

        $certificate = openssl_csr_sign($csr, null, $key, 1, ['digest_alg' => 'sha256']);
        expect($certificate)->not->toBeFalse();
        expect(openssl_x509_export($certificate, $certificatePem))->toBeTrue();

        return (string) $certificatePem;
    }

    public function test_rejects_invalid_payload_and_prepared_state_shapes(): void
    {
        $payload = new ExternalSigningPayload(
            '***',
            SigningInputType::Data,
            \SignerPHP\PdfSigner\Application\DTO\HashAlgorithm::Sha256,
            SignatureAlgorithm::RsaPkcs1V15,
            SignatureEncoding::RsaPkcs1,
        );

        expect(fn () => $payload->input())->toThrow(\InvalidArgumentException::class)
            ->and(fn () => Signer::externalSigner()->complete('invalid', 'signature'))
            ->toThrow(SignProcessException::class, 'Invalid or unsupported');
    }

    public function test_rejects_corrupted_state_fields_and_missing_byte_ranges(): void
    {
        $bundle = Pkcs12Fixture::load();
        $prepared = Signer::externalSigner()
            ->withPdfContent(PdfFixtureFactory::minimalPdf())
            ->withCertificate($bundle['cert'])
            ->withoutDefaultAppearance()
            ->prepare();

        $rewriteState = function (callable $mutate) use ($prepared): string {
            $payload = json_decode($prepared->state, true, flags: JSON_THROW_ON_ERROR);
            unset($payload['checksum']);
            $payload = $mutate($payload);
            $payload['checksum'] = hash('sha256', json_encode($payload, JSON_THROW_ON_ERROR));

            return json_encode($payload, JSON_THROW_ON_ERROR);
        };

        $incomplete = $rewriteState(function (array $payload): array {
            $payload['certificate'] = '';

            return $payload;
        });
        $withoutByteRange = $rewriteState(function (array $payload): array {
            $pdf = (string) base64_decode($payload['unsignedPdf'], true);
            $payload['unsignedPdf'] = base64_encode(str_replace('/ByteRange', '/NoByteRange', $pdf));

            return $payload;
        });

        expect(fn () => Signer::externalSigner()->complete($incomplete, 'signature'))
            ->toThrow(SignProcessException::class, 'incomplete or corrupted')
            ->and(fn () => Signer::externalSigner()->complete($withoutByteRange, 'signature'))
            ->toThrow(SignProcessException::class, 'ByteRange');
    }
}
