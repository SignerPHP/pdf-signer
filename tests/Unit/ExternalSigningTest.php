<?php

declare(strict_types=1);

use SignerPHP\PdfSigner\Application\DTO\CertificationLevel;
use SignerPHP\PdfSigner\Application\DTO\ExternalSigningPayload;
use SignerPHP\PdfSigner\Application\DTO\SignatureAlgorithm;
use SignerPHP\PdfSigner\Application\DTO\SignatureAppearanceDto;
use SignerPHP\PdfSigner\Application\DTO\SignatureEncoding;
use SignerPHP\PdfSigner\Application\DTO\SignatureMetadataDto;
use SignerPHP\PdfSigner\Application\DTO\SigningInputType;
use SignerPHP\PdfSigner\Domain\Exception\SignerException;
use SignerPHP\PdfSigner\Domain\Exception\SignProcessException;
use SignerPHP\PdfSigner\Presentation\ExternalSignerBuilder;
use SignerPHP\PdfSigner\Presentation\Signer;
use SignerPHP\PdfSigner\Tests\Support\PdfFixtureFactory;
use SignerPHP\PdfSigner\Tests\Support\Pkcs12Fixture;

it('exposes the external signer through the public facade', function (): void {
    expect(Signer::externalSigner())->toBeInstanceOf(ExternalSignerBuilder::class);
});

it('prepares serializable state and completes a valid external signature', function (): void {
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
    $signed = signRsaDigest($restored->payload->input(), $bundle['pkey'], 'sha256');

    $pdf = Signer::externalSigner()->complete($restored->state, $signed);
    $validation = Signer::validation()
        ->withPdfContent($pdf)
        ->disableTrustChainValidation()
        ->validate();

    expect($pdf)->toStartWith('%PDF-')
        ->and($validation->hasSignatures)->toBeTrue()
        ->and($validation->allValid)->toBeTrue();
});

it('keeps an existing signature valid when appending another one', function (): void {
    $bundle = Pkcs12Fixture::load();
    $sign = function (string $pdf) use ($bundle): string {
        $builder = Signer::externalSigner()
            ->withPdfContent($pdf)
            ->withCertificate($bundle['cert'])
            ->withoutDefaultAppearance();
        $prepared = $builder->prepare();
        $signature = signRsaDigest($prepared->payload->input(), $bundle['pkey'], 'sha256');

        return $builder->complete($prepared->state, $signature);
    };

    $twiceSigned = $sign($sign(PdfFixtureFactory::minimalPdf()));
    $validation = Signer::validation()
        ->withPdfContent($twiceSigned)
        ->disableTrustChainValidation()
        ->validate();

    expect($validation->entries)->toHaveCount(2)
        ->and($validation->allValid)->toBeTrue();
});

it('rejects modified prepared state', function (): void {
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
});

it('validates required builder inputs and certificate material', function (): void {
    expect(fn () => Signer::externalSigner()->prepare())
        ->toThrow(SignerException::class, 'PDF content')
        ->and(fn () => Signer::externalSigner()->withPdfContent('pdf')->prepare())
        ->toThrow(SignerException::class, 'Signing certificate')
        ->and(fn () => Signer::externalSigner()->withCertificate('invalid'))
        ->toThrow(SignerException::class, 'valid PEM');
});

it('accepts external signature configuration and base64 completion', function (): void {
    $bundle = Pkcs12Fixture::load();
    $builder = Signer::externalSigner()
        ->withPdfContent(PdfFixtureFactory::minimalPdf())
        ->withCertificate($bundle['cert'])
        ->withMetadata(new SignatureMetadataDto(reason: 'Approval'))
        ->withAppearance(new SignatureAppearanceDto(null, [10, 10, 100, 50], 0))
        ->withCertificationLevel(CertificationLevel::FormFillAndSignatures)
        ->withHashAlgorithm('sha384');
    $prepared = $builder->prepare();
    $signature = signRsaDigest($prepared->payload->input(), $bundle['pkey'], 'sha384');

    expect($builder->completeBase64($prepared->state, base64_encode($signature)))->toStartWith('%PDF-')
        ->and(fn () => $builder->completeBase64($prepared->state, '***'))
        ->toThrow(SignerException::class, 'valid non-empty base64')
        ->and(fn () => $builder->withCertificationLevel(99))
        ->toThrow(SignerException::class, 'one of');
});

function signRsaDigest(string $digest, string $privateKeyPem, string $algorithm): string
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

it('rejects invalid payload and prepared state shapes', function (): void {
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
});

it('rejects corrupted state fields and missing byte ranges', function (): void {
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
        $payload['checksum'] = hash('sha256', implode('|', $payload));

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
});
