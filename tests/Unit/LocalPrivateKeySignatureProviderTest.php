<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Tests\Unit;

use PHPUnit\Framework\TestCase;
use SignerPHP\PdfSigner\Application\DTO\CertificateCredentialsDto;
use SignerPHP\PdfSigner\Application\DTO\HashAlgorithm;
use SignerPHP\PdfSigner\Application\DTO\SigningPayload;
use SignerPHP\PdfSigner\Domain\Exception\SignProcessException;
use SignerPHP\PdfSigner\Domain\ValueObject\VerifiedCertificate;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\LocalPrivateKeySignatureProvider;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\LocalPrivateKeySignatureProviderFactory;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\NativeFunctionOverrideState;
use SignerPHP\PdfSigner\Tests\Support\Pkcs12Fixture;

final class LocalPrivateKeySignatureProviderTest extends TestCase
{
    public function test_sign_produces_verifiable_raw_signature(): void
    {
        $bundle = Pkcs12Fixture::load();
        $payload = new SigningPayload('signed-attributes-der', HashAlgorithm::Sha256);
        $provider = new LocalPrivateKeySignatureProvider($bundle['pkey']);
        $value = $provider->sign($payload);

        self::assertNotSame('', $value->bytes);
        self::assertSame(1, openssl_verify($payload->data, $value->bytes, $bundle['cert'], OPENSSL_ALGO_SHA256));
    }

    public function test_sign_supports_sha384(): void
    {
        $bundle = Pkcs12Fixture::load();
        $payload = new SigningPayload('signed-attributes-der', HashAlgorithm::Sha384);
        $provider = new LocalPrivateKeySignatureProvider($bundle['pkey']);
        $value = $provider->sign($payload);

        self::assertSame(1, openssl_verify($payload->data, $value->bytes, $bundle['cert'], OPENSSL_ALGO_SHA384));
    }

    public function test_sign_throws_when_openssl_sign_fails(): void
    {
        $bundle = Pkcs12Fixture::load();
        $provider = new LocalPrivateKeySignatureProvider($bundle['pkey']);
        NativeFunctionOverrideState::$forceOpensslSignFailure = true;

        try {
            $this->expectException(SignProcessException::class);
            $this->expectExceptionMessage('Failed to sign payload with the local private key.');
            $provider->sign(new SigningPayload('payload'));
        } finally {
            NativeFunctionOverrideState::$forceOpensslSignFailure = false;
        }
    }

    public function test_sign_throws_when_private_key_cannot_be_loaded(): void
    {
        $provider = new LocalPrivateKeySignatureProvider('not-a-private-key');

        $this->expectException(SignProcessException::class);
        $this->expectExceptionMessage('Could not load the local private key.');
        $provider->sign(new SigningPayload('payload'));
    }

    public function test_factory_creates_local_provider_from_verified_certificate(): void
    {
        $factory = new LocalPrivateKeySignatureProviderFactory;
        $provider = $factory->create(new VerifiedCertificate(
            new CertificateCredentialsDto('/tmp/cert.pfx', 'secret'),
            ['validTo_time_t' => PHP_INT_MAX],
            ['cert' => 'CERT', 'pkey' => 'KEY'],
        ));

        self::assertInstanceOf(LocalPrivateKeySignatureProvider::class, $provider);
    }

    public function test_factory_throws_when_pem_material_is_missing(): void
    {
        $factory = new LocalPrivateKeySignatureProviderFactory;

        $this->expectException(SignProcessException::class);
        $this->expectExceptionMessage('Verified certificate is missing PEM material for local signing.');

        $factory->create(new VerifiedCertificate(
            new CertificateCredentialsDto('/tmp/cert.pfx', 'secret'),
            ['validTo_time_t' => PHP_INT_MAX],
            ['cert' => '', 'pkey' => ''],
        ));
    }
}
