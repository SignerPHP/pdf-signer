<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Tests\Unit;

use PHPUnit\Framework\TestCase;
use SignerPHP\PdfSigner\Application\DTO\CertificateCredentialsDto;
use SignerPHP\PdfSigner\Application\DTO\SigningPayload;
use SignerPHP\PdfSigner\Domain\Exception\SignProcessException;
use SignerPHP\PdfSigner\Domain\ValueObject\VerifiedCertificate;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\LocalPrivateKeySignatureProvider;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\LocalPrivateKeySignatureProviderFactory;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\NativeFunctionOverrideState;
use SignerPHP\PdfSigner\Tests\Support\SignatureRuntimeSpy;

final class LocalPrivateKeySignatureProviderTest extends TestCase
{
    protected function tearDown(): void
    {
        NativeFunctionOverrideState::$forceTempnamFailure = false;
    }

    public function test_sign_extracts_cms_der_from_openssl_smime_output(): void
    {
        $runtime = new SignatureRuntimeSpy;
        $runtime->decodedBase64 = 'CMS';
        $runtime->fileSize = 3;
        $runtime->readContent = "abc%%EOF\n\n------header\n\nQQ==";

        $provider = new LocalPrivateKeySignatureProvider('CERT', 'KEY', $runtime);
        $value = $provider->sign(new SigningPayload("abc%%EOF\n"));

        self::assertSame('CMS', $value->bytes);
        self::assertContains('/tmp/fake-signature.p7m', $runtime->removedFiles);
    }

    public function test_sign_throws_when_openssl_sign_fails(): void
    {
        $runtime = new SignatureRuntimeSpy;
        $runtime->signResult = false;

        $provider = new LocalPrivateKeySignatureProvider('CERT', 'KEY', $runtime);

        $this->expectException(SignProcessException::class);
        $this->expectExceptionMessage('Failed to sign payload with the local private key.');
        $provider->sign(new SigningPayload('payload'));
    }

    public function test_sign_throws_when_output_temp_file_cannot_be_created(): void
    {
        $runtime = new SignatureRuntimeSpy;
        $runtime->tempFile = false;

        $provider = new LocalPrivateKeySignatureProvider('CERT', 'KEY', $runtime);

        $this->expectException(SignProcessException::class);
        $this->expectExceptionMessage('Could not create a temporary filename for the local signature.');
        $provider->sign(new SigningPayload('payload'));
    }

    public function test_sign_throws_when_signed_output_cannot_be_read(): void
    {
        $runtime = new SignatureRuntimeSpy;
        $runtime->readContent = false;

        $provider = new LocalPrivateKeySignatureProvider('CERT', 'KEY', $runtime);

        $this->expectException(SignProcessException::class);
        $this->expectExceptionMessage('Could not read generated signature file.');
        $provider->sign(new SigningPayload('payload'));
    }

    public function test_sign_throws_when_pkcs7_payload_separator_is_missing(): void
    {
        $runtime = new SignatureRuntimeSpy;
        $runtime->readContent = 'abcNO-SEPARATOR';

        $provider = new LocalPrivateKeySignatureProvider('CERT', 'KEY', $runtime);

        $this->expectException(SignProcessException::class);
        $this->expectExceptionMessage('Could not extract PKCS7 payload from signed output.');
        $provider->sign(new SigningPayload('payload'));
    }

    public function test_sign_throws_when_payload_size_cannot_be_read(): void
    {
        $runtime = new SignatureRuntimeSpy;
        $runtime->fileSize = false;

        $provider = new LocalPrivateKeySignatureProvider('CERT', 'KEY', $runtime);

        $this->expectException(SignProcessException::class);
        $this->expectExceptionMessage('Could not read signing payload size.');
        $provider->sign(new SigningPayload('payload'));
    }

    public function test_sign_throws_when_pkcs7_payload_is_malformed(): void
    {
        $runtime = new SignatureRuntimeSpy;
        $runtime->readContent = 'abc%%EOF'."\n\n".'------header-only';

        $provider = new LocalPrivateKeySignatureProvider('CERT', 'KEY', $runtime);

        $this->expectException(SignProcessException::class);
        $this->expectExceptionMessage('Malformed PKCS7 output.');
        $provider->sign(new SigningPayload('payload'));
    }

    public function test_sign_throws_when_base64_payload_is_invalid(): void
    {
        $runtime = new SignatureRuntimeSpy;
        $runtime->readContent = 'abc%%EOF'."\n\n".'------h'."\n\n".'%%%%';
        $runtime->decodedBase64 = false;

        $provider = new LocalPrivateKeySignatureProvider('CERT', 'KEY', $runtime);

        $this->expectException(SignProcessException::class);
        $this->expectExceptionMessage('Could not decode PKCS7 base64 payload.');
        $provider->sign(new SigningPayload('payload'));
    }

    public function test_sign_throws_when_temp_file_cannot_be_allocated(): void
    {
        NativeFunctionOverrideState::$forceTempnamFailure = true;

        $this->expectException(SignProcessException::class);
        $this->expectExceptionMessage('Could not allocate temporary file to sign payload.');

        (new LocalPrivateKeySignatureProvider('CERT', 'KEY'))->sign(new SigningPayload('payload'));
    }

    public function test_sign_with_local_private_key_produces_verifiable_cms(): void
    {
        if (! function_exists('openssl_pkcs12_read') || ! function_exists('openssl_pkcs7_sign')) {
            self::markTestSkipped('OpenSSL PKCS#7 signing is required.');
        }

        $certPath = __DIR__.'/../../exemplos/cert.pfx';
        if (! is_file($certPath)) {
            self::markTestSkipped('Test certificate exemplos/cert.pfx not found.');
        }

        $pkcs12 = (string) file_get_contents($certPath);
        $bundle = [];
        if (! openssl_pkcs12_read($pkcs12, $bundle, '1234**')) {
            self::markTestSkipped('Could not read exemplos/cert.pfx.');
        }

        $payload = "%PDF-1.4\n1 0 obj<<>>endobj\nstartxref\n0\n%%EOF\n";
        $provider = new LocalPrivateKeySignatureProvider((string) $bundle['cert'], (string) $bundle['pkey']);
        $value = $provider->sign(new SigningPayload($payload));

        self::assertNotSame('', $value->bytes);
        self::assertTrue($this->cmsVerifies($value->bytes, $payload), 'CMS produced by the local provider must verify against the payload.');
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

    private function cmsVerifies(string $cmsDer, string $payload): bool
    {
        $cmsFile = tempnam(sys_get_temp_dir(), 'cms');
        $payloadFile = tempnam(sys_get_temp_dir(), 'dat');
        if ($cmsFile === false || $payloadFile === false) {
            return false;
        }

        try {
            file_put_contents($cmsFile, $cmsDer);
            file_put_contents($payloadFile, $payload);
            $command = sprintf(
                'openssl cms -verify -binary -inform DER -in %s -content %s -noverify -out /dev/null 2>&1',
                escapeshellarg($cmsFile),
                escapeshellarg($payloadFile),
            );
            exec($command, $output, $exitCode);

            return $exitCode === 0;
        } finally {
            @unlink($cmsFile);
            @unlink($payloadFile);
        }
    }
}
