<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Tests\Unit;

use PHPUnit\Framework\TestCase;
use SignerPHP\PdfSigner\Domain\Exception\SignProcessException;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\Cms\Der;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\Cms\X509Certificate;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\NativeFunctionOverrideState;
use SignerPHP\PdfSigner\Tests\Support\Pkcs12Fixture;

final class X509CertificateTest extends TestCase
{
    public function test_from_pem_parses_rsa_fixture(): void
    {
        $certificate = X509Certificate::fromPem(Pkcs12Fixture::load()['cert']);

        self::assertSame('rsa', $certificate->keyType());
        self::assertNotSame('', $certificate->der);
        self::assertNotSame('', $certificate->issuerNameDer);
        self::assertNotSame('', $certificate->serialIntegerDer);
    }

    public function test_from_pem_accepts_raw_der(): void
    {
        $pem = Pkcs12Fixture::load()['cert'];
        $der = (string) base64_decode((string) preg_replace('/-----[^-]+-----|\s+/', '', $pem), true);

        $certificate = X509Certificate::fromPem($der);

        self::assertSame($der, $certificate->der);
        self::assertSame($der, $certificate->pem);
    }

    public function test_from_pem_throws_when_pem_cannot_be_decoded(): void
    {
        $this->expectException(SignProcessException::class);
        $this->expectExceptionMessage('Could not decode signing certificate PEM.');

        X509Certificate::fromPem("-----BEGIN CERTIFICATE-----\n!!!!\n-----END CERTIFICATE-----");
    }

    public function test_from_pem_throws_when_der_is_not_a_sequence(): void
    {
        $this->expectException(SignProcessException::class);
        $this->expectExceptionMessage('Signing certificate is not a DER SEQUENCE.');

        X509Certificate::fromPem(Der::tlv(0x02, "\x01"));
    }

    public function test_from_pem_throws_when_tbs_is_invalid(): void
    {
        $this->expectException(SignProcessException::class);
        $this->expectExceptionMessage('Signing certificate TBS is invalid.');

        X509Certificate::fromPem(Der::sequence(Der::tlv(0x02, "\x01")));
    }

    public function test_from_pem_throws_when_serial_is_invalid(): void
    {
        $this->expectException(SignProcessException::class);
        $this->expectExceptionMessage('Signing certificate serial number is invalid.');

        X509Certificate::fromPem(Der::sequence(Der::sequence(Der::sequence(''))));
    }

    public function test_from_pem_throws_when_issuer_is_invalid(): void
    {
        $this->expectException(SignProcessException::class);
        $this->expectExceptionMessage('Signing certificate issuer is invalid.');

        $tbs = Der::sequence(
            Der::tlv(0x02, "\x01")
            .Der::sequence('')
            .Der::tlv(0x02, "\x01")
        );

        X509Certificate::fromPem(Der::sequence($tbs));
    }

    public function test_key_type_throws_when_public_key_cannot_be_read(): void
    {
        $certificate = X509Certificate::fromPem(Pkcs12Fixture::load()['cert']);
        NativeFunctionOverrideState::$forceOpensslPublicKeyFailure = true;

        try {
            $this->expectException(SignProcessException::class);
            $this->expectExceptionMessage('Could not read signing certificate public key.');
            $certificate->keyType();
        } finally {
            NativeFunctionOverrideState::$forceOpensslPublicKeyFailure = false;
        }
    }

    public function test_key_type_throws_for_unsupported_keys(): void
    {
        $certificate = X509Certificate::fromPem(Pkcs12Fixture::load()['cert']);
        NativeFunctionOverrideState::$forceUnsupportedKeyType = true;

        try {
            $this->expectException(SignProcessException::class);
            $this->expectExceptionMessage('Unsupported signing certificate key type.');
            $certificate->keyType();
        } finally {
            NativeFunctionOverrideState::$forceUnsupportedKeyType = false;
        }
    }
}
