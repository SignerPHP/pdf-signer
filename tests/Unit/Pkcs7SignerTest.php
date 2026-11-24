<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Tests\Unit;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SignerPHP\PdfCore\Buffer;
use SignerPHP\PdfCore\SignatureObject;
use SignerPHP\PdfSigner\Application\Contract\SignatureProviderInterface;
use SignerPHP\PdfSigner\Application\DTO\IcpBrasilPadesPolicy;
use SignerPHP\PdfSigner\Application\DTO\SignatureProfile;
use SignerPHP\PdfSigner\Application\DTO\TimestampOptionsDto;
use SignerPHP\PdfSigner\Domain\Exception\SignProcessException;
use SignerPHP\PdfSigner\Infrastructure\Native\Contract\TimestampTokenProviderInterface;
use SignerPHP\PdfSigner\Infrastructure\Native\Contract\TimestampTokenValidatorInterface;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\Cms\Der;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\Cms\X509Certificate;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\LocalPrivateKeySignatureProvider;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\Pkcs7Signer;
use SignerPHP\PdfSigner\Tests\Support\Pkcs12Fixture;

final class Pkcs7SignerTest extends TestCase
{
    public function test_sign_throws_when_certificate_pem_is_missing(): void
    {
        $provider = new LocalPrivateKeySignatureProvider('not-a-key');

        $this->expectException(SignProcessException::class);
        $this->expectExceptionMessage('Signing certificate PEM is required to assemble CMS.');

        (new Pkcs7Signer)->sign(new Buffer('payload'), $provider, '');
    }

    public function test_sign_assembles_padded_hex_cms_from_provider_signature(): void
    {
        $bundle = Pkcs12Fixture::load();
        $payload = "%PDF-1.4\n1 0 obj<<>>endobj\nstartxref\n0\n%%EOF\n";
        $provider = new LocalPrivateKeySignatureProvider($bundle['pkey']);

        $result = (new Pkcs7Signer)->sign(new Buffer($payload), $provider, $bundle['cert']);
        $binary = (string) hex2bin($result);
        [, , $end] = Der::readTlv($binary, 0);
        $cms = substr($binary, 0, $end);

        self::assertSame(SignatureObject::SIGNATURE_MAX_LENGTH, strlen($result));
        self::assertSame(str_pad(bin2hex($cms), SignatureObject::SIGNATURE_MAX_LENGTH, '0'), $result);
        self::assertTrue(Pkcs12Fixture::cmsVerifies($cms, $payload));
    }

    #[DataProvider('invalidChainEntries')]
    public function test_rejects_invalid_chain_entries_before_requesting_a_signature(string $entry): void
    {
        $bundle = Pkcs12Fixture::load();
        $provider = $this->createMock(SignatureProviderInterface::class);
        $provider->expects(self::never())->method('sign');

        $this->expectException(SignProcessException::class);
        $this->expectExceptionMessage('Invalid certificate in CMS certificate chain');

        (new Pkcs7Signer)->signWithChain(
            new Buffer('payload'),
            $provider,
            $bundle['cert'],
            SignatureProfile::PadesBaselineB,
            [$bundle['cert'], $entry],
        );
    }

    /** @return array<string, array{string}> */
    public static function invalidChainEntries(): array
    {
        return [
            'non-certificate text' => ['not a certificate'],
            'non-whitespace null byte' => ["\0"],
            'malformed PEM' => ["-----BEGIN CERTIFICATE-----\nnot-valid-base64!\n-----END CERTIFICATE-----"],
            'invalid base64 padding' => ["-----BEGIN CERTIFICATE-----\nA===\n-----END CERTIFICATE-----"],
            'base64 containing non-X509 DER' => ["-----BEGIN CERTIFICATE-----\nMAMCAQA=\n-----END CERTIFICATE-----"],
        ];
    }

    #[DataProvider('certificateWithTrailingDataFormats')]
    public function test_rejects_a_valid_certificate_followed_by_trailing_data(bool $der): void
    {
        $bundle = Pkcs12Fixture::load();
        $certificate = $der ? X509Certificate::fromPem($bundle['cert'])->der : $bundle['cert'];
        $provider = $this->createMock(SignatureProviderInterface::class);
        $provider->expects(self::never())->method('sign');

        $this->expectException(SignProcessException::class);
        $this->expectExceptionMessage('Invalid certificate in CMS certificate chain');

        (new Pkcs7Signer)->signWithChain(
            new Buffer('payload'),
            $provider,
            $bundle['cert'],
            SignatureProfile::PadesBaselineB,
            [$certificate.'unexpected data'],
        );
    }

    /** @return array<string, array{bool}> */
    public static function certificateWithTrailingDataFormats(): array
    {
        return [
            'DER' => [true],
            'PEM' => [false],
        ];
    }

    public function test_ad_rt_adds_a_signature_timestamp_over_the_signature_value(): void
    {
        $bundle = Pkcs12Fixture::load();
        $payload = "%PDF-1.4\n1 0 obj<<>>endobj\nstartxref\n0\n%%EOF\n";
        $token = Der::sequence(Der::objectIdentifier('1.2.840.113549.1.7.2'));
        $tsa = $this->tsa(bin2hex($token));
        // This test checks CMS assembly; RFC 3161 cryptographic validation is exercised separately.
        $validator = new class implements TimestampTokenValidatorInterface
        {
            public function assertValid(string $tokenDer, string $signatureValue): void {}
        };

        $result = (new Pkcs7Signer(timestampTokenProvider: $tsa, timestampTokenValidator: $validator))->signWithPolicy(
            new Buffer($payload),
            new LocalPrivateKeySignatureProvider($bundle['pkey']),
            $bundle['cert'],
            SignatureProfile::PadesBaselineB,
            IcpBrasilPadesPolicy::AdRtV1_3->toIdentifier(),
            new TimestampOptionsDto('https://tsa.example'),
        );
        $cms = $this->cms($result);

        self::assertCount(1, $tsa->requests);
        [$data, $byteRange] = $tsa->requests[0];
        self::assertSame([0, strlen($data), strlen($data), 0], $byteRange);

        // SignerInfo: ... signature OCTET STRING, then [1] unsignedAttrs { id-aa-signatureTimeStampToken }
        $unsignedAttributes = Der::contextSpecific(1, Der::sequence(
            Der::objectIdentifier('1.2.840.113549.1.9.16.2.14').Der::set($token)
        ));
        self::assertStringContainsString(Der::octetString($data).$unsignedAttributes, $cms, 'the token covers the signature value');
        self::assertTrue(Pkcs12Fixture::cmsVerifies($cms, $payload));
    }

    public function test_ad_rt_rejects_a_timestamp_larger_than_the_pdf_signature_placeholder(): void
    {
        $bundle = Pkcs12Fixture::load();
        $validator = new class implements TimestampTokenValidatorInterface
        {
            public function assertValid(string $tokenDer, string $signatureValue): void {}
        };

        $this->expectException(SignProcessException::class);
        $this->expectExceptionMessage('exceeds the reserved PDF signature size');

        (new Pkcs7Signer(
            timestampTokenProvider: $this->tsa(str_repeat('30', SignatureObject::SIGNATURE_MAX_LENGTH)),
            timestampTokenValidator: $validator,
        ))->signWithPolicy(
            new Buffer('payload'),
            new LocalPrivateKeySignatureProvider($bundle['pkey']),
            $bundle['cert'],
            SignatureProfile::PadesBaselineB,
            IcpBrasilPadesPolicy::AdRtV1_3->toIdentifier(),
            new TimestampOptionsDto('https://tsa.example'),
        );
    }

    public function test_ad_rb_does_not_request_a_signature_timestamp(): void
    {
        $bundle = Pkcs12Fixture::load();
        $tsa = $this->tsa('3000');

        $result = (new Pkcs7Signer(timestampTokenProvider: $tsa))->signWithPolicy(
            new Buffer('payload'),
            new LocalPrivateKeySignatureProvider($bundle['pkey']),
            $bundle['cert'],
            SignatureProfile::PadesBaselineB,
            IcpBrasilPadesPolicy::AdRbV1_3->toIdentifier(),
            new TimestampOptionsDto('https://tsa.example'),
        );

        self::assertSame([], $tsa->requests);
        self::assertStringNotContainsString(Der::objectIdentifier('1.2.840.113549.1.9.16.2.14'), $this->cms($result));
    }

    public function test_ad_rt_without_tsa_is_rejected(): void
    {
        $bundle = Pkcs12Fixture::load();

        $this->expectException(SignProcessException::class);
        $this->expectExceptionMessage('requires a signature timestamp');

        (new Pkcs7Signer(timestampTokenProvider: $this->tsa('3000')))->signWithPolicy(
            new Buffer('payload'),
            new LocalPrivateKeySignatureProvider($bundle['pkey']),
            $bundle['cert'],
            SignatureProfile::PadesBaselineB,
            IcpBrasilPadesPolicy::AdRtV1_3->toIdentifier(),
        );
    }

    public function test_invalid_tsa_token_is_rejected(): void
    {
        $bundle = Pkcs12Fixture::load();

        $this->expectException(SignProcessException::class);
        $this->expectExceptionMessage('invalid signature timestamp token');

        (new Pkcs7Signer(timestampTokenProvider: $this->tsa('not-hex')))->signWithPolicy(
            new Buffer('payload'),
            new LocalPrivateKeySignatureProvider($bundle['pkey']),
            $bundle['cert'],
            SignatureProfile::PadesBaselineB,
            IcpBrasilPadesPolicy::AdRtV1_3->toIdentifier(),
            new TimestampOptionsDto('https://tsa.example'),
        );
    }

    private function cms(string $paddedHex): string
    {
        $binary = (string) hex2bin($paddedHex);
        [, , $end] = Der::readTlv($binary, 0);

        return substr($binary, 0, $end);
    }

    private function tsa(string $tokenHex): TimestampTokenProviderInterface
    {
        return new class($tokenHex) implements TimestampTokenProviderInterface
        {
            /** @var list<array{0:string,1:array{0:int,1:int,2:int,3:int}}> */
            public array $requests = [];

            public function __construct(private string $tokenHex) {}

            public function requestTokenHex(string $signableDocument, array $byteRange, TimestampOptionsDto $options): string
            {
                $this->requests[] = [$signableDocument, $byteRange];

                return $this->tokenHex;
            }
        };
    }
}
