<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Tests\Unit;

use PHPUnit\Framework\TestCase;
use SignerPHP\PdfCore\Buffer;
use SignerPHP\PdfCore\SignatureObject;
use SignerPHP\PdfSigner\Application\DTO\IcpBrasilPadesPolicy;
use SignerPHP\PdfSigner\Application\DTO\SignatureProfile;
use SignerPHP\PdfSigner\Application\DTO\TimestampOptionsDto;
use SignerPHP\PdfSigner\Domain\Exception\SignProcessException;
use SignerPHP\PdfSigner\Infrastructure\Native\Contract\TimestampTokenProviderInterface;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\Cms\Der;
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

    public function test_ad_rt_adds_a_signature_timestamp_over_the_signature_value(): void
    {
        $bundle = Pkcs12Fixture::load();
        $payload = "%PDF-1.4\n1 0 obj<<>>endobj\nstartxref\n0\n%%EOF\n";
        $token = Der::sequence(Der::objectIdentifier('1.2.840.113549.1.7.2'));
        $tsa = $this->tsa(bin2hex($token));

        $result = (new Pkcs7Signer(timestampTokenProvider: $tsa))->signWithPolicy(
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
