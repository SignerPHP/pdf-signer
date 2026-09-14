<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Tests\Unit;

use PHPUnit\Framework\TestCase;
use SignerPHP\PdfCore\Buffer;
use SignerPHP\PdfSigner\Domain\Exception\SignProcessException;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\Cms\Der;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\LocalPrivateKeySignatureProvider;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\Pkcs7Signer;
use SignerPHP\PdfSigner\Infrastructure\PdfCore\Signature;
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

        self::assertSame(Signature::SIGNATURE_MAX_LENGTH, strlen($result));
        self::assertSame(str_pad(bin2hex($cms), Signature::SIGNATURE_MAX_LENGTH, '0'), $result);
        self::assertTrue(Pkcs12Fixture::cmsVerifies($cms, $payload));
    }
}
