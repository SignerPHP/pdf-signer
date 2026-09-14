<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Tests\Unit;

use PHPUnit\Framework\TestCase;
use SignerPHP\PdfCore\Buffer;
use SignerPHP\PdfSigner\Application\Contract\SignatureProviderInterface;
use SignerPHP\PdfSigner\Application\DTO\SignatureValue;
use SignerPHP\PdfSigner\Application\DTO\SigningPayload;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\Pkcs7Signer;
use SignerPHP\PdfSigner\Infrastructure\PdfCore\Signature;

final class Pkcs7SignerTest extends TestCase
{
    public function test_sign_hex_encodes_and_pads_provider_bytes(): void
    {
        $provider = new class implements SignatureProviderInterface
        {
            public ?SigningPayload $payload = null;

            public function sign(SigningPayload $payload): SignatureValue
            {
                $this->payload = $payload;

                return new SignatureValue('AB');
            }
        };

        $result = (new Pkcs7Signer)->sign(new Buffer('payload-to-sign'), $provider);

        self::assertSame('payload-to-sign', $provider->payload?->data);
        self::assertSame('4142', substr($result, 0, 4));
        self::assertSame(Signature::SIGNATURE_MAX_LENGTH, strlen($result));
        self::assertSame(str_repeat('0', Signature::SIGNATURE_MAX_LENGTH - 4), substr($result, 4));
    }
}
