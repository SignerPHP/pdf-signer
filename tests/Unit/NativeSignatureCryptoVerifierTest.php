<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Tests\Unit;

use PHPUnit\Framework\TestCase;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\NativeSignatureCryptoVerifier;
use SignerPHP\PdfSigner\Tests\Support\CmsTestFactory;

final class NativeSignatureCryptoVerifierTest extends TestCase
{
    public function test_verify_returns_invalid_for_empty_signature_hex(): void
    {
        $verifier = new NativeSignatureCryptoVerifier;
        $result = $verifier->verify('content', '');

        self::assertFalse($result->valid);
    }

    public function test_verify_returns_invalid_for_zero_placeholder_hex(): void
    {
        $verifier = new NativeSignatureCryptoVerifier;
        $result = $verifier->verify('content', '0000000000');

        self::assertFalse($result->valid);
        self::assertSame('Empty signature contents.', $result->message);
    }

    public function test_verify_returns_invalid_for_non_hex_signature(): void
    {
        $verifier = new NativeSignatureCryptoVerifier;

        set_error_handler(static function (): bool {
            return true;
        });
        try {
            $result = $verifier->verify('content', 'GG');
            $odd = $verifier->verify('content', 'ABC');
        } finally {
            restore_error_handler();
        }

        self::assertFalse($result->valid);
        self::assertSame('Invalid signature hex payload.', $result->message);
        self::assertSame('Invalid signature hex payload.', $odd->message);
    }

    public function test_verify_accepts_a_real_detached_signature_padded_like_pdf_contents(): void
    {
        $content = "%PDF-1.7 signed byte range\n";
        $hex = str_pad(strtoupper(bin2hex(CmsTestFactory::sign($content))), 16384, '0');

        $verifier = new NativeSignatureCryptoVerifier;

        self::assertTrue($verifier->verify($content, $hex)->valid);
        $tampered = $verifier->verify($content.'x', $hex);
        self::assertFalse($tampered->valid);
        self::assertSame('CMS message digest does not match the signed content.', $tampered->message);
    }

    public function test_verify_reports_a_payload_that_is_not_cms(): void
    {
        $result = (new NativeSignatureCryptoVerifier)->verify('content', '3003020101');

        self::assertFalse($result->valid);
        self::assertStringStartsWith('Invalid CMS signature: ', (string) $result->message);
    }
}
