<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Tests\Unit;

use PHPUnit\Framework\TestCase;
use SignerPHP\PdfSigner\Application\DTO\TimestampOptionsDto;
use SignerPHP\PdfSigner\Application\Service\TimestampService;
use SignerPHP\PdfSigner\Domain\Exception\SignProcessException;
use SignerPHP\PdfSigner\Infrastructure\Native\Contract\TimestampTokenProviderInterface;

final class TimestampServiceTest extends TestCase
{
    public function test_request_token_hex_uses_full_content_as_byte_range(): void
    {
        $capture = new class
        {
            public string $content = '';

            /** @var array{0:int,1:int,2:int,3:int}|null */
            public ?array $byteRange = null;
        };

        $provider = new class($capture) implements TimestampTokenProviderInterface
        {
            public function __construct(private object $capture) {}

            public function requestTokenHex(string $signableDocument, array $byteRange, TimestampOptionsDto $options): string
            {
                $this->capture->content = $signableDocument;
                $this->capture->byteRange = $byteRange;

                return 'ABCD';
            }
        };

        $service = new TimestampService($provider);
        $hex = $service->requestTokenHex('probe-content', new TimestampOptionsDto('https://tsa.example'));

        self::assertSame('ABCD', $hex);
        self::assertSame('probe-content', $capture->content);
        self::assertSame([0, strlen('probe-content'), 0, 0], $capture->byteRange);
    }

    public function test_test_connection_returns_failure_with_status_code_when_provider_throws_http_status_message(): void
    {
        $provider = new class implements TimestampTokenProviderInterface
        {
            public function requestTokenHex(string $signableDocument, array $byteRange, TimestampOptionsDto $options): string
            {
                throw new SignProcessException('Could not fetch RFC3161 timestamp response from TSA endpoint. Status: 403.');
            }
        };

        $service = new TimestampService($provider);
        $result = $service->testConnection(new TimestampOptionsDto('https://tsa.example'));

        self::assertFalse($result->success);
        self::assertSame(403, $result->statusCode);
        self::assertStringContainsString('Status: 403', (string) $result->message);
    }

    public function test_request_token_base64_converts_hex_payload_from_provider(): void
    {
        $provider = new class implements TimestampTokenProviderInterface
        {
            public function requestTokenHex(string $signableDocument, array $byteRange, TimestampOptionsDto $options): string
            {
                return '414243';
            }
        };

        $service = new TimestampService($provider);

        self::assertSame('QUJD', $service->requestTokenBase64('probe', new TimestampOptionsDto('https://tsa.example')));
    }

    public function test_request_token_base64_throws_when_hex_is_invalid(): void
    {
        $provider = new class implements TimestampTokenProviderInterface
        {
            public function requestTokenHex(string $signableDocument, array $byteRange, TimestampOptionsDto $options): string
            {
                return 'invalid-hex';
            }
        };

        $service = new TimestampService($provider);

        $this->expectException(SignProcessException::class);
        $this->expectExceptionMessage('Could not convert timestamp token hex to binary.');
        set_error_handler(static function (): bool {
            return true;
        });
        try {
            $service->requestTokenBase64('probe', new TimestampOptionsDto('https://tsa.example'));
        } finally {
            restore_error_handler();
        }
    }

    public function test_test_connection_returns_success_message_with_token_size(): void
    {
        $provider = new class implements TimestampTokenProviderInterface
        {
            public function requestTokenHex(string $signableDocument, array $byteRange, TimestampOptionsDto $options): string
            {
                return 'ABCD1234';
            }
        };

        $service = new TimestampService($provider);
        $result = $service->testConnection(new TimestampOptionsDto('https://tsa.example'), 'fixed-probe');

        self::assertTrue($result->success);
        self::assertNull($result->statusCode);
        self::assertStringContainsString('8 hex chars', (string) $result->message);
    }

    public function test_test_connection_returns_failure_without_status_code_for_non_http_message(): void
    {
        $provider = new class implements TimestampTokenProviderInterface
        {
            public function requestTokenHex(string $signableDocument, array $byteRange, TimestampOptionsDto $options): string
            {
                throw new SignProcessException('Generic transport failure');
            }
        };

        $service = new TimestampService($provider);
        $result = $service->testConnection(new TimestampOptionsDto('https://tsa.example'));

        self::assertFalse($result->success);
        self::assertNull($result->statusCode);
        self::assertSame('Generic transport failure', $result->message);
    }
}
