<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Tests\Unit;

use PHPUnit\Framework\TestCase;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\CurlHttpClient;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\NativeFunctionOverrideState;

final class NativeTempnamFailureCoverageTest extends TestCase
{
    public function test_curl_http_client_returns_transport_error_when_curl_init_fails(): void
    {
        NativeFunctionOverrideState::$forceCurlInitFailure = true;

        try {
            $client = new CurlHttpClient;
            $response = $client->request('GET', 'https://example.com');

            self::assertSame(0, $response->statusCode);
            self::assertSame('curl_init failed', $response->transportError);
        } finally {
            NativeFunctionOverrideState::$forceCurlInitFailure = false;
        }
    }
}
