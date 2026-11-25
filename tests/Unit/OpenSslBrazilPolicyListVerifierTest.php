<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Tests\Unit;

use PHPUnit\Framework\TestCase;
use SignerPHP\PdfSigner\Application\DTO\SignatureValidationOptionsDto;
use SignerPHP\PdfSigner\Infrastructure\Native\Contract\HttpClientInterface;
use SignerPHP\PdfSigner\Infrastructure\Native\Contract\ProcessRunnerInterface;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\OpenSslBrazilPolicyListVerifier;
use SignerPHP\PdfSigner\Infrastructure\Native\ValueObject\HttpResponse;
use SignerPHP\PdfSigner\Infrastructure\Native\ValueObject\ProcessResult;

final class OpenSslBrazilPolicyListVerifierTest extends TestCase
{
    public function test_verify_returns_invalid_when_lpa_urls_are_missing(): void
    {
        $verifier = new OpenSslBrazilPolicyListVerifier;
        $result = $verifier->verifyPadesPolicy(new SignatureValidationOptionsDto);

        self::assertFalse($result->valid);
        self::assertStringContainsString('LPA PAdES URLs are not configured', (string) $result->message);
    }

    public function test_verify_returns_invalid_when_download_fails(): void
    {
        $httpClient = new class implements HttpClientInterface
        {
            public function request(
                string $method,
                string $url,
                array $headers = [],
                string $body = '',
                int $timeoutSeconds = 10,
                bool $followRedirects = false
            ): HttpResponse {
                return new HttpResponse(500, '');
            }
        };

        $verifier = new OpenSslBrazilPolicyListVerifier($httpClient);
        $result = $verifier->verifyPadesPolicy(new SignatureValidationOptionsDto(
            lpaUrlAsn1Pades: 'https://example.local/lpa.der',
            lpaUrlAsn1SignaturePades: 'https://example.local/lpa.p7s',
        ));

        self::assertFalse($result->valid);
        self::assertStringContainsString('Could not download LPA PAdES ASN.1', (string) $result->message);
    }

    public function test_verify_returns_invalid_when_signature_download_fails(): void
    {
        $httpClient = new class implements HttpClientInterface
        {
            private int $calls = 0;

            public function request(
                string $method,
                string $url,
                array $headers = [],
                string $body = '',
                int $timeoutSeconds = 10,
                bool $followRedirects = false
            ): HttpResponse {
                $this->calls++;

                if ($this->calls === 1) {
                    return new HttpResponse(200, 'lpa');
                }

                return new HttpResponse(500, '');
            }
        };

        $verifier = new OpenSslBrazilPolicyListVerifier($httpClient);
        $result = $verifier->verifyPadesPolicy(new SignatureValidationOptionsDto(
            lpaUrlAsn1Pades: 'https://example.local/lpa.der',
            lpaUrlAsn1SignaturePades: 'https://example.local/lpa.p7s',
        ));

        self::assertFalse($result->valid);
        self::assertStringContainsString('Could not download LPA PAdES signature', (string) $result->message);
    }

    public function test_verifies_the_official_iti_lpa_signature(): void
    {
        // Official LPA PAdES and its BER-encoded detached signature, as published by ITI.
        $result = $this->verifyWith(self::fixture('LPA_PAdES.der'), self::fixture('LPA_PAdES.p7s'));

        self::assertTrue($result->valid, (string) $result->message);
    }

    public function test_accepts_pem_and_smime_encoded_signatures(): void
    {
        $base64 = chunk_split(base64_encode(self::fixture('LPA_PAdES.p7s')), 64, "\n");

        self::assertTrue($this->verifyWith(self::fixture('LPA_PAdES.der'), "-----BEGIN PKCS7-----\n{$base64}-----END PKCS7-----\n")->valid);
        self::assertTrue($this->verifyWith(self::fixture('LPA_PAdES.der'), "Content-Type: application/pkcs7-signature; name=\"smime.p7s\"\nContent-Transfer-Encoding: base64\n\n{$base64}")->valid);
    }

    public function test_rejects_a_modified_lpa(): void
    {
        $result = $this->verifyWith(self::fixture('LPA_PAdES.der').' ', self::fixture('LPA_PAdES.p7s'));

        self::assertFalse($result->valid);
        self::assertSame('LPA PAdES signature verification failed.', $result->message);
    }

    public function test_rejects_a_signature_that_is_not_cms(): void
    {
        $result = $this->verifyWith(self::fixture('LPA_PAdES.der'), 'not a signature');

        self::assertFalse($result->valid);
        self::assertSame('LPA PAdES signature verification failed.', $result->message);
    }

    public function test_a_process_runner_is_still_accepted_and_never_used(): void
    {
        $runner = new class implements ProcessRunnerInterface
        {
            public function run(string $command): ProcessResult
            {
                throw new \LogicException('No external process may run.');
            }
        };

        $verifier = new OpenSslBrazilPolicyListVerifier($this->httpClientServing(self::fixture('LPA_PAdES.der'), self::fixture('LPA_PAdES.p7s')), $runner);

        self::assertTrue($verifier->verifyPadesPolicy($this->options())->valid);
    }

    private function verifyWith(string $lpa, string $signature): \SignerPHP\PdfSigner\Infrastructure\Native\ValueObject\SignaturePolicyVerification
    {
        return (new OpenSslBrazilPolicyListVerifier($this->httpClientServing($lpa, $signature)))->verifyPadesPolicy($this->options());
    }

    private function options(): SignatureValidationOptionsDto
    {
        return new SignatureValidationOptionsDto(
            lpaUrlAsn1Pades: 'https://example.local/lpa.der',
            lpaUrlAsn1SignaturePades: 'https://example.local/lpa.p7s',
        );
    }

    private function httpClientServing(string $lpa, string $signature): HttpClientInterface
    {
        return new class($lpa, $signature) implements HttpClientInterface
        {
            public function __construct(private readonly string $lpa, private readonly string $signature) {}

            public function request(
                string $method,
                string $url,
                array $headers = [],
                string $body = '',
                int $timeoutSeconds = 10,
                bool $followRedirects = false
            ): HttpResponse {
                return new HttpResponse(200, str_ends_with($url, '.p7s') ? $this->signature : $this->lpa);
            }
        };
    }

    private static function fixture(string $name): string
    {
        return (string) file_get_contents(dirname(__DIR__).'/Fixtures/icp-brasil/'.$name);
    }
}
