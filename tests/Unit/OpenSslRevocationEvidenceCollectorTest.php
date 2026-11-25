<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Tests\Unit;

use PHPUnit\Framework\TestCase;
use SignerPHP\PdfSigner\Infrastructure\Native\Contract\ProcessRunnerInterface;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\Ocsp\OcspRequest;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\Ocsp\OcspResponse;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\OpenSslRevocationEvidenceCollector;
use SignerPHP\PdfSigner\Infrastructure\Native\ValueObject\HttpResponse;
use SignerPHP\PdfSigner\Tests\Support\OcspTestPki;

final class OpenSslRevocationEvidenceCollectorTest extends TestCase
{
    private static ?OcspTestPki $pki = null;

    private function pki(): OcspTestPki
    {
        if (! OcspTestPki::opensslAvailable()) {
            self::markTestSkipped('The OpenSSL CLI is required to produce OCSP response fixtures.');
        }

        return self::$pki ??= new OcspTestPki;
    }

    public function test_collect_returns_empty_array_when_chain_is_empty(): void
    {
        $collector = new OpenSslRevocationEvidenceCollector;

        self::assertSame([], $collector->collect([]));
    }

    public function test_collect_returns_empty_evidence_for_invalid_certificates(): void
    {
        $collector = new OpenSslRevocationEvidenceCollector;

        $result = $collector->collect(["\x01\x02\x03", "\x04\x05\x06"]);

        self::assertSame(
            [
                0 => ['ocsp' => [], 'crl' => []],
                1 => ['ocsp' => [], 'crl' => []],
            ],
            $result,
        );
    }

    public function test_collect_returns_empty_evidence_for_empty_der_payload(): void
    {
        $collector = new OpenSslRevocationEvidenceCollector;

        $result = $collector->collect(['']);

        self::assertSame([0 => ['ocsp' => [], 'crl' => []]], $result);
    }

    public function test_collect_aggregates_and_deduplicates_crl_evidence(): void
    {
        if (! $this->hasOpenSslCli()) {
            self::markTestSkipped('OpenSSL CLI is required for extension-rich test certificates.');
        }

        $http = OcspTestPki::httpClient(static fn (string $body, string $url): HttpResponse => str_contains($url, 'crl.local')
            ? new HttpResponse(200, 'crl-bytes')
            : new HttpResponse(404, ''));
        $collector = new OpenSslRevocationEvidenceCollector(httpClient: $http);

        $certA = $this->createCertificateDerWithRevocationExtensions('A');
        $certB = $this->createCertificateDerWithRevocationExtensions('B');
        $result = $collector->collect([$certA, $certB]);

        self::assertSame([
            ['ocsp' => [], 'crl' => ['crl-bytes']],
            ['ocsp' => [], 'crl' => ['crl-bytes']],
        ], $result);
        // Neither certificate issued the other, so no OCSP request is made for them.
        self::assertSame(['http://crl.local/one', 'http://crl.local/one'], array_column($http->requests, 'url'));
    }

    public function test_collect_skips_unavailable_crls_and_empty_chain_entries(): void
    {
        if (! $this->hasOpenSslCli()) {
            self::markTestSkipped('OpenSSL CLI is required for extension-rich test certificates.');
        }

        $http = OcspTestPki::httpClient(static fn (): HttpResponse => new HttpResponse(404, ''));
        $collector = new OpenSslRevocationEvidenceCollector(httpClient: $http);
        $certA = $this->createCertificateDerWithRevocationExtensions('A');
        $certB = $this->createCertificateDerWithRevocationExtensions('B');

        self::assertSame([
            ['ocsp' => [], 'crl' => []],
            ['ocsp' => [], 'crl' => []],
            ['ocsp' => [], 'crl' => []],
        ], $collector->collect([$certA, '', $certB]));
    }

    public function test_collect_stores_the_ocsp_response_of_the_real_issuer_without_nonce(): void
    {
        $pki = $this->pki();
        $http = OcspTestPki::httpClient(static fn (string $request): HttpResponse => new HttpResponse(200, $pki->respond($request)));
        $runner = $this->createMock(ProcessRunnerInterface::class);
        $runner->expects(self::never())->method('run');

        $result = (new OpenSslRevocationEvidenceCollector(httpClient: $http, processRunner: $runner))
            ->collect([$pki->der('leaf'), $pki->der('ca'), $pki->der('root')]);

        self::assertCount(1, $result[0]['ocsp']);
        self::assertSame([], $result[1]['ocsp']);
        self::assertSame([], $result[2]['ocsp']);
        self::assertCount(1, $http->requests);
        self::assertSame('POST', $http->requests[0]['method']);
        self::assertSame('http://ocsp.example.test/', $http->requests[0]['url']);
        self::assertContains('Content-Type: application/ocsp-request', $http->requests[0]['headers']);
        self::assertStringNotContainsString("\x2B\x06\x01\x05\x05\x07\x30\x01\x02", $http->requests[0]['body']);

        $request = OcspRequest::forCertificate($pki->der('leaf'), $pki->der('ca'));
        $response = OcspResponse::parse($result[0]['ocsp'][0]);
        self::assertNotNull($request);
        self::assertNotNull($response);
        self::assertSame('good', $request->findStatus($response)?->status);
    }

    public function test_collect_deduplicates_identical_responses_and_skips_unusable_ones(): void
    {
        $pki = $this->pki();
        $leafOnly = OcspRequest::forCertificate($pki->der('twoResponders'), $pki->der('ca'));
        $other = OcspRequest::forCertificate($pki->der('leafWithoutOcsp'), $pki->der('ca'));
        self::assertNotNull($leafOnly);
        self::assertNotNull($other);
        $fixed = $pki->respond($leafOnly->der, certificate: 'twoResponders');
        $unrelated = $pki->respond($other->der, certificate: 'leafWithoutOcsp');

        $answers = [
            [new HttpResponse(200, $fixed), new HttpResponse(200, $fixed)],
            [new HttpResponse(200, $unrelated), new HttpResponse(200, "\x30\x03\x0A\x01\x06")],
            [new HttpResponse(500, $fixed), new HttpResponse(0, '', 'timeout')],
        ];
        $expected = [[$fixed], [], []];

        foreach ($answers as $index => $pair) {
            $http = OcspTestPki::httpClient(static fn (string $request, string $url): HttpResponse => str_contains($url, 'ocsp-a') ? $pair[0] : $pair[1]);
            $result = (new OpenSslRevocationEvidenceCollector(httpClient: $http))
                ->collect([$pki->der('twoResponders'), $pki->der('ca')]);

            self::assertSame($expected[$index], $result[0]['ocsp']);
            self::assertCount(2, $http->requests);
        }
    }

    public function test_collect_ocsp_internal_returns_empty_when_urls_or_issuers_are_missing(): void
    {
        $collector = new OpenSslRevocationEvidenceCollector;
        $method = new \ReflectionMethod($collector, 'collectOcspResponses');

        self::assertSame([], $method->invoke($collector, 'cert-der', [], ['http://ocsp.local']));
        self::assertSame([], $method->invoke($collector, 'cert-der', ['issuer-der'], []));
        self::assertSame([], $method->invoke($collector, '', ['issuer-der'], ['http://ocsp.local']));
        self::assertSame([], $method->invoke($collector, 'cert-der', ['issuer-der'], ['http://ocsp.local']));
    }

    private function createCertificateDerWithRevocationExtensions(string $cn): string
    {
        $dir = sys_get_temp_dir().'/signer-php-revocation-cert-'.uniqid('', true);
        self::assertTrue(mkdir($dir, 0775, true) || is_dir($dir));

        $keyPath = $dir.'/key.pem';
        $certPath = $dir.'/cert.pem';
        $configPath = $dir.'/openssl.cnf';

        $config = <<<CFG
[ req ]
distinguished_name = req_distinguished_name
x509_extensions = v3_req
prompt = no

[ req_distinguished_name ]
CN = Revocation {$cn}

[ v3_req ]
authorityInfoAccess = OCSP;URI:http://ocsp.local/one
crlDistributionPoints = URI:http://crl.local/one
CFG;
        file_put_contents($configPath, $config);

        $command = sprintf(
            'openssl req -x509 -newkey rsa:1024 -keyout %s -out %s -days 1 -nodes -config %s 2>/dev/null',
            escapeshellarg($keyPath),
            escapeshellarg($certPath),
            escapeshellarg($configPath),
        );
        exec($command, $output, $code);
        self::assertSame(0, $code);

        $pem = file_get_contents($certPath);
        self::assertIsString($pem);
        $der = $this->pemToDer($pem);

        @unlink($keyPath);
        @unlink($certPath);
        @unlink($configPath);
        @rmdir($dir);

        return $der;
    }

    private function pemToDer(string $pem): string
    {
        $base64 = preg_replace('/-----BEGIN CERTIFICATE-----|-----END CERTIFICATE-----|\s+/', '', $pem);
        self::assertIsString($base64);
        $der = base64_decode($base64, true);
        self::assertIsString($der);

        return $der;
    }

    private function hasOpenSslCli(): bool
    {
        exec('command -v openssl >/dev/null 2>&1', $output, $code);

        return $code === 0;
    }
}
