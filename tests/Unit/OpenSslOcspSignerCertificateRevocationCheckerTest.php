<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Tests\Unit;

use PHPUnit\Framework\TestCase;
use SignerPHP\PdfSigner\Domain\Exception\SignProcessException;
use SignerPHP\PdfSigner\Infrastructure\Native\Contract\HttpClientInterface;
use SignerPHP\PdfSigner\Infrastructure\Native\Contract\ProcessRunnerInterface;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\Ocsp\OcspCertificate;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\Ocsp\OcspRequest;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\OpenSslOcspSignerCertificateRevocationChecker;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\X509ExtensionUrlExtractor;
use SignerPHP\PdfSigner\Infrastructure\Native\ValueObject\HttpResponse;
use SignerPHP\PdfSigner\Tests\Support\OcspTestPki;

final class OpenSslOcspSignerCertificateRevocationCheckerTest extends TestCase
{
    private const NONCE_EXTENSION = "\x06\x09\x2B\x06\x01\x05\x05\x07\x30\x01\x02\x04\x12\x04\x10";

    private static OcspTestPki $pki;

    public static function setUpBeforeClass(): void
    {
        if (! OcspTestPki::opensslAvailable()) {
            self::markTestSkipped('The OpenSSL CLI is required to produce OCSP response fixtures.');
        }

        self::$pki = new OcspTestPki;
    }

    public function test_good_response_passes_and_the_request_is_a_nonced_ocsp_post(): void
    {
        $http = $this->responder(fn (string $request): string => self::$pki->respond($request));

        $this->checker($http)->assertNotRevoked(self::$pki->pem('leaf'), $this->chain());

        self::assertCount(1, $http->requests);
        $request = $http->requests[0];
        self::assertSame('POST', $request['method']);
        self::assertSame('http://ocsp.example.test/', $request['url']);
        self::assertContains('Content-Type: application/ocsp-request', $request['headers']);
        self::assertSame(10, $request['timeout']);
        self::assertStringContainsString(self::NONCE_EXTENSION, $request['body']);
    }

    public function test_verified_revoked_response_from_the_issuer_is_fatal(): void
    {
        $http = $this->responder(fn (string $request): string => self::$pki->respond($request, 'revoked'));

        try {
            $this->checker($http)->assertNotRevoked(self::$pki->pem('leaf'), $this->chain());
            self::fail('A revoked certificate must not be accepted.');
        } catch (SignProcessException $exception) {
            self::assertStringContainsString('"Revocation Test Signer" is revoked', $exception->getMessage());
            self::assertStringContainsString('http://ocsp.example.test/', $exception->getMessage());
            self::assertMatchesRegularExpression('/ at \w{3} \d{1,2} \d{2}:\d{2}:\d{2} \d{4} GMT \(keyCompromise\)\.$/', $exception->getMessage());
        }
    }

    public function test_revoked_response_from_a_delegated_responder_with_ocsp_signing_is_fatal(): void
    {
        $http = $this->responder(fn (string $request): string => self::$pki->respond($request, 'revoked', signer: 'responder'));

        $this->expectException(SignProcessException::class);
        $this->expectExceptionMessage('is revoked');
        $this->checker($http)->assertNotRevoked(self::$pki->pem('leaf'), $this->chain());
    }

    public function test_revoked_response_from_a_delegated_responder_without_ocsp_signing_is_ignored(): void
    {
        $http = $this->responder(fn (string $request): string => self::$pki->respond($request, 'revoked', signer: 'responderWithoutEku'));

        $this->checker($http)->assertNotRevoked(self::$pki->pem('leaf'), [...$this->chain(), self::$pki->pem('responderWithoutEku')]);

        self::assertCount(1, $http->requests);
    }

    public function test_revoked_response_identifying_the_responder_by_key_is_fatal(): void
    {
        $http = $this->responder(fn (string $request): string => self::$pki->respond($request, 'revoked', byKey: true));

        $this->expectException(SignProcessException::class);
        $this->checker($http)->assertNotRevoked(self::$pki->pem('leaf'), $this->chain());
    }

    public function test_revoked_response_whose_responder_id_names_another_certificate_is_ignored(): void
    {
        $caKey = sha1((string) OcspCertificate::fromPem(self::$pki->pem('ca'))?->publicKeyBits, true);
        $responderKey = sha1((string) OcspCertificate::fromPem(self::$pki->pem('responder'))?->publicKeyBits, true);
        // Signed by the issuer, but the ResponderID claims the delegated responder.
        $http = $this->responder(fn (string $request): string => self::$pki->resign(
            self::$pki->respond($request, 'revoked', byKey: true),
            // Only the ResponderID byKey element; the CertID carries the same issuer key hash.
            static fn (string $tbs): string => str_replace("\xA2\x16\x04\x14".$caKey, "\xA2\x16\x04\x14".$responderKey, $tbs),
        ));

        $this->checker($http)->assertNotRevoked(self::$pki->pem('leaf'), [...$this->chain(), self::$pki->pem('responder')]);

        self::assertCount(1, $http->requests);
    }

    public function test_revoked_response_without_a_valid_signature_is_ignored(): void
    {
        $forgers = [
            // Same issuer DN as the real CA, different key.
            fn (string $request): string => self::$pki->respond($request, 'revoked', signer: 'rogueCa'),
            // Correctly issued response whose signature was altered in transit.
            fn (string $request): string => OcspTestPki::corruptSignature(self::$pki->respond($request, 'revoked')),
            // Signature algorithm this checker cannot verify (sha256WithRSA relabelled as RSASSA-PSS).
            fn (string $request): string => str_replace(
                "\x2A\x86\x48\x86\xF7\x0D\x01\x01\x0B",
                "\x2A\x86\x48\x86\xF7\x0D\x01\x01\x0A",
                self::$pki->respond($request, 'revoked'),
            ),
        ];

        foreach ($forgers as $forger) {
            $this->checker($this->responder($forger))->assertNotRevoked(self::$pki->pem('leaf'), $this->chain());
        }

        $this->addToAssertionCount(count($forgers));
    }

    public function test_stale_or_premature_revoked_response_is_ignored(): void
    {
        $stale = [
            // nextUpdate more than 5 minutes in the past.
            fn (string $request): string => self::$pki->resign(
                self::$pki->respond($request, 'revoked'),
                static fn (string $tbs): string => OcspTestPki::shiftTimes($tbs, -3 * 86400),
            ),
            // thisUpdate more than 5 minutes in the future.
            fn (string $request): string => self::$pki->resign(
                self::$pki->respond($request, 'revoked'),
                static fn (string $tbs): string => OcspTestPki::shiftTimes($tbs, 3600),
            ),
            // No nextUpdate and older than one day.
            fn (string $request): string => self::$pki->resign(
                self::$pki->respond($request, 'revoked', days: null),
                static fn (string $tbs): string => OcspTestPki::shiftTimes($tbs, -2 * 86400),
            ),
        ];

        foreach ($stale as $responder) {
            $this->checker($this->responder($responder))->assertNotRevoked(self::$pki->pem('leaf'), $this->chain());
        }

        $this->addToAssertionCount(count($stale));
    }

    public function test_recent_revoked_response_without_next_update_is_fatal(): void
    {
        $http = $this->responder(fn (string $request): string => self::$pki->resign(
            self::$pki->respond($request, 'revoked', days: null),
            static fn (string $tbs): string => OcspTestPki::shiftTimes($tbs, -3600),
        ));

        $this->expectException(SignProcessException::class);
        $this->checker($http)->assertNotRevoked(self::$pki->pem('leaf'), $this->chain());
    }

    public function test_revoked_response_answering_another_nonce_is_ignored(): void
    {
        $http = $this->responder(fn (string $request): string => self::$pki->resign(
            self::$pki->respond($request, 'revoked'),
            static fn (string $tbs): string => str_replace(
                substr($tbs, strpos($tbs, self::NONCE_EXTENSION) + strlen(self::NONCE_EXTENSION), 16),
                random_bytes(16),
                $tbs,
            ),
        ));

        $this->checker($http)->assertNotRevoked(self::$pki->pem('leaf'), $this->chain());

        self::assertCount(1, $http->requests);
    }

    public function test_revoked_response_from_a_responder_without_nonce_support_is_fatal(): void
    {
        // The responder ignores the nonce: answer a request that has none.
        $withoutNonce = OcspRequest::forCertificate(self::$pki->der('leaf'), self::$pki->der('ca'));
        self::assertNotNull($withoutNonce);
        $http = $this->responder(fn (): string => self::$pki->respond($withoutNonce->der, 'revoked'));

        $this->expectException(SignProcessException::class);
        $this->checker($http)->assertNotRevoked(self::$pki->pem('leaf'), $this->chain());
    }

    public function test_response_about_another_certificate_or_not_successful_is_ignored(): void
    {
        $other = OcspRequest::forCertificate(self::$pki->der('leafWithoutOcsp'), self::$pki->der('ca'));
        self::assertNotNull($other);
        $answers = [
            fn (): HttpResponse => new HttpResponse(200, self::$pki->respond($other->der, 'revoked', certificate: 'leafWithoutOcsp')),
            fn (): HttpResponse => new HttpResponse(200, "\x30\x03\x0A\x01\x06"), // unauthorized
            fn (): HttpResponse => new HttpResponse(200, 'not DER'),
            fn (): HttpResponse => new HttpResponse(500, 'error'),
            fn (): HttpResponse => new HttpResponse(200, ''),
            fn (): HttpResponse => new HttpResponse(0, '', 'Could not resolve host'),
        ];

        foreach ($answers as $answer) {
            $this->checker(OcspTestPki::httpClient($answer))->assertNotRevoked(self::$pki->pem('leaf'), $this->chain());
        }

        $this->addToAssertionCount(count($answers));
    }

    public function test_every_responder_is_asked_and_any_verified_revocation_wins(): void
    {
        $http = $this->responder(fn (string $request, string $url): string => self::$pki->respond(
            $request,
            str_contains($url, 'ocsp-b') ? 'revoked' : 'good',
            certificate: 'twoResponders',
        ));

        try {
            $this->checker($http)->assertNotRevoked(self::$pki->pem('twoResponders'), $this->chain());
            self::fail('A revocation reported by the second responder must not be ignored.');
        } catch (SignProcessException $exception) {
            self::assertStringContainsString('http://ocsp-b.example.test/', $exception->getMessage());
        }

        self::assertSame(['http://ocsp-a.example.test/', 'http://ocsp-b.example.test/'], array_column($http->requests, 'url'));
    }

    public function test_good_from_every_responder_passes(): void
    {
        $http = $this->responder(fn (string $request): string => self::$pki->respond($request, certificate: 'twoResponders'));

        $this->checker($http)->assertNotRevoked(self::$pki->pem('twoResponders'), $this->chain());

        self::assertCount(2, $http->requests);
    }

    public function test_uses_the_certificate_that_actually_issued_the_signer_when_ca_names_collide(): void
    {
        self::assertSame(
            openssl_x509_parse(self::$pki->pem('ca'))['subject'],
            openssl_x509_parse(self::$pki->pem('rogueCa'))['subject'],
        );
        $http = $this->responder(fn (string $request): string => self::$pki->respond($request, 'revoked'));

        $this->expectException(SignProcessException::class);
        $this->expectExceptionMessage('is revoked');
        $this->checker($http)->assertNotRevoked(
            self::$pki->pem('leaf'),
            [self::$pki->pem('rogueCa'), self::$pki->pem('rogueRoot'), self::$pki->pem('ca'), self::$pki->pem('root')],
        );
    }

    public function test_skips_the_check_without_url_issuer_trust_anchor_or_certificate(): void
    {
        $http = $this->responder(fn (string $request): string => self::$pki->respond($request, 'revoked'));
        $checker = $this->checker($http);

        $checker->assertNotRevoked(self::$pki->pem('leafWithoutOcsp'), $this->chain());
        $checker->assertNotRevoked(self::$pki->pem('leaf'), []);
        // Issuer present but no self-signed root at all.
        $checker->assertNotRevoked(self::$pki->pem('leaf'), [self::$pki->pem('ca')]);
        // A self-signed root that is not the issuer's: the issuer does not chain to it.
        $checker->assertNotRevoked(self::$pki->pem('leaf'), [self::$pki->pem('ca'), self::$pki->pem('rogueRoot')]);
        $checker->assertNotRevoked('', $this->chain());
        $checker->assertNotRevoked('not a certificate', $this->chain());

        self::assertSame([], $http->requests);
    }

    public function test_a_non_ca_issuer_is_not_trusted(): void
    {
        // The delegated responder (CA:FALSE) "issues" nothing, so it cannot anchor the check.
        $http = $this->responder(fn (string $request): string => self::$pki->respond($request, 'revoked'));
        $checker = $this->checker($http);
        $method = new \ReflectionMethod($checker, 'chainsToTrustAnchor');

        self::assertFalse($method->invoke($checker, self::$pki->pem('responder'), $this->chain(), [self::$pki->pem('root')]));
        self::assertFalse($method->invoke($checker, 'not a certificate', $this->chain(), [self::$pki->pem('root')]));
        self::assertTrue($method->invoke($checker, self::$pki->pem('ca'), $this->chain(), [self::$pki->pem('root')]));
    }

    public function test_process_runner_is_never_used(): void
    {
        $runner = $this->createMock(ProcessRunnerInterface::class);
        $runner->expects(self::never())->method('run');
        $http = $this->responder(fn (string $request): string => self::$pki->respond($request));

        (new OpenSslOcspSignerCertificateRevocationChecker(new X509ExtensionUrlExtractor, $runner, $http))
            ->assertNotRevoked(self::$pki->pem('leaf'), $this->chain());
    }

    /**
     * @return list<string>
     */
    private function chain(): array
    {
        return [self::$pki->pem('ca'), self::$pki->pem('root')];
    }

    private function checker(HttpClientInterface $http): OpenSslOcspSignerCertificateRevocationChecker
    {
        return new OpenSslOcspSignerCertificateRevocationChecker(httpClient: $http);
    }

    /**
     * @param  callable(string, string): string  $responder  request DER and URL to OCSP response DER
     */
    private function responder(callable $responder): HttpClientInterface
    {
        return OcspTestPki::httpClient(static fn (string $request, string $url): HttpResponse => new HttpResponse(200, $responder($request, $url)));
    }
}
