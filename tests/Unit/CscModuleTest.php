<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Tests\Unit;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SignerPHP\PdfSigner\Application\DTO\ExternalSigningPayload;
use SignerPHP\PdfSigner\Application\DTO\HashAlgorithm;
use SignerPHP\PdfSigner\Application\DTO\SignatureAlgorithm;
use SignerPHP\PdfSigner\Application\DTO\SignatureEncoding;
use SignerPHP\PdfSigner\Application\DTO\SigningCertificateDto;
use SignerPHP\PdfSigner\Application\DTO\SigningInputType;
use SignerPHP\PdfSigner\Domain\Exception\SignerException;
use SignerPHP\PdfSigner\Infrastructure\Native\Contract\HttpClientInterface;
use SignerPHP\PdfSigner\Infrastructure\Native\ValueObject\HttpResponse;
use SignerPHP\PdfSigner\Infrastructure\Remote\Csc\CscCertificateDiscovery;
use SignerPHP\PdfSigner\Infrastructure\Remote\Csc\CscClient;
use SignerPHP\PdfSigner\Infrastructure\Remote\Csc\CscSignatureProvider;
use SignerPHP\PdfSigner\Infrastructure\Remote\Csc\CscSignHashOutcomeUnknownException;
use SignerPHP\PdfSigner\Presentation\Signer;
use SignerPHP\PdfSigner\RemoteSigning\DTO\RemoteCertificate;
use SignerPHP\PdfSigner\Tests\Support\PdfFixtureFactory;
use SignerPHP\PdfSigner\Tests\Support\Pkcs12Fixture;

final class CscModuleTest extends TestCase
{
    public function test_discovers_a_usable_rsa_certificate_through_the_csc_v1_contract(): void
    {
        $bundle = Pkcs12Fixture::load();
        $calls = [];
        $client = self::client(function ($operation, $data, $headers) use ($bundle, &$calls) {
            $calls[] = [$operation, $data];
            self::assertContains('Authorization: Bearer synthetic-token', $headers);

            return match ($operation) {
                'info' => ['specs' => '1.0.4.0'],
                'credentials/list' => ['credentialIDs' => ['lab/signer']],
                'credentials/info' => self::credentialInfo($bundle['cert']),
                default => throw new \LogicException('Unexpected CSC operation'),
            };
        });

        $discovered = (new CscCertificateDiscovery($client))->certificates();
        self::assertCount(1, $discovered);
        self::assertSame('lab/signer', $discovered[0]->identifier);
        self::assertSame(
            openssl_x509_fingerprint($bundle['cert'], 'sha256'),
            openssl_x509_fingerprint($discovered[0]->certificate->certificatePem, 'sha256'),
        );
        self::assertSame(['credentialID' => 'lab/signer', 'certificates' => 'chain'], $calls[2][1]);
    }

    public function test_an_empty_credential_list_is_a_valid_discovery_result(): void
    {
        $client = self::client(fn ($operation) => $operation === 'info'
            ? ['specs' => '1.0.4.0'] : ['credentialIDs' => []]);

        self::assertSame([], (new CscCertificateDiscovery($client))->certificates());
    }

    public function test_signs_a_valid_pades_b_b_pdf_with_only_remote_private_key_access(): void
    {
        $bundle = Pkcs12Fixture::load();
        $calls = [];
        $authorizedHash = null;
        $client = self::client(function ($operation, $data) use ($bundle, &$calls, &$authorizedHash) {
            $calls[] = $operation;
            if ($operation === 'info') {
                return ['specs' => '1.0.4.0'];
            }
            if ($operation === 'credentials/info') {
                return self::credentialInfo($bundle['cert']);
            }
            if ($operation === 'credentials/authorize') {
                self::assertSame('lab/signer', $data['credentialID']);
                self::assertSame(1, $data['numSignatures']);
                self::assertCount(1, $data['hash']);
                $authorizedHash = $data['hash'];

                return ['SAD' => 'synthetic-sad'];
            }

            self::assertSame('signatures/signHash', $operation);
            self::assertSame('synthetic-sad', $data['SAD']);
            self::assertSame('1.2.840.113549.1.1.11', $data['signAlgo']);
            self::assertSame('2.16.840.1.101.3.4.2.1', $data['hashAlgo']);
            self::assertSame($authorizedHash, $data['hash']);

            $digest = base64_decode($data['hash'][0], true);
            self::assertSame(32, strlen($digest));
            $digestInfo = hex2bin('3031300d060960864801650304020105000420').$digest;
            openssl_private_encrypt($digestInfo, $signature, $bundle['pkey'], OPENSSL_PKCS1_PADDING);

            return ['signatures' => [base64_encode($signature)]];
        });

        $credential = (new CscCertificateDiscovery($client))->certificates('lab/signer')[0];
        $builder = Signer::externalSigner()
            ->withPdfContent(PdfFixtureFactory::minimalPdf())
            ->withCertificate($credential->certificate->certificatePem)
            ->withoutDefaultAppearance()
            ->withPadesBaselineB();
        $prepared = $builder->prepare();
        $raw = (new CscSignatureProvider($client))->sign($prepared->payload, $credential);
        $pdf = $builder->complete($prepared->state, $raw->bytes);
        $result = Signer::validation()->withPdfContent($pdf)->disableTrustChainValidation()->validate();

        self::assertTrue($result->allValid);
        self::assertStringContainsString('/ETSI.CAdES.detached', $pdf);
        self::assertSame(
            ['info', 'credentials/info', 'info', 'credentials/info', 'credentials/authorize', 'signatures/signHash'],
            $calls,
        );
    }

    public function test_rejects_certificate_substitution_before_remote_authorization(): void
    {
        $bundle = Pkcs12Fixture::load();
        $client = self::client(fn ($operation) => match ($operation) {
            'info' => ['specs' => '1.0.4.0'],
            'credentials/info' => self::credentialInfo(self::otherCertificate()),
            default => throw new \LogicException('Authorization must not execute'),
        });

        expect(fn () => (new CscSignatureProvider($client))->sign(
            self::payload(),
            new RemoteCertificate('lab/signer', new SigningCertificateDto($bundle['cert'])),
        ))->toThrow(SignerException::class, 'certificate changed');
    }

    public function test_rejects_a_signature_for_a_different_digest(): void
    {
        $bundle = Pkcs12Fixture::load();
        $client = self::client(function ($operation) use ($bundle) {
            if ($operation === 'info') {
                return ['specs' => '1.0.4.0'];
            }
            if ($operation === 'credentials/info') {
                return self::credentialInfo($bundle['cert']);
            }
            if ($operation === 'credentials/authorize') {
                return ['SAD' => 'synthetic-sad'];
            }

            $digestInfo = hex2bin('3031300d060960864801650304020105000420').random_bytes(32);
            openssl_private_encrypt($digestInfo, $signature, $bundle['pkey'], OPENSSL_PKCS1_PADDING);

            return ['signatures' => [base64_encode($signature)]];
        });

        expect(fn () => (new CscSignatureProvider($client))->sign(
            self::payload(),
            new RemoteCertificate('lab/signer', new SigningCertificateDto($bundle['cert'])),
        ))->toThrow(CscSignHashOutcomeUnknownException::class, 'reconcile');
    }

    #[DataProvider('unsupportedPayloads')]
    public function test_rejects_unsupported_crypto_inputs_without_a_remote_call(
        SigningInputType $inputType,
        HashAlgorithm $hashAlgorithm,
        SignatureAlgorithm $signatureAlgorithm,
        SignatureEncoding $encoding,
    ): void {
        $calls = 0;
        $client = self::client(function () use (&$calls) {
            $calls++;

            throw new \LogicException('No network access expected');
        });
        $payload = new ExternalSigningPayload(base64_encode(random_bytes(32)), $inputType, $hashAlgorithm, $signatureAlgorithm, $encoding);
        $credential = new RemoteCertificate('lab/signer', new SigningCertificateDto('not-needed'));

        expect(fn () => (new CscSignatureProvider($client))->sign($payload, $credential))
            ->toThrow(SignerException::class, 'CSC v1');
        self::assertSame(0, $calls);
    }

    public static function unsupportedPayloads(): array
    {
        return [
            'input is original data' => [SigningInputType::Data, HashAlgorithm::Sha256, SignatureAlgorithm::RsaPkcs1V15, SignatureEncoding::RsaPkcs1],
            'hash is SHA-512' => [SigningInputType::Digest, HashAlgorithm::Sha512, SignatureAlgorithm::RsaPkcs1V15, SignatureEncoding::RsaPkcs1],
            'signature uses ECDSA' => [SigningInputType::Digest, HashAlgorithm::Sha256, SignatureAlgorithm::Ecdsa, SignatureEncoding::EcdsaDer],
            'signature output encoding is DER' => [SigningInputType::Digest, HashAlgorithm::Sha256, SignatureAlgorithm::RsaPkcs1V15, SignatureEncoding::EcdsaDer],
        ];
    }

    #[DataProvider('unsupportedVersions')]
    public function test_rejects_unverified_protocol_versions(?string $version): void
    {
        $client = self::client(fn () => ['specs' => $version]);

        expect(fn () => $client->assertVersion())->toThrow(SignerException::class, 'version');
    }

    public static function unsupportedVersions(): array
    {
        return [
            'CSC 2.2 must not be mistaken for v1' => ['2.2.0.0'],
            'empty version' => [''],
            'version omitted' => [null],
        ];
    }

    #[DataProvider('invalidHttpResponses')]
    public function test_rejects_http_errors_and_malformed_json_without_exposing_response_body(int $status, string $body, string $message): void
    {
        $client = new CscClient(self::transport(fn () => new HttpResponse($status, $body)), 'https://csc.example');

        expect(fn () => $client->post('info'))->toThrow(SignerException::class, $message);
    }

    public static function invalidHttpResponses(): array
    {
        return [
            '401 unauthorized' => [401, 'private-token', 'HTTP 401'],
            '403 forbidden' => [403, 'token-secret', 'HTTP 403'],
            'broken JSON' => [200, '{', 'invalid JSON'],
            'top-level list' => [200, '[]', 'invalid response'],
        ];
    }

    public function test_never_retries_an_authentication_failure(): void
    {
        $calls = 0;
        $client = new CscClient(self::transport(function () use (&$calls) {
            $calls++;

            return new HttpResponse(403, 'token-secret');
        }), 'https://csc.example');

        expect(fn () => $client->post('signatures/signHash'))
            ->toThrow(CscSignHashOutcomeUnknownException::class, 'reconcile');
        self::assertSame(1, $calls);
    }

    #[DataProvider('uncertainSignHashResponses')]
    public function test_signhash_errors_are_typed_as_uncertain_without_retry(int $status, string $body): void
    {
        $calls = 0;
        $client = new CscClient(self::transport(function () use ($status, $body, &$calls) {
            $calls++;

            return new HttpResponse($status, $body);
        }), 'https://csc.example');

        expect(fn () => $client->post('signatures/signHash'))
            ->toThrow(CscSignHashOutcomeUnknownException::class, 'reconcile');
        self::assertSame(1, $calls);
    }

    public static function uncertainSignHashResponses(): array
    {
        return [
            'connection lost' => [0, ''],
            'gateway error' => [503, 'unavailable'],
            'invalid JSON after 200' => [200, '{'],
            'unexpected list after 200' => [200, '[]'],
        ];
    }

    public function test_transport_exceptions_after_signhash_submission_are_uncertain(): void
    {
        $calls = 0;
        $client = new CscClient(self::transport(function () use (&$calls) {
            $calls++;
            throw new \RuntimeException('synthetic transport interruption');
        }), 'https://csc.example');

        expect(fn () => $client->post('signatures/signHash'))
            ->toThrow(CscSignHashOutcomeUnknownException::class, 'reconcile');
        self::assertSame(1, $calls);
    }

    public function test_pre_submission_discovery_failure_is_not_classified_uncertain(): void
    {
        $client = new CscClient(self::transport(fn () => new HttpResponse(503, 'unavailable')), 'https://csc.example');
        try {
            $client->post('credentials/info');
            self::fail('Expected pre-submission failure');
        } catch (SignerException $exception) {
            self::assertNotInstanceOf(CscSignHashOutcomeUnknownException::class, $exception);
        }
    }

    #[DataProvider('invalidSigningResponses')]
    public function test_rejects_bad_sad_and_signhash_responses_without_submitting_an_extra_signature(string $failure, int $expectedSignCalls): void
    {
        $bundle = Pkcs12Fixture::load();
        $signCalls = 0;
        $client = self::client(function ($operation) use ($bundle, $failure, &$signCalls) {
            if ($operation === 'info') {
                return ['specs' => '1.0.4.0'];
            }
            if ($operation === 'credentials/info') {
                return self::credentialInfo($bundle['cert']);
            }
            if ($operation === 'credentials/authorize') {
                return match ($failure) {
                    'missing SAD' => ['authorization' => 'unexpected'],
                    'empty SAD' => ['SAD' => ''],
                    default => ['SAD' => 'synthetic-sad'],
                };
            }

            $signCalls++;

            return match ($failure) {
                'missing signatures' => ['signature' => 'wrong shape'],
                'too many signatures' => ['signatures' => ['one', 'two']],
                'malformed signature base64' => ['signatures' => ['***']],
                default => throw new \LogicException('Unexpected signHash operation'),
            };
        });
        $credential = new RemoteCertificate('lab/signer', new SigningCertificateDto($bundle['cert']));

        try {
            (new CscSignatureProvider($client))->sign(self::payload(), $credential);
            self::fail('Expected CSC signing failure');
        } catch (SignerException $exception) {
            if ($expectedSignCalls === 0) {
                self::assertNotInstanceOf(CscSignHashOutcomeUnknownException::class, $exception);
            } else {
                self::assertInstanceOf(CscSignHashOutcomeUnknownException::class, $exception);
            }
        }
        self::assertSame($expectedSignCalls, $signCalls);
    }

    public static function invalidSigningResponses(): array
    {
        return [
            'missing SAD' => ['missing SAD', 0],
            'empty SAD' => ['empty SAD', 0],
            'missing signatures list' => ['missing signatures', 1],
            'more than one signature' => ['too many signatures', 1],
            'malformed raw signature' => ['malformed signature base64', 1],
        ];
    }

    #[DataProvider('unusableCredentialCases')]
    public function test_rejects_unusable_credential_information(string $case): void
    {
        $bundle = Pkcs12Fixture::load();
        $info = self::credentialInfo($bundle['cert']);
        switch ($case) {
            case 'disabled':
                $info['key']['status'] = 'disabled';
                break;
            case 'unsupported algorithm':
                $info['key']['algo'] = ['1.2.840.10045.4.3.2'];
                break;
            case 'generic RSA OID only':
                $info['key']['algo'] = ['1.2.840.113549.1.1.1'];
                break;
            case 'missing certificate':
                unset($info['cert']);
                break;
            case 'invalid X.509':
                $info['cert']['certificates'] = [base64_encode('not X509')];
                break;
        }
        $client = self::client(fn ($operation) => $operation === 'info' ? ['specs' => '1.0.4.0'] : $info);

        expect(fn () => (new CscCertificateDiscovery($client))->certificates('lab/signer'))
            ->toThrow(SignerException::class);
    }

    public static function unusableCredentialCases(): array
    {
        return [
            'disabled key' => ['disabled'],
            'unsupported ECDSA algorithm' => ['unsupported algorithm'],
            'generic RSA OID does not claim SHA-256' => ['generic RSA OID only'],
            'missing certificate' => ['missing certificate'],
            'invalid X.509 DER' => ['invalid X.509'],
        ];
    }

    #[DataProvider('unsafeEndpoints')]
    public function test_refuses_unsafe_csc_endpoint_configuration(string $url): void
    {
        $http = self::transport(fn () => throw new \LogicException('Unexpected network access'));

        expect(fn () => new CscClient($http, $url))
            ->toThrow(\InvalidArgumentException::class, 'HTTPS');
    }

    public static function unsafeEndpoints(): array
    {
        return [
            'insecure remote HTTP' => ['http://signing.example'],
            'embedded credentials in URL' => ['https://user:password@signing.example'],
            'not a URL' => ['not a URL'],
        ];
    }

    public function test_rejects_invalid_timeout_and_unsupported_operations(): void
    {
        $http = self::transport(fn () => throw new \LogicException('Unexpected network access'));

        expect(fn () => new CscClient($http, 'https://csc.example', timeoutSeconds: 0))
            ->toThrow(\InvalidArgumentException::class, 'timeout');
        expect(fn () => (new CscClient($http, 'https://csc.example'))->post('signatures/signPolling'))
            ->toThrow(\InvalidArgumentException::class, 'Unsupported');
    }

    #[DataProvider('invalidCredentialLists')]
    public function test_rejects_malformed_credential_enumeration(array $response): void
    {
        $client = self::client(fn ($operation) => $operation === 'info' ? ['specs' => '1.0.4.0'] : $response);

        expect(fn () => (new CscCertificateDiscovery($client))->certificates())
            ->toThrow(SignerException::class);
    }

    public static function invalidCredentialLists(): array
    {
        return [
            'not a list' => [['credentialIDs' => ['bad' => 'not a list']]],
            'null identifier' => [['credentialIDs' => [null]]],
            'blank identifier' => [['credentialIDs' => ['']]],
        ];
    }

    public function test_rejects_blank_explicit_credential_identifier(): void
    {
        $client = self::client(fn () => ['specs' => '1.0.4.0']);

        expect(fn () => (new CscCertificateDiscovery($client))->certificates(' '))
            ->toThrow(SignerException::class, 'ID');
    }

    #[DataProvider('invalidCertificateTypes')]
    public function test_rejects_ec_and_invalid_der_certificates(string $case): void
    {
        $info = self::credentialInfo(Pkcs12Fixture::load()['cert']);
        if ($case === 'ec public key') {
            $key = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']);
            $csr = openssl_csr_new(['commonName' => 'Unsupported EC lab signer'], $key);
            $x509 = openssl_csr_sign($csr, null, $key, 1);
            openssl_x509_export($x509, $pem);
            $info = self::credentialInfo($pem);
        } else {
            $info['cert']['certificates'] = ['!not-base64!'];
        }
        $client = self::client(fn ($operation) => $operation === 'info' ? ['specs' => '1.0.4.0'] : $info);

        expect(fn () => (new CscCertificateDiscovery($client))->certificates('lab/signer'))
            ->toThrow(SignerException::class);
    }

    public static function invalidCertificateTypes(): array
    {
        return [
            'EC key for an RSA-only signing flow' => ['ec public key'],
            'malformed DER base64' => ['bad DER'],
        ];
    }

    #[DataProvider('invalidSigningRequests')]
    public function test_rejects_incorrect_digest_or_credential_before_any_remote_call(string $digest, string $identifier): void
    {
        $calls = 0;
        $client = self::client(function () use (&$calls) {
            $calls++;

            throw new \LogicException('Unexpected remote authorization');
        });
        $payload = new ExternalSigningPayload(base64_encode($digest), SigningInputType::Digest, HashAlgorithm::Sha256, SignatureAlgorithm::RsaPkcs1V15, SignatureEncoding::RsaPkcs1);
        $credential = new RemoteCertificate($identifier, new SigningCertificateDto('not-needed'));

        expect(fn () => (new CscSignatureProvider($client))->sign($payload, $credential))
            ->toThrow(SignerException::class, 'CSC signing requires');
        self::assertSame(0, $calls);
    }

    public static function invalidSigningRequests(): array
    {
        return [
            'incorrect digest length' => ['short', 'lab/signer'],
            'missing credential' => [str_repeat('a', 32), ''],
        ];
    }

    public function test_refuses_changed_signing_capabilities_before_authorization(): void
    {
        $bundle = Pkcs12Fixture::load();
        $authorizationCalls = 0;
        $client = self::client(function ($operation) use ($bundle, &$authorizationCalls) {
            if ($operation === 'info') {
                return ['specs' => '1.0.4.0'];
            }
            if ($operation === 'credentials/info') {
                $info = self::credentialInfo($bundle['cert']);
                $info['key']['algo'] = ['1.2.840.10045.4.3.2'];

                return $info;
            }
            $authorizationCalls++;

            return ['SAD' => 'should-not-be-issued'];
        });

        expect(fn () => (new CscSignatureProvider($client))->sign(
            self::payload(),
            new RemoteCertificate('lab/signer', new SigningCertificateDto($bundle['cert'])),
        ))->toThrow(SignerException::class, 'cannot sign');
        self::assertSame(0, $authorizationCalls);
    }

    public function test_refuses_invalid_local_signer_certificate(): void
    {
        $bundle = Pkcs12Fixture::load();
        $client = self::client(fn ($operation) => $operation === 'info'
            ? ['specs' => '1.0.4.0'] : self::credentialInfo($bundle['cert']));

        expect(fn () => (new CscSignatureProvider($client))->sign(
            self::payload(),
            new RemoteCertificate('lab/signer', new SigningCertificateDto('not-a-certificate')),
        ))->toThrow(SignerException::class, 'certificate changed');
    }

    private static function payload(): ExternalSigningPayload
    {
        return new ExternalSigningPayload(
            base64_encode(random_bytes(32)),
            SigningInputType::Digest,
            HashAlgorithm::Sha256,
            SignatureAlgorithm::RsaPkcs1V15,
            SignatureEncoding::RsaPkcs1,
        );
    }

    /** @return array<string, mixed> */
    private static function credentialInfo(string $pem): array
    {
        $der = base64_decode(preg_replace('/-----[^-]+-----|\s+/', '', $pem) ?? '', true);

        return [
            'key' => ['status' => 'enabled', 'algo' => [CscCertificateDiscovery::SHA256_RSA_OID]],
            'cert' => ['certificates' => [base64_encode($der)]],
            'SCAL' => '2',
        ];
    }

    private static function otherCertificate(): string
    {
        $key = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048]);
        $csr = openssl_csr_new(['commonName' => 'Other CSC signer'], $key);
        $x509 = openssl_csr_sign($csr, null, $key, 1);
        openssl_x509_export($x509, $pem);

        return $pem;
    }

    private static function client(callable $responder): CscClient
    {
        return new CscClient(self::transport(function ($method, $url, $headers, $body) use ($responder) {
            self::assertSame('POST', $method);
            self::assertStringStartsWith('https://csc.example/csc/v1/', $url);
            $operation = substr($url, strlen('https://csc.example/csc/v1/'));

            return new HttpResponse(200, json_encode($responder($operation, json_decode($body, true), $headers), JSON_THROW_ON_ERROR));
        }), 'https://csc.example', 'synthetic-token');
    }

    private static function transport(callable $handler): HttpClientInterface
    {
        return new class($handler) implements HttpClientInterface
        {
            public function __construct(private $handler) {}

            public function request(string $method, string $url, array $headers = [], string $body = '', int $timeoutSeconds = 10, bool $followRedirects = false): HttpResponse
            {
                return ($this->handler)($method, $url, $headers, $body, $timeoutSeconds, $followRedirects);
            }
        };
    }
}
