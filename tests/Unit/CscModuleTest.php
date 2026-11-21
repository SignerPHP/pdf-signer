<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Tests\Unit;

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
use SignerPHP\PdfSigner\Presentation\Signer;
use SignerPHP\PdfSigner\RemoteSigning\DTO\RemoteCertificate;
use SignerPHP\PdfSigner\Tests\Support\PdfFixtureFactory;
use SignerPHP\PdfSigner\Tests\Support\Pkcs12Fixture;

final class CscModuleTest extends TestCase
{
    public function test_discovers_an_enabled_rsa_certificate_and_uses_csc_v1_http_contract(): void
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
                default => throw new \LogicException('unexpected call'),
            };
        });
        $certificates = (new CscCertificateDiscovery($client))->certificates();
        self::assertCount(1, $certificates);
        self::assertSame('lab/signer', $certificates[0]->identifier);
        self::assertSame(openssl_x509_fingerprint($bundle['cert'], 'sha256'), openssl_x509_fingerprint($certificates[0]->certificate->certificatePem, 'sha256'));
        self::assertSame(['credentialID' => 'lab/signer', 'certificates' => 'chain'], $calls[2][1]);
    }

    public function test_creates_cryptographically_valid_pades_baseline_b_without_giving_the_pdf_engine_the_private_key(): void
    {
        $bundle = Pkcs12Fixture::load();
        $calls = [];
        $client = self::client(function ($operation, $data) use ($bundle, &$calls) {
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

                return ['SAD' => 'synthetic-sad'];
            }
            self::assertSame('signatures/signHash', $operation);
            self::assertSame('synthetic-sad', $data['SAD']);
            self::assertSame('1.2.840.113549.1.1.11', $data['signAlgo']);
            self::assertSame('2.16.840.1.101.3.4.2.1', $data['hashAlgo']);
            self::assertSame(1, count($data['hash']));
            $digest = base64_decode($data['hash'][0], true);
            self::assertSame(32, strlen($digest));
            $digestInfo = hex2bin('3031300d060960864801650304020105000420').$digest;
            openssl_private_encrypt($digestInfo, $signature, $bundle['pkey'], OPENSSL_PKCS1_PADDING);

            return ['signatures' => [base64_encode($signature)]];
        });
        $certificate = (new CscCertificateDiscovery($client))->certificates('lab/signer')[0];
        $builder = Signer::externalSigner()->withPdfContent(PdfFixtureFactory::minimalPdf())
            ->withCertificate($certificate->certificate->certificatePem)
            ->withoutDefaultAppearance()->withPadesBaselineB();
        $prepared = $builder->prepare();
        $raw = (new CscSignatureProvider($client))->sign($prepared->payload, $certificate);
        $pdf = $builder->complete($prepared->state, $raw->bytes);
        $validation = Signer::validation()->withPdfContent($pdf)->disableTrustChainValidation()->validate();
        self::assertTrue($validation->allValid);
        self::assertStringContainsString('/ETSI.CAdES.detached', $pdf);
        self::assertSame(['info', 'credentials/info', 'info', 'credentials/info', 'credentials/authorize', 'signatures/signHash'], $calls);
    }

    public function test_rejects_a_changed_certificate_before_authorization(): void
    {
        $bundle = Pkcs12Fixture::load();
        $client = self::client(fn ($operation) => match ($operation) {
            'info' => ['specs' => '1.0.4.0'],
            'credentials/info' => self::credentialInfo(self::otherCertificate()),
            default => throw new \LogicException('authorization must not execute'),
        });
        $provider = new CscSignatureProvider($client);
        $certificate = new RemoteCertificate('lab/signer', new SigningCertificateDto($bundle['cert']));
        $this->expectException(SignerException::class);
        $this->expectExceptionMessage('certificate changed');
        $provider->sign(self::payload(), $certificate);
    }

    public function test_rejects_signature_for_another_digest(): void
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
        $this->expectException(SignerException::class);
        $this->expectExceptionMessage('inconsistent');
        (new CscSignatureProvider($client))->sign(self::payload(), new RemoteCertificate('lab/signer', new SigningCertificateDto($bundle['cert'])));
    }

    public function test_rejects_unsupported_algorithms_before_network_requests(): void
    {
        $client = self::client(fn () => throw new \LogicException('unexpected network call'));
        $bad = new ExternalSigningPayload(base64_encode(random_bytes(32)), SigningInputType::Digest, HashAlgorithm::Sha512, SignatureAlgorithm::RsaPkcs1V15, SignatureEncoding::RsaPkcs1);
        $this->expectException(SignerException::class);
        (new CscSignatureProvider($client))->sign($bad, new RemoteCertificate('lab/signer', new SigningCertificateDto('unused')));
    }

    public function test_rejects_invalid_versions_and_malformed_responses(): void
    {
        foreach (['2.2.0.0', '', null] as $version) {
            $client = self::client(fn () => ['specs' => $version]);
            try {
                $client->assertVersion();
                self::fail('Accepted unsupported CSC version');
            } catch (SignerException $e) {
                self::assertStringContainsString('version', $e->getMessage());
            }
        }
        foreach ([new HttpResponse(401, 'private-token'), new HttpResponse(200, '{'), new HttpResponse(200, '[]')] as $response) {
            $http = self::transport(fn () => $response);
            $client = new CscClient($http, 'https://csc.example');
            try {
                $client->post('info');
                self::fail('Accepted invalid CSC HTTP response');
            } catch (SignerException $e) {
                self::assertStringNotContainsString('private-token', $e->getMessage());
            }
        }
    }

    public function test_never_retries_after_authentication_failure(): void
    {
        $count = 0;
        $http = self::transport(function () use (&$count) {
            $count++;

            return new HttpResponse(403, 'token-secret');
        });
        try {
            (new CscClient($http, 'https://csc.example'))->post('signatures/signHash');
            self::fail('Expected rejected request');
        } catch (SignerException $e) {
            self::assertSame(1, $count);
            self::assertStringNotContainsString('token-secret', $e->getMessage());
        }
    }

    public function test_rejects_malformed_sad_and_signature_lists(): void
    {
        $bundle = Pkcs12Fixture::load();
        foreach (['missing sad', 'empty sad', 'missing signatures', 'extra signatures', 'invalid base64'] as $failure) {
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
                        'missing sad' => ['authorization' => 'unexpected'],
                        'empty sad' => ['SAD' => ''],
                        default => ['SAD' => 'synthetic-sad'],
                    };
                }
                $signCalls++;

                return match ($failure) {
                    'missing signatures' => ['signature' => 'wrong shape'],
                    'extra signatures' => ['signatures' => ['one', 'two']],
                    'invalid base64' => ['signatures' => ['***']],
                    default => throw new \LogicException('unexpected signHash'),
                };
            });
            try {
                (new CscSignatureProvider($client))->sign(self::payload(), new RemoteCertificate('lab/signer', new SigningCertificateDto($bundle['cert'])));
                self::fail('Accepted malformed CSC response: '.$failure);
            } catch (SignerException $e) {
                self::assertStringContainsString('CSC', $e->getMessage());
                self::assertSame(in_array($failure, ['missing sad', 'empty sad'], true) ? 0 : 1, $signCalls);
            }
        }
    }

    public function test_rejects_discovery_without_usable_credential_or_certificate(): void
    {
        foreach (['disabled', 'unsupported algorithm', 'missing certificate', 'invalid certificate'] as $failure) {
            $bundle = Pkcs12Fixture::load();
            $info = self::credentialInfo($bundle['cert']);
            if ($failure === 'disabled') {
                $info['key']['status'] = 'disabled';
            } elseif ($failure === 'unsupported algorithm') {
                $info['key']['algo'] = ['1.2.840.10045.4.3.2'];
            } elseif ($failure === 'missing certificate') {
                unset($info['cert']);
            } else {
                $info['cert']['certificates'] = [base64_encode('not X509')];
            }
            $client = self::client(fn ($operation) => $operation === 'info' ? ['specs' => '1.0.4.0'] : $info);
            try {
                (new CscCertificateDiscovery($client))->certificates('lab/signer');
                self::fail('Accepted malformed CSC credential: '.$failure);
            } catch (SignerException $e) {
                self::assertStringContainsString('CSC', $e->getMessage());
            }
        }
    }

    public function test_rejects_invalid_endpoint_configuration_and_unrecognized_operations(): void
    {
        $http = self::transport(fn () => throw new \LogicException('No network access expected'));
        foreach (['http://signing.example', 'https://user:password@signing.example', 'not a URL'] as $baseUrl) {
            try {
                new CscClient($http, $baseUrl);
                self::fail('Accepted unsafe CSC endpoint: '.$baseUrl);
            } catch (\InvalidArgumentException $e) {
                self::assertStringContainsString('HTTPS', $e->getMessage());
            }
        }
        try {
            new CscClient($http, 'https://csc.example', timeoutSeconds: 0);
            self::fail('Accepted non-positive HTTP timeout');
        } catch (\InvalidArgumentException $e) {
            self::assertStringContainsString('timeout', $e->getMessage());
        }
        try {
            (new CscClient($http, 'https://csc.example'))->post('signatures/signPolling');
            self::fail('Accepted an unsupported CSC operation');
        } catch (\InvalidArgumentException $e) {
            self::assertStringContainsString('Unsupported', $e->getMessage());
        }
    }

    public function test_rejects_invalid_credential_selection_and_discovery_lists(): void
    {
        $client = self::client(fn ($operation) => $operation === 'info' ? ['specs' => '1.0.4.0'] : ['credentialIDs' => ['lab/signer']]);
        try {
            (new CscCertificateDiscovery($client))->certificates(' ');
            self::fail('Accepted an empty credential identifier');
        } catch (SignerException $e) {
            self::assertStringContainsString('ID', $e->getMessage());
        }
        foreach ([
            ['credentialIDs' => ['bad' => 'not a list']],
            ['credentialIDs' => [null]],
            ['credentialIDs' => ['']],
        ] as $invalid) {
            $client = self::client(fn ($operation) => $operation === 'info' ? ['specs' => '1.0.4.0'] : $invalid);
            try {
                (new CscCertificateDiscovery($client))->certificates();
                self::fail('Accepted invalid credential enumeration');
            } catch (SignerException $e) {
                self::assertStringContainsString('CSC', $e->getMessage());
            }
        }
    }

    public function test_rejects_non_rsa_and_invalid_der_credentials(): void
    {
        $key = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']);
        $csr = openssl_csr_new(['commonName' => 'Unsupported EC lab signer'], $key);
        $x509 = openssl_csr_sign($csr, null, $key, 1);
        openssl_x509_export($x509, $ecPem);
        $ecInfo = self::credentialInfo($ecPem);
        foreach ([
            $ecInfo,
            ['key' => ['status' => 'enabled', 'algo' => [CscCertificateDiscovery::SHA256_RSA_OID]],
                'cert' => ['certificates' => ['!not-base64!']]],
        ] as $info) {
            $client = self::client(fn ($operation) => $operation === 'info' ? ['specs' => '1.0.4.0'] : $info);
            try {
                (new CscCertificateDiscovery($client))->certificates('lab/signer');
                self::fail('Accepted unusable public key/certificate');
            } catch (SignerException $e) {
                self::assertStringContainsString('CSC', $e->getMessage());
            }
        }
    }

    public function test_rejects_invalid_digest_size_or_credential_before_authorization(): void
    {
        $bundle = Pkcs12Fixture::load();
        $count = 0;
        $client = self::client(function () use (&$count) {
            $count++;

            return ['specs' => '1.0.4.0'];
        });
        foreach ([
            [new ExternalSigningPayload(base64_encode('short'), SigningInputType::Digest, HashAlgorithm::Sha256, SignatureAlgorithm::RsaPkcs1V15, SignatureEncoding::RsaPkcs1), 'lab/signer'],
            [self::payload(), ''],
        ] as [$payload, $id]) {
            try {
                (new CscSignatureProvider($client))->sign($payload, new RemoteCertificate($id, new SigningCertificateDto($bundle['cert'])));
                self::fail('Accepted invalid signing request');
            } catch (SignerException $e) {
                self::assertStringContainsString('CSC signing requires', $e->getMessage());
            }
        }
        self::assertSame(0, $count);
    }

    public function test_refuses_changed_capabilities_and_invalid_local_certificate(): void
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
        try {
            (new CscSignatureProvider($client))->sign(self::payload(), new RemoteCertificate('lab/signer', new SigningCertificateDto($bundle['cert'])));
            self::fail('Authorized after the remote signing algorithm changed');
        } catch (SignerException $e) {
            self::assertStringContainsString('algorithm', $e->getMessage());
        }
        self::assertSame(0, $authorizationCalls);

        $invalidClient = self::client(fn ($operation) => $operation === 'info' ? ['specs' => '1.0.4.0'] : self::credentialInfo($bundle['cert']));
        try {
            (new CscSignatureProvider($invalidClient))->sign(self::payload(), new RemoteCertificate('lab/signer', new SigningCertificateDto('not-a-certificate')));
            self::fail('Accepted an invalid local signer certificate');
        } catch (SignerException $e) {
            self::assertStringContainsString('certificate changed', $e->getMessage());
        }
    }

    private static function payload(): ExternalSigningPayload
    {
        return new ExternalSigningPayload(base64_encode(random_bytes(32)), SigningInputType::Digest, HashAlgorithm::Sha256, SignatureAlgorithm::RsaPkcs1V15, SignatureEncoding::RsaPkcs1);
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
