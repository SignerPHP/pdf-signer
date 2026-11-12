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
use SignerPHP\PdfSigner\Infrastructure\Remote\BirdId\BirdIdAuthorization;
use SignerPHP\PdfSigner\Infrastructure\Remote\BirdId\BirdIdCertificateDiscovery;
use SignerPHP\PdfSigner\Infrastructure\Remote\BirdId\BirdIdClient;
use SignerPHP\PdfSigner\Infrastructure\Remote\BirdId\BirdIdPkce;
use SignerPHP\PdfSigner\Infrastructure\Remote\BirdId\BirdIdSignatureProvider;
use SignerPHP\PdfSigner\Presentation\Signer;
use SignerPHP\PdfSigner\RemoteSigning\Contract\RemoteCertificateDiscoveryInterface;
use SignerPHP\PdfSigner\RemoteSigning\Contract\RemoteSignatureProviderInterface;
use SignerPHP\PdfSigner\RemoteSigning\DTO\RemoteCertificate;
use SignerPHP\PdfSigner\Tests\Support\PdfFixtureFactory;
use SignerPHP\PdfSigner\Tests\Support\Pkcs12Fixture;

final class BirdIdModuleTest extends TestCase
{
    public function test_builds_a_birdid_authorization_url_with_pkce_and_zero_padded_login_hint(): void
    {
        $verifier = BirdIdPkce::generateVerifier();
        $challenge = BirdIdPkce::challenge($verifier);
        $authorization = new BirdIdAuthorization(
            self::birdIdHttp(fn (): HttpResponse => new HttpResponse(200, '{}')),
            'client-id',
            'client-secret',
            BirdIdClient::PRODUCTION_URL,
        );
        $url = $authorization->authorizationUrl(
            codeChallenge: $challenge,
            redirectUri: 'https://client.example/callback',
            state: 'state-value',
            loginHint: '11111111111',
        );

        parse_str((string) parse_url($url, PHP_URL_QUERY), $query);

        expect($url)->toStartWith(BirdIdClient::PRODUCTION_URL.'/v0/oauth/authorize?')
            ->and($query['code_challenge'])->toBe($challenge)
            ->and($query['code_challenge_method'])->toBe('S256')
            ->and($query['scope'])->toBe('signature_session')
            ->and($query['lifetime'])->toBe((string) BirdIdAuthorization::DEFAULT_SIGNATURE_LIFETIME_SECONDS)
            ->and($query['state'])->toBe('state-value')
            ->and($query['login_hint'])->toBe('11111111111');
    }

    public function test_exchanges_an_authorization_code_using_a_json_token_request(): void
    {
        $capture = new class
        {
            public string $url = '';

            public string $body = '';

            /** @var list<string> */
            public array $headers = [];
        };
        $http = self::birdIdHttp(function (string $method, string $url, array $headers, string $body) use ($capture): HttpResponse {
            $capture->url = $url;
            $capture->body = $body;
            $capture->headers = $headers;

            return new HttpResponse(200, json_encode([
                'access_token' => 'user-token',
                'token_type' => 'Bearer',
                'expires_in' => 46800,
                'scope' => 'signature_session',
                'authorized_identification_type' => 'CPF',
                'authorized_identification' => '00000000001',
            ], JSON_THROW_ON_ERROR));
        });

        $token = (new BirdIdAuthorization(
            $http,
            'client-id',
            'client-secret',
            BirdIdClient::PRODUCTION_URL,
        ))->exchangeAuthorizationCode('authorization-code', str_repeat('a', 43), 'https://client.example/callback');

        $payload = json_decode($capture->body, true, flags: JSON_THROW_ON_ERROR);

        expect($capture->url)->toBe(BirdIdClient::PRODUCTION_URL.'/v0/oauth/token')
            ->and($capture->headers)->toContain('Content-Type: application/json')
            ->and($payload['grant_type'])->toBe('authorization_code')
            ->and($payload['code_verifier'])->toBe(str_repeat('a', 43))
            ->and($payload['lifetime'])->toBe(BirdIdAuthorization::DEFAULT_SIGNATURE_LIFETIME_SECONDS)
            ->and($token->value)->toBe('user-token')
            ->and($token->expiresIn)->toBe(46800)
            ->and($token->authorizedIdentification)->toBe('00000000001');
    }

    public function test_authorizes_with_otp_password_grant_and_discovers_users(): void
    {
        $requests = [];
        $http = self::birdIdHttp(function (string $method, string $url, array $headers, string $body) use (&$requests): HttpResponse {
            $requests[] = [$url, json_decode($body, true, flags: JSON_THROW_ON_ERROR)];

            if (str_ends_with($url, '/pwd_authorize')) {
                return new HttpResponse(200, '{"access_token":"otp-token","expires_in":46800,"token_type":"bearer","scope":"signature_session"}');
            }

            return new HttpResponse(200, json_encode([
                'status' => 'S',
                'slots' => [
                    ['slot_alias' => '11111111111-1', 'label' => 'A3 PESSOAL'],
                    ['slot_alias' => '', 'label' => 'ignored'],
                ],
            ], JSON_THROW_ON_ERROR));
        });
        $authorization = new BirdIdAuthorization($http, 'client-id', 'client-secret', BirdIdClient::VAULT_ID_URL);

        $token = $authorization->authorizeWithPassword('111.111.111-11', '123456');
        $discovery = $authorization->discoverUser('11.111.111/0001-11');

        expect($token->value)->toBe('otp-token')
            ->and($requests[0][0])->toBe(BirdIdClient::VAULT_ID_URL.'/v0/oauth/pwd_authorize')
            ->and($requests[0][1]['username'])->toBe('11111111111')
            ->and($requests[0][1]['password'])->toBe('123456')
            ->and($requests[0][1]['grant_type'])->toBe('password')
            ->and($requests[1][1]['user_cpf_cnpj'])->toBe('CNPJ')
            ->and($requests[1][1]['val_cpf_cnpj'])->toBe('11111111000111')
            ->and($discovery->hasCertificate)->toBeTrue()
            ->and($discovery->slots)->toHaveCount(1)
            ->and($discovery->slots[0]->alias)->toBe('11111111111-1')
            ->and($discovery->slots[0]->label)->toBe('A3 PESSOAL');
    }

    public function test_revokes_an_access_token(): void
    {
        $body = '';
        $http = self::birdIdHttp(function (string $method, string $url, array $headers, string $requestBody) use (&$body): HttpResponse {
            $body = $requestBody;

            return new HttpResponse(200, '{"revoked":true}');
        });

        expect((new BirdIdAuthorization($http, 'id', 'secret'))->revoke('access-token'))->toBeTrue()
            ->and(json_decode($body, true)['token'])->toBe('access-token');
    }

    public function test_discovers_certificates_and_normalizes_der_to_pem(): void
    {
        $bundle = Pkcs12Fixture::load();
        preg_match('/-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----/s', $bundle['cert'], $matches);
        $derBase64 = preg_replace('/\s+/', '', $matches[1] ?? '');
        $http = self::birdIdHttp(fn (): HttpResponse => new HttpResponse(200, json_encode([
            'status' => 'S',
            'certificates' => [
                ['alias' => 'CERT-1', 'certificate' => $derBase64],
                ['alias' => 'CERT-2', 'certificate' => $bundle['cert']],
                ['alias' => '', 'certificate' => 'ignored'],
            ],
        ], JSON_THROW_ON_ERROR)));

        $discovery = new BirdIdCertificateDiscovery(new BirdIdClient('token', $http));
        $certificates = $discovery->certificates('CERT-1');

        expect($discovery)->toBeInstanceOf(RemoteCertificateDiscoveryInterface::class)
            ->and($certificates)->toHaveCount(1)
            ->and($certificates[0]->identifier)->toBe('CERT-1')
            ->and($certificates[0]->certificate->certificatePem)->toStartWith('-----BEGIN CERTIFICATE-----')
            ->and(openssl_x509_read($certificates[0]->certificate->certificatePem))->not->toBeFalse();
    }

    public function test_signs_a_prepared_pdf_through_the_birdid_raw_hex_hash_contract(): void
    {
        $bundle = Pkcs12Fixture::load();
        $capture = new class
        {
            /** @var array<string, mixed> */
            public array $request = [];
        };
        $http = self::birdIdHttp(function (string $method, string $url, array $headers, string $body) use ($bundle, $capture): HttpResponse {
            $request = json_decode($body, true, flags: JSON_THROW_ON_ERROR);
            $capture->request = $request;
            $hash = hex2bin($request['hashes'][0]['hash']);
            expect($hash)->not->toBeFalse()->and(strlen((string) $hash))->toBe(32);
            $digestInfo = hex2bin('3031300d060960864801650304020105000420').$hash;
            $signature = '';
            expect(openssl_private_encrypt($digestInfo, $signature, $bundle['pkey'], OPENSSL_PKCS1_PADDING))->toBeTrue();

            return new HttpResponse(200, json_encode([
                'signatures' => [[
                    'id' => $request['hashes'][0]['id'],
                    'raw_signature' => base64_encode($signature),
                ]],
                'certificate_alias' => 'CERT-1',
            ], JSON_THROW_ON_ERROR));
        });
        $provider = new BirdIdSignatureProvider(new BirdIdClient('token', $http));
        $remoteCertificate = self::birdIdRemoteCertificate('CERT-1', $bundle['cert']);
        $builder = Signer::externalSigner()
            ->withPdfContent(PdfFixtureFactory::minimalPdf())
            ->withCertificate($bundle['cert'])
            ->withoutDefaultAppearance()
            ->withPadesBaselineB();
        $prepared = $builder->prepare();

        $signature = $provider->sign($prepared->payload, $remoteCertificate);
        $signedPdf = $builder->complete($prepared->state, $signature->bytes);
        $validation = Signer::validation()->withPdfContent($signedPdf)->disableTrustChainValidation()->validate();

        expect($provider)->toBeInstanceOf(RemoteSignatureProviderInterface::class)
            ->and($capture->request['certificate_alias'])->toBe('CERT-1')
            ->and($capture->request['hashes'][0]['signature_format'])->toBe('RAW')
            ->and($capture->request['hashes'][0]['hash'])->toMatch('/^[a-f0-9]{64}$/')
            ->and($validation->allValid)->toBeTrue();
    }

    public function test_rejects_unsupported_algorithms_and_malformed_provider_responses(): void
    {
        $http = self::birdIdHttp(fn (): HttpResponse => new HttpResponse(200, '{"certificate_alias":"CERT-1"}'));
        $provider = new BirdIdSignatureProvider(new BirdIdClient('token', $http));
        $certificate = self::birdIdRemoteCertificate();
        $unsupported = new ExternalSigningPayload('', SigningInputType::Digest, HashAlgorithm::Sha512, SignatureAlgorithm::RsaPkcs1V15, SignatureEncoding::RsaPkcs1);
        $supported = new ExternalSigningPayload(base64_encode(random_bytes(32)), SigningInputType::Digest, HashAlgorithm::Sha256, SignatureAlgorithm::RsaPkcs1V15, SignatureEncoding::RsaPkcs1);

        expect(fn () => $provider->sign($unsupported, $certificate))
            ->toThrow(SignerException::class, 'SHA-256')
            ->and(fn () => $provider->sign($supported, self::birdIdRemoteCertificate('')))
            ->toThrow(SignerException::class, 'alias')
            ->and(fn () => $provider->sign($supported, $certificate))
            ->toThrow(SignerException::class, 'does not contain signatures');
    }

    public function test_validates_birdid_configuration_and_oauth_failures(): void
    {
        $ok = self::birdIdHttp(fn (): HttpResponse => new HttpResponse(200, '{}'));
        $unauthorized = self::birdIdHttp(fn (): HttpResponse => new HttpResponse(401, '{"error":"invalid_grant"}'));
        $invalidJson = self::birdIdHttp(fn (): HttpResponse => new HttpResponse(200, 'invalid'));

        expect(fn () => new BirdIdClient('', $ok))->toThrow(SignerException::class, 'access token')
            ->and(fn () => new BirdIdAuthorization($ok, '', 'secret'))->toThrow(SignerException::class, 'clientId')
            ->and(fn () => (new BirdIdAuthorization($ok, 'id', 'secret'))->authorizationUrl(''))->toThrow(SignerException::class, 'codeChallenge')
            ->and(fn () => (new BirdIdAuthorization($ok, 'id', 'secret'))->exchangeAuthorizationCode('', 'verifier'))->toThrow(SignerException::class, 'code and codeVerifier')
            ->and(fn () => (new BirdIdAuthorization($unauthorized, 'id', 'secret'))->exchangeAuthorizationCode('code', 'verifier'))->toThrow(SignerException::class, 'HTTP 401')
            ->and(fn () => (new BirdIdAuthorization($invalidJson, 'id', 'secret'))->exchangeAuthorizationCode('code', 'verifier'))->toThrow(SignerException::class, 'invalid JSON')
            ->and(fn () => (new BirdIdAuthorization($ok, 'id', 'secret'))->exchangeAuthorizationCode('code', 'verifier'))->toThrow(SignerException::class, 'access_token')
            ->and(fn () => (new BirdIdAuthorization($ok, 'id', 'secret'))->authorizeWithPassword('', 'otp'))->toThrow(SignerException::class, 'username and OTP')
            ->and(fn () => (new BirdIdAuthorization($ok, 'id', 'secret'))->revoke(''))->toThrow(SignerException::class, 'access token')
            ->and(fn () => (new BirdIdAuthorization($ok, 'id', 'secret'))->discoverUser(''))->toThrow(SignerException::class, 'CPF or CNPJ');
    }

    public function test_validates_pkce_input_and_invalid_certificate_discovery_responses(): void
    {
        $invalidList = self::birdIdHttp(fn (): HttpResponse => new HttpResponse(200, '{"certificates":"invalid"}'));
        $emptyList = self::birdIdHttp(fn (): HttpResponse => new HttpResponse(200, '{"certificates":["invalid"]}'));
        $invalidCertificate = self::birdIdHttp(fn (): HttpResponse => new HttpResponse(200, '{"certificates":[{"alias":"CERT","certificate":"***"}]}'));

        expect(fn () => BirdIdPkce::challenge('short'))->toThrow(\InvalidArgumentException::class, '43')
            ->and(fn () => (new BirdIdCertificateDiscovery(new BirdIdClient('token', $invalidList)))->certificates())->toThrow(SignerException::class, 'response is invalid')
            ->and(fn () => (new BirdIdCertificateDiscovery(new BirdIdClient('token', $emptyList)))->certificates())->toThrow(SignerException::class, 'usable certificate')
            ->and(fn () => (new BirdIdCertificateDiscovery(new BirdIdClient('token', $invalidCertificate)))->certificates())->toThrow(SignerException::class, 'invalid certificate');
    }

    public function test_rejects_mismatched_certificate_aliases_on_signature_responses(): void
    {
        $mismatch = self::birdIdHttp(fn (): HttpResponse => new HttpResponse(200, '{"certificate_alias":"OTHER","signatures":[]}'));
        $provider = new BirdIdSignatureProvider(new BirdIdClient('token', $mismatch));
        $validDigest = new ExternalSigningPayload(base64_encode(random_bytes(32)), SigningInputType::Digest, HashAlgorithm::Sha256, SignatureAlgorithm::RsaPkcs1V15, SignatureEncoding::RsaPkcs1);

        expect(fn () => $provider->sign($validDigest, self::birdIdRemoteCertificate()))
            ->toThrow(SignerException::class, 'unexpected certificate alias');
    }

    private static function birdIdRemoteCertificate(string $identifier = 'CERT-1', string $certificatePem = 'certificate'): RemoteCertificate
    {
        return new RemoteCertificate($identifier, new SigningCertificateDto($certificatePem));
    }

    /** @param callable(string, string, array<int, string>, string, int, bool): HttpResponse $callback */
    private static function birdIdHttp(callable $callback): HttpClientInterface
    {
        return new class($callback) implements HttpClientInterface
        {
            public function __construct(private $callback) {}

            public function request(
                string $method,
                string $url,
                array $headers = [],
                string $body = '',
                int $timeoutSeconds = 20,
                bool $followRedirects = true,
            ): HttpResponse {
                return ($this->callback)($method, $url, $headers, $body, $timeoutSeconds, $followRedirects);
            }
        };
    }
}
