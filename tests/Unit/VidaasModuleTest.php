<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Tests\Unit;

use InvalidArgumentException;
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
use SignerPHP\PdfSigner\Infrastructure\Remote\Vidaas\VidaasAuthorization;
use SignerPHP\PdfSigner\Infrastructure\Remote\Vidaas\VidaasCertificateDiscovery;
use SignerPHP\PdfSigner\Infrastructure\Remote\Vidaas\VidaasClient;
use SignerPHP\PdfSigner\Infrastructure\Remote\Vidaas\VidaasPkce;
use SignerPHP\PdfSigner\Infrastructure\Remote\Vidaas\VidaasSignatureProvider;
use SignerPHP\PdfSigner\Presentation\Signer;
use SignerPHP\PdfSigner\RemoteSigning\Contract\RemoteCertificateDiscoveryInterface;
use SignerPHP\PdfSigner\RemoteSigning\Contract\RemoteSignatureProviderInterface;
use SignerPHP\PdfSigner\RemoteSigning\DTO\RemoteCertificate;
use SignerPHP\PdfSigner\Tests\Support\PdfFixtureFactory;
use SignerPHP\PdfSigner\Tests\Support\Pkcs12Fixture;

final class VidaasModuleTest extends TestCase
{
    public function test_builds_a_vidaas_authorization_url_with_pkce_and_optional_context(): void
    {
        $verifier = VidaasPkce::generateVerifier();
        $challenge = VidaasPkce::challenge($verifier);
        $authorization = new VidaasAuthorization(self::callbackHttpClient(fn (): HttpResponse => new HttpResponse(200, '{}')), 'client-id', 'client-secret', VidaasClient::SANDBOX_URL);
        $url = $authorization->authorizationUrl(
            codeChallenge: $challenge,
            redirectUri: 'https://client.example/callback',
            state: 'state-value',
            loginHint: '11111111111',
        );

        parse_str((string) parse_url($url, PHP_URL_QUERY), $query);

        expect($url)->toStartWith(VidaasClient::SANDBOX_URL.'/v0/oauth/authorize?')
            ->and($query['code_challenge'])->toBe($challenge)
            ->and($query['code_challenge_method'])->toBe('S256')
            ->and($query['scope'])->toBe('signature_session')
            ->and($query['state'])->toBe('state-value')
            ->and($query['login_hint'])->toBe('11111111111');
    }

    public function test_exchanges_an_authorization_code_for_an_access_token(): void
    {
        $capture = new class
        {
            public string $url = '';

            public string $body = '';
        };
        $http = self::callbackHttpClient(function (string $method, string $url, array $headers, string $body) use ($capture): HttpResponse {
            $capture->url = $url;
            $capture->body = $body;

            return new HttpResponse(200, json_encode([
                'access_token' => 'user-token',
                'token_type' => 'Bearer',
                'expires_in' => 43200,
                'scope' => 'signature_session',
            ], JSON_THROW_ON_ERROR));
        });

        $token = (new VidaasAuthorization(
            $http,
            'client-id',
            'client-secret',
            VidaasClient::SANDBOX_URL,
        ))->exchangeAuthorizationCode('authorization-code', str_repeat('a', 43), 'https://client.example/callback');

        parse_str($capture->body, $form);
        expect($capture->url)->toBe(VidaasClient::SANDBOX_URL.'/v0/oauth/token')
            ->and($form['grant_type'])->toBe('authorization_code')
            ->and($form['code_verifier'])->toBe(str_repeat('a', 43))
            ->and($token->value)->toBe('user-token')
            ->and($token->expiresIn)->toBe(43200);
    }

    public function test_discovers_certificates_and_normalizes_der_to_pem(): void
    {
        $bundle = Pkcs12Fixture::load();
        preg_match('/-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----/s', $bundle['cert'], $matches);
        $derBase64 = preg_replace('/\s+/', '', $matches[1] ?? '');
        $requestedUrl = '';
        $http = self::callbackHttpClient(function (string $method, string $url) use (&$requestedUrl, $derBase64): HttpResponse {
            $requestedUrl = $url;

            return new HttpResponse(200, json_encode([
                'certificates' => [
                    ['alias' => 'CERT-1', 'certificate' => $derBase64],
                    ['alias' => '', 'certificate' => 'ignored'],
                ],
            ], JSON_THROW_ON_ERROR));
        });

        $discovery = new VidaasCertificateDiscovery(new VidaasClient('token', $http));
        $certificates = $discovery->certificates('CERT-1');

        expect($discovery)->toBeInstanceOf(RemoteCertificateDiscoveryInterface::class)
            ->and($requestedUrl)->toContain('/v0/oauth/certificate-discovery?certificate_alias=CERT-1')
            ->and($certificates)->toHaveCount(1)
            ->and($certificates[0]->identifier)->toBe('CERT-1')
            ->and($certificates[0]->certificate->certificatePem)->toStartWith('-----BEGIN CERTIFICATE-----')
            ->and(openssl_x509_read($certificates[0]->certificate->certificatePem))->not->toBeFalse();
    }

    public function test_signs_a_prepared_pdf_through_the_vidaas_raw_contract(): void
    {
        $bundle = Pkcs12Fixture::load();
        $capture = new class
        {
            /** @var array<string, mixed> */
            public array $request = [];
        };
        $http = self::callbackHttpClient(function (string $method, string $url, array $headers, string $body) use ($bundle, $capture): HttpResponse {
            $request = json_decode($body, true, flags: JSON_THROW_ON_ERROR);
            $capture->request = $request;
            $hash = base64_decode($request['hashes'][0]['hash'], true);
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
        $provider = new VidaasSignatureProvider(new VidaasClient('token', $http));
        $remoteCertificate = self::remoteCertificate('CERT-1', $bundle['cert']);
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
            ->and($capture->request['hashes'][0]['padding_method'])->toBe('PKCS1V1_5')
            ->and($validation->allValid)->toBeTrue();
    }

    public function test_rejects_unsupported_algorithms_and_malformed_provider_responses(): void
    {
        $http = self::callbackHttpClient(fn (): HttpResponse => new HttpResponse(200, '{"certificate_alias":"CERT-1"}'));
        $provider = new VidaasSignatureProvider(new VidaasClient('token', $http));
        $certificate = self::remoteCertificate();
        $unsupported = new ExternalSigningPayload('', SigningInputType::Digest, HashAlgorithm::Sha512, SignatureAlgorithm::RsaPkcs1V15, SignatureEncoding::RsaPkcs1);
        $supported = new ExternalSigningPayload(base64_encode(random_bytes(32)), SigningInputType::Digest, HashAlgorithm::Sha256, SignatureAlgorithm::RsaPkcs1V15, SignatureEncoding::RsaPkcs1);

        expect(fn () => $provider->sign($unsupported, $certificate))
            ->toThrow(SignerException::class, 'SHA-256')
            ->and(fn () => $provider->sign($supported, self::remoteCertificate('')))
            ->toThrow(SignerException::class, 'alias')
            ->and(fn () => $provider->sign($supported, $certificate))
            ->toThrow(SignerException::class, 'does not contain signatures');
    }

    public function test_validates_vidaas_configuration_and_oauth_failures(): void
    {
        $ok = self::callbackHttpClient(fn (): HttpResponse => new HttpResponse(200, '{}'));
        $unauthorized = self::callbackHttpClient(fn (): HttpResponse => new HttpResponse(401, '{"error":"invalid_grant"}'));
        $invalidJson = self::callbackHttpClient(fn (): HttpResponse => new HttpResponse(200, 'invalid'));

        expect(fn () => new VidaasClient('', $ok))->toThrow(SignerException::class, 'access token')
            ->and(fn () => new VidaasAuthorization($ok, '', 'secret'))->toThrow(SignerException::class, 'clientId')
            ->and(fn () => (new VidaasAuthorization($ok, 'id', 'secret'))->authorizationUrl(''))->toThrow(SignerException::class, 'codeChallenge')
            ->and(fn () => (new VidaasAuthorization($ok, 'id', 'secret'))->exchangeAuthorizationCode('', 'verifier'))->toThrow(SignerException::class, 'code and codeVerifier')
            ->and(fn () => (new VidaasAuthorization($unauthorized, 'id', 'secret'))->exchangeAuthorizationCode('code', 'verifier'))->toThrow(SignerException::class, 'HTTP 401')
            ->and(fn () => (new VidaasAuthorization($invalidJson, 'id', 'secret'))->exchangeAuthorizationCode('code', 'verifier'))->toThrow(SignerException::class, 'invalid JSON')
            ->and(fn () => (new VidaasAuthorization($ok, 'id', 'secret'))->exchangeAuthorizationCode('code', 'verifier'))->toThrow(SignerException::class, 'access_token');
    }

    public function test_starts_and_polls_a_vidaas_push_authorization(): void
    {
        $responses = [
            new HttpResponse(200, 'code=push-code'),
            new HttpResponse(200, '{"status":"PENDING"}'),
            new HttpResponse(200, '{"authorizationToken":"approved-code","redirectUrl":"app://approved"}'),
        ];
        $requests = [];
        $http = self::callbackHttpClient(function (string $method, string $url, array $headers) use (&$responses, &$requests): HttpResponse {
            $requests[] = [$method, $url, $headers];

            return array_shift($responses);
        });
        $authorization = new VidaasAuthorization($http, 'client-id', 'client-secret', VidaasClient::SANDBOX_URL);

        $started = $authorization->startPush('11111111111');
        $pending = $authorization->pollPush($started->code);
        $approved = $authorization->pollPush($started->code);

        parse_str((string) parse_url($requests[0][1], PHP_URL_QUERY), $query);
        expect($started->code)->toBe('push-code')
            ->and($query['redirect_uri'])->toBe('push://')
            ->and($query['code_challenge'])->toBe('challenge')
            ->and($query['code_challenge_method'])->toBe('plain')
            ->and($query['login_hint'])->toBe('11111111111')
            ->and($pending->approved)->toBeFalse()
            ->and($approved->approved)->toBeTrue()
            ->and($approved->authorizationToken)->toBe('approved-code')
            ->and($requests[1][0])->toBe('POST')
            ->and($requests[1][1])->toEndWith('/valid/api/v1/trusted-services/authentications')
            ->and($requests[1][2])->toContain('Authorization: Bearer push-code');
    }

    public function test_exchanges_a_vidaas_push_token_with_the_provider_push_verifier(): void
    {
        $capturedBody = '';
        $http = self::callbackHttpClient(function (string $method, string $url, array $headers, string $body) use (&$capturedBody): HttpResponse {
            $capturedBody = $body;

            return new HttpResponse(200, '{"access_token":"push-access-token"}');
        });

        $token = (new VidaasAuthorization($http, 'client-id', 'client-secret'))->exchangePushAuthorizationToken('approved-code');
        parse_str($capturedBody, $form);

        expect($token->value)->toBe('push-access-token')
            ->and($form['code'])->toBe('approved-code')
            ->and($form['code_verifier'])->toBe('challenge')
            ->and($form['redirect_uri'])->toBe('push://');
    }

    public function test_validates_malformed_vidaas_push_responses(): void
    {
        $failed = self::callbackHttpClient(fn (): HttpResponse => new HttpResponse(401, ''));
        $missingCode = self::callbackHttpClient(fn (): HttpResponse => new HttpResponse(200, 'invalid'));
        $pending = self::callbackHttpClient(fn (): HttpResponse => new HttpResponse(200, '{}'));

        expect(fn () => (new VidaasAuthorization($failed, 'id', 'secret'))->startPush('11111111111'))
            ->toThrow(SignerException::class, 'HTTP 401')
            ->and(fn () => (new VidaasAuthorization($missingCode, 'id', 'secret'))->startPush('11111111111'))
            ->toThrow(SignerException::class, 'does not contain code')
            ->and((new VidaasAuthorization($pending, 'id', 'secret'))->pollPush('code')->approved)->toBeFalse()
            ->and(fn () => (new VidaasAuthorization($pending, 'id', 'secret'))->pollPush(''))
            ->toThrow(SignerException::class, 'requires a code')
            ->and(fn () => (new VidaasAuthorization($pending, 'id', 'secret'))->startPush(''))
            ->toThrow(SignerException::class, 'loginHint')
            ->and(fn () => (new VidaasAuthorization($pending, 'id', 'secret'))->startPush('11111111111', lifetimeSeconds: 10))
            ->toThrow(SignerException::class, 'between 60 and 3600');
    }

    public function test_validates_pkce_input_and_invalid_certificate_discovery_responses(): void
    {
        $invalidList = self::callbackHttpClient(fn (): HttpResponse => new HttpResponse(200, '{"certificates":"invalid"}'));
        $emptyList = self::callbackHttpClient(fn (): HttpResponse => new HttpResponse(200, '{"certificates":["invalid"]}'));
        $invalidCertificate = self::callbackHttpClient(fn (): HttpResponse => new HttpResponse(200, '{"certificates":[{"alias":"CERT","certificate":"***"}]}'));

        expect(fn () => VidaasPkce::generateVerifier(10))->toThrow(\InvalidArgumentException::class, 'entropy')
            ->and(fn () => VidaasPkce::challenge('short'))->toThrow(\InvalidArgumentException::class, '43')
            ->and(fn () => (new VidaasCertificateDiscovery(new VidaasClient('token', $invalidList)))->certificates())->toThrow(SignerException::class, 'response is invalid')
            ->and(fn () => (new VidaasCertificateDiscovery(new VidaasClient('token', $emptyList)))->certificates())->toThrow(SignerException::class, 'usable certificate')
            ->and(fn () => (new VidaasCertificateDiscovery(new VidaasClient('token', $invalidCertificate)))->certificates())->toThrow(SignerException::class, 'invalid certificate');
    }

    public function test_rejects_invalid_digests_and_mismatched_certificate_aliases(): void
    {
        $mismatch = self::callbackHttpClient(fn (): HttpResponse => new HttpResponse(200, '{"certificate_alias":"OTHER","signatures":[]}'));
        $provider = new VidaasSignatureProvider(new VidaasClient('token', $mismatch));
        $invalidDigest = new ExternalSigningPayload('***', SigningInputType::Digest, HashAlgorithm::Sha256, SignatureAlgorithm::RsaPkcs1V15, SignatureEncoding::RsaPkcs1);
        $validDigest = new ExternalSigningPayload(base64_encode(random_bytes(32)), SigningInputType::Digest, HashAlgorithm::Sha256, SignatureAlgorithm::RsaPkcs1V15, SignatureEncoding::RsaPkcs1);

        expect(fn () => $provider->sign($invalidDigest, self::remoteCertificate()))->toThrow(InvalidArgumentException::class, 'invalid base64 input')
            ->and(fn () => $provider->sign($validDigest, self::remoteCertificate()))->toThrow(SignerException::class, 'unexpected certificate alias');
    }

    private static function remoteCertificate(string $identifier = 'CERT-1', string $certificatePem = 'certificate'): RemoteCertificate
    {
        return new RemoteCertificate($identifier, new SigningCertificateDto($certificatePem));
    }

    /** @param callable(string, string, array<int, string>, string, int, bool): HttpResponse $callback */
    private static function callbackHttpClient(callable $callback): HttpClientInterface
    {
        return new class($callback) implements HttpClientInterface
        {
            public function __construct(private $callback) {}

            public function request(string $method, string $url, array $headers = [], string $body = '', int $timeoutSeconds = 10, bool $followRedirects = false): HttpResponse
            {
                return ($this->callback)($method, $url, $headers, $body, $timeoutSeconds, $followRedirects);
            }
        };
    }
}
