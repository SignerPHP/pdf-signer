<?php

declare(strict_types=1);

use SignerPHP\PdfSigner\Application\DTO\ExternalSigningPayload;
use SignerPHP\PdfSigner\Application\DTO\HashAlgorithm;
use SignerPHP\PdfSigner\Application\DTO\SignatureAlgorithm;
use SignerPHP\PdfSigner\Domain\Exception\SignerException;
use SignerPHP\PdfSigner\Infrastructure\Native\Contract\HttpClientInterface;
use SignerPHP\PdfSigner\Infrastructure\Native\ValueObject\HttpResponse;
use SignerPHP\PdfSigner\Infrastructure\Remote\Vidaas\VidaasPkce;
use SignerPHP\PdfSigner\Infrastructure\Remote\Vidaas\VidaasProvider;
use SignerPHP\PdfSigner\Presentation\Signer;
use SignerPHP\PdfSigner\Tests\Support\PdfFixtureFactory;
use SignerPHP\PdfSigner\Tests\Support\Pkcs12Fixture;

it('builds a VIDaaS authorization URL with PKCE and optional context', function (): void {
    $verifier = VidaasPkce::generateVerifier();
    $challenge = VidaasPkce::challenge($verifier);
    $url = VidaasProvider::authorizationUrl(
        clientId: 'client-id',
        codeChallenge: $challenge,
        redirectUri: 'https://client.example/callback',
        state: 'state-value',
        loginHint: '11111111111',
        baseUrl: VidaasProvider::SANDBOX_URL,
    );

    parse_str((string) parse_url($url, PHP_URL_QUERY), $query);

    expect($url)->toStartWith(VidaasProvider::SANDBOX_URL.'/v0/oauth/authorize?')
        ->and($query['code_challenge'])->toBe($challenge)
        ->and($query['code_challenge_method'])->toBe('S256')
        ->and($query['scope'])->toBe('signature_session')
        ->and($query['state'])->toBe('state-value')
        ->and($query['login_hint'])->toBe('11111111111');
});

it('exchanges an authorization code for an access token', function (): void {
    $capture = new class
    {
        public string $url = '';

        public string $body = '';
    };
    $http = callbackHttpClient(function (string $method, string $url, array $headers, string $body) use ($capture): HttpResponse {
        $capture->url = $url;
        $capture->body = $body;

        return new HttpResponse(200, json_encode([
            'access_token' => 'user-token',
            'token_type' => 'Bearer',
            'expires_in' => 43200,
            'scope' => 'signature_session',
        ], JSON_THROW_ON_ERROR));
    });

    $token = VidaasProvider::exchangeAuthorizationCode(
        $http,
        'client-id',
        'client-secret',
        'authorization-code',
        str_repeat('a', 43),
        'https://client.example/callback',
        VidaasProvider::SANDBOX_URL,
    );

    parse_str($capture->body, $form);
    expect($capture->url)->toBe(VidaasProvider::SANDBOX_URL.'/v0/oauth/token')
        ->and($form['grant_type'])->toBe('authorization_code')
        ->and($form['code_verifier'])->toBe(str_repeat('a', 43))
        ->and($token->value)->toBe('user-token')
        ->and($token->expiresIn)->toBe(43200);
});

it('discovers certificates and normalizes DER to PEM', function (): void {
    $bundle = Pkcs12Fixture::load();
    preg_match('/-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----/s', $bundle['cert'], $matches);
    $derBase64 = preg_replace('/\s+/', '', $matches[1] ?? '');
    $http = callbackHttpClient(fn (): HttpResponse => new HttpResponse(200, json_encode([
        'certificates' => [
            ['alias' => 'CERT-1', 'certificate' => $derBase64],
            ['alias' => '', 'certificate' => 'ignored'],
        ],
    ], JSON_THROW_ON_ERROR)));

    $certificates = (new VidaasProvider('token', $http))->certificates('CERT-1');

    expect($certificates)->toHaveCount(1)
        ->and($certificates[0]->alias)->toBe('CERT-1')
        ->and($certificates[0]->pem)->toStartWith('-----BEGIN CERTIFICATE-----')
        ->and(openssl_x509_read($certificates[0]->pem))->not->toBeFalse();
});

it('signs a prepared PDF through the VIDaaS RAW contract', function (): void {
    $bundle = Pkcs12Fixture::load();
    $capture = new class
    {
        /** @var array<string, mixed> */
        public array $request = [];
    };
    $http = callbackHttpClient(function (string $method, string $url, array $headers, string $body) use ($bundle, $capture): HttpResponse {
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
    $provider = new VidaasProvider('token', $http);
    $builder = Signer::externalSigner()
        ->withPdfContent(PdfFixtureFactory::minimalPdf())
        ->withCertificate($bundle['cert'])
        ->withoutDefaultAppearance()
        ->withPadesBaselineB();
    $prepared = $builder->prepare();

    $signature = $provider->sign($prepared->payload, 'CERT-1');
    $signedPdf = $builder->complete($prepared->state, $signature->bytes);
    $validation = Signer::validation()->withPdfContent($signedPdf)->disableTrustChainValidation()->validate();

    expect($capture->request['certificate_alias'])->toBe('CERT-1')
        ->and($capture->request['hashes'][0]['signature_format'])->toBe('RAW')
        ->and($capture->request['hashes'][0]['padding_method'])->toBe('PKCS1V1_5')
        ->and($validation->allValid)->toBeTrue();
});

it('rejects unsupported algorithms and malformed provider responses', function (): void {
    $http = callbackHttpClient(fn (): HttpResponse => new HttpResponse(200, '{"certificate_alias":"CERT-1"}'));
    $provider = new VidaasProvider('token', $http);
    $unsupported = new ExternalSigningPayload('', '', HashAlgorithm::Sha512, SignatureAlgorithm::RsaPkcs1V15);
    $supported = new ExternalSigningPayload('', base64_encode(random_bytes(32)), HashAlgorithm::Sha256, SignatureAlgorithm::RsaPkcs1V15);

    expect(fn () => $provider->sign($unsupported, 'CERT-1'))
        ->toThrow(SignerException::class, 'SHA-256')
        ->and(fn () => $provider->sign($supported, ''))
        ->toThrow(SignerException::class, 'alias')
        ->and(fn () => $provider->sign($supported, 'CERT-1'))
        ->toThrow(SignerException::class, 'does not contain signatures');
});

it('validates VIDaaS configuration and OAuth failures', function (): void {
    $ok = callbackHttpClient(fn (): HttpResponse => new HttpResponse(200, '{}'));
    $unauthorized = callbackHttpClient(fn (): HttpResponse => new HttpResponse(401, '{"error":"invalid_grant"}'));
    $invalidJson = callbackHttpClient(fn (): HttpResponse => new HttpResponse(200, 'invalid'));

    expect(fn () => new VidaasProvider('', $ok))->toThrow(SignerException::class, 'access token')
        ->and(fn () => VidaasProvider::authorizationUrl('', 'challenge'))->toThrow(SignerException::class, 'authorization requires')
        ->and(fn () => VidaasProvider::exchangeAuthorizationCode($ok, '', 'secret', 'code', 'verifier'))->toThrow(SignerException::class, 'token exchange requires')
        ->and(fn () => VidaasProvider::exchangeAuthorizationCode($unauthorized, 'id', 'secret', 'code', 'verifier'))->toThrow(SignerException::class, 'HTTP 401')
        ->and(fn () => VidaasProvider::exchangeAuthorizationCode($invalidJson, 'id', 'secret', 'code', 'verifier'))->toThrow(SignerException::class, 'invalid JSON')
        ->and(fn () => VidaasProvider::exchangeAuthorizationCode($ok, 'id', 'secret', 'code', 'verifier'))->toThrow(SignerException::class, 'access_token');
});

it('validates PKCE input and invalid certificate discovery responses', function (): void {
    $invalidList = callbackHttpClient(fn (): HttpResponse => new HttpResponse(200, '{"certificates":"invalid"}'));
    $emptyList = callbackHttpClient(fn (): HttpResponse => new HttpResponse(200, '{"certificates":["invalid"]}'));
    $invalidCertificate = callbackHttpClient(fn (): HttpResponse => new HttpResponse(200, '{"certificates":[{"alias":"CERT","certificate":"***"}]}'));

    expect(fn () => VidaasPkce::generateVerifier(10))->toThrow(\InvalidArgumentException::class, 'entropy')
        ->and(fn () => VidaasPkce::challenge('short'))->toThrow(\InvalidArgumentException::class, '43')
        ->and(fn () => (new VidaasProvider('token', $invalidList))->certificates())->toThrow(SignerException::class, 'response is invalid')
        ->and(fn () => (new VidaasProvider('token', $emptyList))->certificates())->toThrow(SignerException::class, 'usable certificate')
        ->and(fn () => (new VidaasProvider('token', $invalidCertificate))->certificates())->toThrow(SignerException::class, 'invalid certificate');
});

it('rejects invalid digests and mismatched certificate aliases', function (): void {
    $mismatch = callbackHttpClient(fn (): HttpResponse => new HttpResponse(200, '{"certificate_alias":"OTHER","signatures":[]}'));
    $provider = new VidaasProvider('token', $mismatch);
    $invalidDigest = new ExternalSigningPayload('', '***', HashAlgorithm::Sha256, SignatureAlgorithm::RsaPkcs1V15);
    $validDigest = new ExternalSigningPayload('', base64_encode(random_bytes(32)), HashAlgorithm::Sha256, SignatureAlgorithm::RsaPkcs1V15);

    expect(fn () => $provider->sign($invalidDigest, 'CERT-1'))->toThrow(SignerException::class, 'valid SHA-256')
        ->and(fn () => $provider->sign($validDigest, 'CERT-1'))->toThrow(SignerException::class, 'unexpected certificate alias');
});

/** @param callable(string, string, array<int, string>, string, int, bool): HttpResponse $callback */
function callbackHttpClient(callable $callback): HttpClientInterface
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
