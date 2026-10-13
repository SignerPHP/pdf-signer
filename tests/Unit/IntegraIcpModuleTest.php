<?php

declare(strict_types=1);

use SignerPHP\PdfSigner\Application\DTO\ExternalSigningPayload;
use SignerPHP\PdfSigner\Application\DTO\HashAlgorithm;
use SignerPHP\PdfSigner\Application\DTO\SignatureAlgorithm;
use SignerPHP\PdfSigner\Application\DTO\SignatureEncoding;
use SignerPHP\PdfSigner\Application\DTO\SigningCertificateDto;
use SignerPHP\PdfSigner\Application\DTO\SigningInputType;
use SignerPHP\PdfSigner\Domain\Exception\SignerException;
use SignerPHP\PdfSigner\Infrastructure\Native\Contract\HttpClientInterface;
use SignerPHP\PdfSigner\Infrastructure\Native\ValueObject\HttpResponse;
use SignerPHP\PdfSigner\Infrastructure\Remote\IntegraIcp\IntegraIcpAuthorization;
use SignerPHP\PdfSigner\Infrastructure\Remote\IntegraIcp\IntegraIcpCertificateDiscovery;
use SignerPHP\PdfSigner\Infrastructure\Remote\IntegraIcp\IntegraIcpClient;
use SignerPHP\PdfSigner\Infrastructure\Remote\IntegraIcp\IntegraIcpPkce;
use SignerPHP\PdfSigner\Infrastructure\Remote\IntegraIcp\IntegraIcpSignatureProvider;
use SignerPHP\PdfSigner\Presentation\Signer;
use SignerPHP\PdfSigner\RemoteSigning\DTO\RemoteCertificate;
use SignerPHP\PdfSigner\Tests\Support\PdfFixtureFactory;
use SignerPHP\PdfSigner\Tests\Support\Pkcs12Fixture;

it('encodes callback context with S256 without sending the verifier', function (): void {
    $verifier = IntegraIcpPkce::generateVerifier();
    $auth = new IntegraIcpAuthorization(new IntegraIcpClient('channel', integraHttp(fn () => integraResponse([]))));
    $callback = 'https://client.example/callback?state=opaque&request=123';
    $url = $auth->authorizationUrl(IntegraIcpPkce::challenge($verifier), $callback, '52998224725');
    parse_str(parse_url($url, PHP_URL_QUERY), $query);
    expect($verifier)->toHaveLength(43)
        ->and($url)->toStartWith('https://services.integraicp.com.br/c/channel/icp/v3/authentications?')
        ->and($url)->not->toContain($verifier)
        ->and($query)->toMatchArray(['secret_type' => 'code_challenge', 'callback_uri' => $callback,
            'subject_key' => '52998224725', 'subject_type' => 'CPF', 'autostart' => 'true']);
});

it('returns provider clearances including an empty list', function (): void {
    $items = [['clearanceId' => 'clearance', 'productName' => 'VIDaaS', 'providerName' => 'Valid',
        'clearanceEndpoint' => 'https://services.integraicp.com.br/clearance', 'clearanceType' => 'IDENTIFICATION']];
    foreach ([$items, []] as $list) {
        $auth = new IntegraIcpAuthorization(new IntegraIcpClient('channel', integraHttp(fn () => integraResponse(['clearances' => $list]))));
        expect($auth->clearances(str_repeat('a', 43), 'https://client.example/callback'))->toBe($list);
    }
});

it('rejects malformed clearance responses', function (array $data): void {
    $auth = new IntegraIcpAuthorization(new IntegraIcpClient('channel', integraHttp(fn () => integraResponse($data))));
    expect(fn () => $auth->clearances(str_repeat('a', 43), 'https://client.example/callback'))->toThrow(SignerException::class);
})->with([
    [['clearances' => 'invalid']], [['clearances' => [null]]], [['clearances' => [['clearanceId' => 'id']]]],
    [['clearances' => [['clearanceId' => 'id', 'productName' => 'p', 'providerName' => 'p', 'clearanceEndpoint' => 'http://unsafe', 'clearanceType' => 't']]]],
]);

it('completes a cryptographically valid PAdES PDF using IntegraICP RAW', function (): void {
    $bundle = Pkcs12Fixture::load();
    $verifier = IntegraIcpPkce::generateVerifier();
    $http = integraHttp(function ($method, $url, $headers, $body) use ($bundle, $verifier) {
        expect($url)->toStartWith('https://services.integraicp.com.br/c/channel/icp/v3/');
        if ($method === 'GET') {
            parse_str(parse_url($url, PHP_URL_QUERY), $query);
            expect($query)->toMatchArray(['secret_type' => 'code_verifier', 'secret_data' => $verifier]);

            return integraResponse(['credentialId' => 'credential', 'certificateInformation' => ['encodedX509' => $bundle['cert']]]);
        }
        $request = json_decode($body, true, flags: JSON_THROW_ON_ERROR);
        expect($request)->toMatchArray(['credentialId' => 'credential', 'secretType' => 'code_verifier', 'secretData' => $verifier])
            ->and($request['requests'][0]['signaturePolicy'])->toBe('RAW');
        $item = $request['requests'][0];
        $info = hex2bin('3031300d060960864801650304020105000420').base64_decode($item['contentDigest'], true);
        openssl_private_encrypt($info, $raw, $bundle['pkey'], OPENSSL_PKCS1_PADDING);

        return integraResponse(['executionStatus' => ['currentStatus' => 'COMPLETED_WITH_SUCCESS'],
            'certificateInformation' => ['encodedX509' => $bundle['cert']],
            'signatures' => [$item + ['signedContent' => base64_encode($raw)]]]);
    });
    $client = new IntegraIcpClient('channel', $http);
    $cert = (new IntegraIcpCertificateDiscovery($client, 'credential', $verifier))->certificates('credential')[0];
    $builder = Signer::externalSigner()->withPdfContent(PdfFixtureFactory::minimalPdf())
        ->withCertificate($cert->certificate->certificatePem)->withoutDefaultAppearance()->withPadesBaselineB();
    $prepared = $builder->prepare();
    $raw = (new IntegraIcpSignatureProvider($client, 'credential', $verifier))->sign($prepared->payload, $cert);
    $pdf = $builder->complete($prepared->state, $raw->bytes);
    expect(Signer::validation()->withPdfContent($pdf)->disableTrustChainValidation()->validate()->allValid)->toBeTrue();
});

it('sanitizes transport and envelope failures', function (int $status, string $body): void {
    $client = new IntegraIcpClient('private-channel', integraHttp(fn () => new HttpResponse($status, $body)));
    try {
        $client->json('GET', 'credentials/private-credential', query: ['secret_data' => 'private-verifier']);
        test()->fail('Expected exception');
    } catch (SignerException $error) {
        expect($error->getMessage())->not->toContain('private-channel', 'private-credential', 'private-verifier');
    }
})->with([[403, '{"error":{"message":"private-verifier"}}'], [200, 'invalid'], [200, '{"data":"invalid"}'], [200, '{"data":[],"error":{}}']]);

it('validates configuration and authorization input', function (): void {
    $http = integraHttp(fn () => integraResponse([]));
    $auth = new IntegraIcpAuthorization(new IntegraIcpClient('channel', $http));
    expect(fn () => new IntegraIcpClient('', $http))->toThrow(InvalidArgumentException::class)
        ->and(fn () => new IntegraIcpClient('c', $http, timeoutSeconds: 0))->toThrow(InvalidArgumentException::class)
        ->and(fn () => new IntegraIcpClient('c', $http, 'http://unsafe'))->toThrow(InvalidArgumentException::class)
        ->and(fn () => IntegraIcpPkce::challenge('short'))->toThrow(InvalidArgumentException::class)
        ->and(fn () => $auth->authorizationUrl('short', 'https://client.example'))->toThrow(InvalidArgumentException::class)
        ->and(fn () => $auth->authorizationUrl(str_repeat('a', 43), 'http://client.example'))->toThrow(InvalidArgumentException::class)
        ->and(fn () => $auth->authorizationUrl(str_repeat('a', 43), 'https://client.example', 'invalid'))->toThrow(InvalidArgumentException::class)
        ->and(fn () => $auth->authorizationUrl(str_repeat('a', 43), 'https://client.example', credentialLifetimeSeconds: 604801))->toThrow(InvalidArgumentException::class)
        ->and(fn () => $auth->authorizationUrl(str_repeat('a', 43), 'https://client.example', clearanceLifetimeSeconds: 86401))->toThrow(InvalidArgumentException::class)
        ->and(fn () => new IntegraIcpCertificateDiscovery(new IntegraIcpClient('c', $http), '', str_repeat('a', 43)))->toThrow(InvalidArgumentException::class)
        ->and(fn () => new IntegraIcpSignatureProvider(new IntegraIcpClient('c', $http), '', str_repeat('a', 43)))->toThrow(InvalidArgumentException::class);
});

it('refuses credential substitution and unusable certificates', function (): void {
    $client = new IntegraIcpClient('c', integraHttp(fn () => integraResponse(['credentialId' => 'other'])));
    $discovery = new IntegraIcpCertificateDiscovery($client, 'credential', str_repeat('a', 43));
    expect(fn () => $discovery->certificates('other'))->toThrow(SignerException::class, 'identifier')
        ->and(fn () => $discovery->certificates())->toThrow(SignerException::class, 'credential ID');
    $invalid = new IntegraIcpClient('c', integraHttp(fn () => integraResponse(['credentialId' => 'credential', 'certificateInformation' => ['encodedX509' => 'invalid']])));
    expect(fn () => (new IntegraIcpCertificateDiscovery($invalid, 'credential', str_repeat('a', 43)))->certificates())->toThrow(SignerException::class, 'X509');
});

it('refuses unsupported signing algorithms and digests', function (): void {
    $client = new IntegraIcpClient('c', integraHttp(fn () => integraResponse([])));
    $provider = new IntegraIcpSignatureProvider($client, 'credential', str_repeat('a', 43));
    $cert = new RemoteCertificate('credential', new SigningCertificateDto('invalid'));
    $unsupported = new ExternalSigningPayload('', SigningInputType::Digest, HashAlgorithm::Sha512, SignatureAlgorithm::RsaPkcs1V15, SignatureEncoding::RsaPkcs1);
    $short = new ExternalSigningPayload(base64_encode('short'), SigningInputType::Digest, HashAlgorithm::Sha256, SignatureAlgorithm::RsaPkcs1V15, SignatureEncoding::RsaPkcs1);
    expect(fn () => $provider->sign($unsupported, $cert))->toThrow(SignerException::class, 'SHA-256')
        ->and(fn () => $provider->sign($short, $cert))->toThrow(SignerException::class, 'digest');
});

it('refuses pending and substituted signing responses', function (string $failure): void {
    $bundle = Pkcs12Fixture::load();
    $http = integraHttp(function ($method, $url, $headers, $body) use ($bundle, $failure) {
        $request = json_decode($body, true);
        $item = $request['requests'][0] + ['signedContent' => base64_encode('raw')];
        $data = ['executionStatus' => ['currentStatus' => 'COMPLETED_WITH_SUCCESS'],
            'certificateInformation' => ['encodedX509' => $bundle['cert']], 'signatures' => [$item]];
        switch ($failure) {
            case 'pending': $data['executionStatus']['currentStatus'] = 'PENDING_AUTHORIZATON';
                break;
            case 'certificate': $data['certificateInformation']['encodedX509'] = 'other';
                break;
            case 'list': $data['signatures'] = [];
                break;
            case 'id': $data['signatures'][0]['contentId'] = 'other';
                break;
            case 'digest': $data['signatures'][0]['contentDigest'] = base64_encode(random_bytes(32));
                break;
            case 'base64': $data['signatures'][0]['signedContent'] = '***';
                break;
        }

        return integraResponse($data);
    });
    $provider = new IntegraIcpSignatureProvider(new IntegraIcpClient('c', $http), 'credential', str_repeat('a', 43));
    $cert = new RemoteCertificate('credential', new SigningCertificateDto($bundle['cert']));
    $payload = new ExternalSigningPayload(base64_encode(random_bytes(32)), SigningInputType::Digest, HashAlgorithm::Sha256, SignatureAlgorithm::RsaPkcs1V15, SignatureEncoding::RsaPkcs1);
    expect(fn () => $provider->sign($payload, $cert))->toThrow(SignerException::class);
})->with(['pending', 'certificate', 'list', 'id', 'digest', 'base64']);

function integraResponse(array $data): HttpResponse
{
    return new HttpResponse(200, json_encode(['data' => $data], JSON_THROW_ON_ERROR));
}

function integraHttp(callable $callback): HttpClientInterface
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
