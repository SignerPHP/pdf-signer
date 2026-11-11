# BirdID cloud signing

Reference: [BirdID Public API](https://docs.vaultid.com.br/workspace/cloud/api/uso-de-certificado/assinatura-digital). Request `client_id` / `client_secret` from Soluti for your application. This adapter does **not** use CESS or BirdID Sign.

This module implements `RemoteCertificateDiscoveryInterface` and `RemoteSignatureProviderInterface`. It requests **RAW SHA-256 / RSA PKCS#1 v1.5** signatures over a **hexadecimal** digest. The library assembles CMS and the final PAdES PDF.

```php
use SignerPHP\PdfSigner\Infrastructure\Native\Service\CurlHttpClient;
use SignerPHP\PdfSigner\Infrastructure\Remote\BirdId\BirdIdAuthorization;
use SignerPHP\PdfSigner\Infrastructure\Remote\BirdId\BirdIdCertificateDiscovery;
use SignerPHP\PdfSigner\Infrastructure\Remote\BirdId\BirdIdClient;
use SignerPHP\PdfSigner\Infrastructure\Remote\BirdId\BirdIdPkce;
use SignerPHP\PdfSigner\Infrastructure\Remote\BirdId\BirdIdSignatureProvider;
use SignerPHP\PdfSigner\Presentation\Signer;

$http = new CurlHttpClient();
$authorization = new BirdIdAuthorization($http, $clientId, $clientSecret);
$discovery = $authorization->discoverUser($cpf);
if (! $discovery->hasCertificate) {
    // Guide the user to issue a BirdID cloud certificate.
}

$verifier = BirdIdPkce::generateVerifier();
$authorizationUrl = $authorization->authorizationUrl(
    codeChallenge: BirdIdPkce::challenge($verifier),
    redirectUri: $callbackUrl,
    state: $state,
    loginHint: $cpf,
);

// After the authorization callback:
$token = $authorization->exchangeAuthorizationCode($authorizationCode, $verifier, $callbackUrl);
$client = new BirdIdClient($token->value, $http);
$certificate = (new BirdIdCertificateDiscovery($client))->certificates()[0];

$builder = Signer::externalSigner()
    ->withPdfContent($pdf)
    ->withCertificate($certificate->certificate->certificatePem)
    ->withPadesBaselineB();
$prepared = $builder->prepare();
$signature = (new BirdIdSignatureProvider($client))->sign($prepared->payload, $certificate);
$signedPdf = $builder->complete($prepared->state, $signature->bytes);
```

For desktop / OTP flows without a browser redirect, call `authorizeWithPassword($cpf, $otp)` instead of the authorization-code exchange. Password grants may return multiple certificates; present aliases to the user and pass the selected `RemoteCertificate`.

Use `BirdIdClient::PRODUCTION_URL` (`https://api.birdid.com.br`) by default. Older VaultID accounts may still live at `BirdIdClient::VAULT_ID_URL`. Cache negative user-discovery results for a few hours as recommended by Soluti.

BirdID signs only hashes. Validate a pilot PDF with the ITI verifier. Unit tests exercise the documented HTTP contract with simulated responses and cryptographic PDF verification; they do not prove live Soluti credentials or production availability.
