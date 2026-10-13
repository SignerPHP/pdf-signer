# IntegraICP cloud signing

Reference: [IntegraICP v3](https://developers.integraicp.com.br/api-reference/icp/v3/index.html), revised 2024-05-22. Request a channel from Valid and confirm the service URL and enabled providers for your environment; this module does not assume a separate sandbox host.

This adapter implements `RemoteCertificateDiscoveryInterface` and `RemoteSignatureProviderInterface`. It requests **RAW SHA-256 / RSA PKCS#1 v1.5** signatures. The library assembles CMS and the final PAdES PDF. IntegraICP's CMS response is not accepted as a `SignatureValue`.

```php
use SignerPHP\PdfSigner\Infrastructure\Native\Service\CurlHttpClient;
use SignerPHP\PdfSigner\Infrastructure\Remote\IntegraIcp\IntegraIcpAuthorization;
use SignerPHP\PdfSigner\Infrastructure\Remote\IntegraIcp\IntegraIcpCertificateDiscovery;
use SignerPHP\PdfSigner\Infrastructure\Remote\IntegraIcp\IntegraIcpClient;
use SignerPHP\PdfSigner\Infrastructure\Remote\IntegraIcp\IntegraIcpPkce;
use SignerPHP\PdfSigner\Infrastructure\Remote\IntegraIcp\IntegraIcpSignatureProvider;
use SignerPHP\PdfSigner\Presentation\Signer;

$client = new IntegraIcpClient($channelId, new CurlHttpClient());
$verifier = IntegraIcpPkce::generateVerifier();
$challenge = IntegraIcpPkce::challenge($verifier);
$authorization = new IntegraIcpAuthorization($client);
// Generate and persist an opaque state bound to the logged-in user and document.
$callbackUri = 'https://your-app.example/signature-return?state='.$state;
$authorizationUrl = $authorization->authorizationUrl($challenge, $callbackUri, $cpf);
// Navigate the user's browser to $authorizationUrl. autostart selects the first clearance.
// Alternatively, call clearances() and let the user choose a clearanceEndpoint.

// After the provider's callback: verify state, session, expiry and document ownership.
// Obtain $credentialId from the callback contract agreed with Valid.
// Keep $verifier server-side; it is required for both discovery and signing.
$certificate = (new IntegraIcpCertificateDiscovery($client, $credentialId, $verifier))
    ->certificates()[0];
// Compare the certificate holder's CPF with the authorized signer in your application.
$builder = Signer::externalSigner()->withPdfContent($pdf)
    ->withCertificate($certificate->certificate->certificatePem)->withPadesBaselineB();
$prepared = $builder->prepare();
$signature = (new IntegraIcpSignatureProvider($client, $credentialId, $verifier))
    ->sign($prepared->payload, $certificate);
$signedPdf = $builder->complete($prepared->state, $signature->bytes);
```

The credential identifies the certificate selected during provider authorization; discovery returns that single certificate. A request cannot substitute a different credential or certificate. Signature responses must match the content ID, SHA-256 digest and public certificate, and indicate successful completion.

Treat channel, credential ID, verifier, authorization URLs and callback parameters as secrets: exclude them from access logs, traces and analytics. Never send the verifier in the authorization URL. The v3 reference does not specify the callback query parameter name or separate push/poll endpoints; applications must confirm the callback contract and use the provider's hosted authorization flow rather than inventing endpoints.

The reference provides only the signer's X509 certificate, without a chain. Supply a trusted chain through `withCertificate($pem, $chain)` if required by your verification policy. Validate a pilot PDF with the ITI validator. Tests exercise the documented HTTP contract with simulated responses and cryptographic PDF verification; they do not prove live channel access, pricing, provider availability or the callback contract.
