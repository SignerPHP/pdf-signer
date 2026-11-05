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
// Use exactly the callback URL registered with Valid; do not append per-request state.
$callbackUri = 'https://your-app.example/signature-return';
// Before redirecting, persist the verifier and pending signing context server-side,
// bound to the logged-in user's session, document and a short expiry.
$authorizationUrl = $authorization->authorizationUrl($challenge, $callbackUri, $cpf);
// Navigate the user's browser to $authorizationUrl. autostart selects the first clearance.
// Alternatively, call clearances() and let the user choose a clearanceEndpoint.

// After the callback: require the initiating session, an unexpired pending request
// and document ownership. Reject missing, expired or already consumed requests.
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

The credential identifies the certificate selected during provider authorization; discovery returns that single certificate. A request cannot substitute a different credential or certificate. Signature responses must match the content ID, SHA-256 digest and public certificate, and indicate successful completion. Before returning a signature, the adapter also verifies RSA PKCS#1 v1.5 padding and the SHA-256 DigestInfo against the requested digest using the authorized certificate public key; the digest is not hashed again.

Treat channel, credential ID, verifier, authorization URLs and callback parameters as secrets: exclude them from access logs, traces and analytics. Never send the verifier in the authorization URL. The v3 reference does not specify the callback query parameter name or separate push/poll endpoints; applications must confirm the callback contract and use the provider's hosted authorization flow rather than inventing endpoints.

The reference provides only the signer's X509 certificate, without a chain. Supply a trusted chain through `withCertificate($pem, $chain)` if required by your verification policy. Validate a pilot PDF with the ITI validator. Tests exercise the documented HTTP contract with simulated responses and cryptographic PDF verification; they do not prove live channel access, pricing, provider availability or the callback contract.

## Registered callback and live verification

The [Valid IntegraICP FAQ, question 19](https://validcertificadora.com.br/pages/integraicp-faq) requires the callback URL to match the registered URL exactly. Older API examples show variable query strings; this guide follows the FAQ and uses a fixed callback. Do not append a random `state` or document ID to `callback_uri` unless Valid explicitly confirms support for your channel.

Keep correlation in server-side session/request storage, including the verifier, expected signer, document and expiry. For a simple session-based flow, allow only one pending authorization per session and reject a second start until the first is completed, cancelled or expired; do not overwrite its verifier. Require the initiating session on return, check the returned credential using that request's verifier, and compare the certificate holder with the expected signer before signing. Consume the pending request once, atomically, to reject replay. If your application needs parallel authorizations or callbacks without the original browser session, first agree a supported correlation mechanism with Valid; do not infer one from URL encoding tests.

Live channel verification remains pending. With a registered channel, confirm the exact callback URL and returned parameter names, then exercise authorization, certificate discovery and RAW signing through the real hosted flow. Check session correlation, expiry, replay rejection and a second authorization attempt, and validate the resulting pilot PDF. Simulated tests do not establish callback acceptance by Valid. Never include channel credentials, verifier values or authorization URLs in recorded evidence.
