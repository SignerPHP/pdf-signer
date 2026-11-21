# CSC v1 laboratory adapter (experimental)

Supported wire protocol: **CSC API v1.0.4.0**, exercised with Certomancer CSC Dummy 0.4.2. This does not establish CSC 2.2 conformity, commercial interoperability, or production readiness. The adapter's reference server is MIT licensed.

## Responsibility and scope

The client uses the existing HttpClientInterface and explicit /csc/v1 endpoints. Discovery returns a credential identifier and public X.509 certificate/chain before PDF preparation. The first implementation accepts enabled RSA credentials for SHA-256 with RSA PKCS#1 v1.5 only.

CscSignatureProvider sends exactly the SHA-256 digest of CMS signed attributes in ExternalSigningPayload, not a hash of the original PDF, to credentials/authorize and signatures/signHash. It does not hash it again. The signer response is verified locally against the selected public certificate and requested digest, and SignatureValue is passed back to the existing PDF finalizer.

Only one synchronous operation is supported. Authorization obtains a single hash-bound SAD, including for SCAL 2. The caller supplies any required service access token. The adapter does not implement OAuth token acquisition, interactive PIN or OTP. Transport errors are sanitized. No request is automatically retried, because a signHash timeout is an uncertain signing outcome.

## Deterministic tests

Run the local mock HTTP contract tests without internet access:

    composer install
    vendor/bin/pest --configuration phpunit.xml tests/Unit/CscModuleTest.php

These cover discovery, authorization, algorithms, cryptographic matching, PAdES B-B output, invalid HTTP response and certificate mismatch. They never call a remote service.

## Opt-in laboratory

Create a disposable environment containing synthetic key material. Certomancer's public example.yml uses keys from tests/data/keys-rsa. The dummy server should never be exposed publicly or used with production keys.

    git clone --depth 1 https://github.com/MatthiasValvekens/certomancer.git
    python3 -m venv .venv
    . .venv/bin/activate
    pip install 'certomancer-csc-dummy==0.4.2'
    certomancer-csc certomancer/example.yml 19143 2

In the SignerPHP checkout, execute:

    CSC_LAB_BASE_URL=http://127.0.0.1:19143 CSC_LAB_CREDENTIAL_ID=testing-ca/signer1-long vendor/bin/pest --configuration phpunit.xml tests/Integration/CscLabTest.php

The laboratory test is skipped unless both variables are present, so mandatory CI does not require internet. The integration test disables PKI trust-chain validation for the synthetic certificate, but checks cryptographic signature validity and PDF PAdES B-B markers. Private keys remain inside the laboratory server; the PDF engine receives only the public certificate and signature bytes.

## Usage and public contract

Instantiate CscClient with CurlHttpClient, the trusted CSC service base URL and optional service access token. Use CscCertificateDiscovery::certificates($credentialId) to select a RemoteCertificate; pass its certificate PEM and chain to Signer::externalSigner()->withCertificate(...), then call prepare(). Pass the prepared ExternalSigningPayload and selected RemoteCertificate to CscSignatureProvider::sign(). Finally call the existing builder complete() with the prepared state and returned SignatureValue::bytes.

LibreSign should consume the current RemoteCertificateDiscoveryInterface, RemoteSignatureProviderInterface, ExternalSigningPayload, and prepare()/complete() contract. CSC's SAD, version-specific HTTP fields and protocol credentials stay inside the adapter, rather than becoming a LibreSign domain model.

## Explicit limitations and pending decisions

No CSC v2.x, ECDSA, RSA-PSS, batch signing, dynamic credential provisioning, asynchronous authorization, signatures/signPolling, PIN/OTP, OAuth token management, transaction extension, timestamping, trust anchors, revocation checking, replay prevention or commercial provider homologation has been implemented.

Application-side session persistence, unknown-outcome reconciliation, authorization state, user assignment and policy must be decided in LibreSign #8356, #8942 and #8943; do not freeze a new public integration API for those concerns now.
