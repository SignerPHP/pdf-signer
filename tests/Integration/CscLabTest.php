<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Tests\Integration;

use PHPUnit\Framework\TestCase;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\CurlHttpClient;
use SignerPHP\PdfSigner\Infrastructure\Remote\Csc\CscCertificateDiscovery;
use SignerPHP\PdfSigner\Infrastructure\Remote\Csc\CscClient;
use SignerPHP\PdfSigner\Infrastructure\Remote\Csc\CscSignatureProvider;
use SignerPHP\PdfSigner\Presentation\Signer;
use SignerPHP\PdfSigner\Tests\Support\PdfFixtureFactory;

final class CscLabTest extends TestCase
{
    public function test_certomancer_dummy_csc_v1_signs_a_cryptographically_valid_pades_b_b_pdf(): void
    {
        $url = getenv('CSC_LAB_BASE_URL');
        $credentialId = getenv('CSC_LAB_CREDENTIAL_ID');
        if (! is_string($url) || $url === '' || ! is_string($credentialId) || $credentialId === '') {
            self::markTestSkipped('CSC lab is opt-in: configure CSC_LAB_BASE_URL and CSC_LAB_CREDENTIAL_ID.');
        }
        $client = new CscClient(new CurlHttpClient, $url, timeoutSeconds: 20);
        $credentials = (new CscCertificateDiscovery($client))->certificates($credentialId);
        self::assertCount(1, $credentials);
        $credential = $credentials[0];
        $builder = Signer::externalSigner()
            ->withPdfContent(PdfFixtureFactory::minimalPdf())
            ->withCertificate($credential->certificate->certificatePem, $credential->certificate->chainPem)
            ->withoutDefaultAppearance()
            ->withPadesBaselineB();
        $prepared = $builder->prepare();
        $signature = (new CscSignatureProvider($client))->sign($prepared->payload, $credential);
        $pdf = $builder->complete($prepared->state, $signature->bytes);
        $verification = Signer::validation()
            ->withPdfContent($pdf)
            ->disableTrustChainValidation()
            ->validate();
        self::assertTrue($verification->hasSignatures);
        self::assertTrue($verification->allValid);
        self::assertStringContainsString('/ETSI.CAdES.detached', $pdf);
        self::assertStringContainsString('/ByteRange', $pdf);
    }
}
