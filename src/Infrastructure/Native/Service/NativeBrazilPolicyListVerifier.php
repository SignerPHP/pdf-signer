<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Infrastructure\Native\Service;

use SignerPHP\PdfSigner\Application\DTO\SignatureValidationOptionsDto;
use SignerPHP\PdfSigner\Infrastructure\Native\Contract\BrazilPolicyListVerifierInterface;
use SignerPHP\PdfSigner\Infrastructure\Native\Contract\HttpClientInterface;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\Cms\CmsSignatureVerifier;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\Cms\CmsSignedData;
use SignerPHP\PdfSigner\Infrastructure\Native\ValueObject\SignaturePolicyVerification;

/**
 * Verifies the signature of the ICP-Brasil LPA (PAdES policy list) in PHP (no `openssl` binary).
 */
final class NativeBrazilPolicyListVerifier implements BrazilPolicyListVerifierInterface
{
    public function __construct(
        private readonly HttpClientInterface $httpClient = new CurlHttpClient,
        private readonly CmsSignatureVerifier $cmsVerifier = new CmsSignatureVerifier,
    ) {}

    public function verifyPadesPolicy(SignatureValidationOptionsDto $options): SignaturePolicyVerification
    {
        $lpaUrl = $options->lpaUrlAsn1Pades;
        $sigUrl = $options->lpaUrlAsn1SignaturePades;
        if ($lpaUrl === null || $sigUrl === null) {
            return new SignaturePolicyVerification(false, 'LPA PAdES URLs are not configured for BR-ITI policy.');
        }

        $lpa = $this->download($lpaUrl, 20);
        if ($lpa === null) {
            return new SignaturePolicyVerification(false, 'Could not download LPA PAdES ASN.1 from '.$lpaUrl);
        }

        $signature = $this->download($sigUrl, 20);
        if ($signature === null) {
            return new SignaturePolicyVerification(false, 'Could not download LPA PAdES signature from '.$sigUrl);
        }

        try {
            $signedData = CmsSignedData::fromDer($this->signatureDer($signature));
        } catch (\UnexpectedValueException) {
            return new SignaturePolicyVerification(false, 'LPA PAdES signature verification failed.');
        }

        return $this->cmsVerifier->verify($signedData, $lpa)->valid
            ? new SignaturePolicyVerification(true)
            : new SignaturePolicyVerification(false, 'LPA PAdES signature verification failed.');
    }

    /**
     * The LPA signature is published as DER; PEM and S/MIME (base64 body) encodings are accepted too.
     */
    private function signatureDer(string $signature): string
    {
        if (str_starts_with($signature, "\x30")) {
            return $signature;
        }

        $body = preg_replace('/-----[^-]+-----/', '', $signature) ?? '';
        $headerEnd = preg_match('/\R\R/', $body, $match, PREG_OFFSET_CAPTURE) === 1 && preg_match('/\A[\w-]+:/', $body) === 1
            ? $match[0][1]
            : 0;
        $decoded = base64_decode(preg_replace('/\s+/', '', substr($body, $headerEnd)) ?? '', true);

        return $decoded === false ? $signature : $decoded;
    }

    private function download(string $url, int $timeoutSeconds): ?string
    {
        $response = $this->httpClient->request('GET', $url, [], '', $timeoutSeconds);
        if (! $response->isSuccessful() || $response->body === '' || $response->transportError !== null) {
            return null;
        }

        return $response->body;
    }
}
