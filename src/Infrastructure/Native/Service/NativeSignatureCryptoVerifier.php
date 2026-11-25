<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Infrastructure\Native\Service;

use SignerPHP\PdfSigner\Infrastructure\Native\Contract\SignatureCryptoVerifierInterface;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\Cms\CmsSignatureVerifier;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\Cms\CmsSignedData;
use SignerPHP\PdfSigner\Infrastructure\Native\ValueObject\SignatureCryptoVerification;

/**
 * Verifies a detached CMS signature over the signed ByteRange in PHP (no `openssl` binary).
 */
final class NativeSignatureCryptoVerifier implements SignatureCryptoVerifierInterface
{
    public function __construct(
        private readonly CmsSignatureVerifier $cmsVerifier = new CmsSignatureVerifier,
    ) {}

    public function verify(string $signedContent, string $signatureHex): SignatureCryptoVerification
    {
        if ($signatureHex === '' || preg_match('/\A[0]+\z/', $signatureHex) === 1) {
            return new SignatureCryptoVerification(false, 'Empty signature contents.');
        }

        if (strlen($signatureHex) % 2 !== 0 || ! ctype_xdigit($signatureHex)) {
            return new SignatureCryptoVerification(false, 'Invalid signature hex payload.');
        }

        try {
            $signedData = CmsSignedData::fromHex($signatureHex);
        } catch (\UnexpectedValueException $exception) {
            return new SignatureCryptoVerification(false, 'Invalid CMS signature: '.$exception->getMessage());
        }

        $result = $this->cmsVerifier->verify($signedData, $signedContent);

        return new SignatureCryptoVerification($result->valid, $result->message);
    }
}
