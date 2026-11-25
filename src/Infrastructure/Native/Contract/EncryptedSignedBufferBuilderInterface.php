<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Infrastructure\Native\Contract;

use SignerPHP\PdfCore\Buffer;
use SignerPHP\PdfCore\PdfDocument;
use SignerPHP\PdfSigner\Application\Contract\SignatureProviderInterface;
use SignerPHP\PdfSigner\Application\DTO\SigningContextDto;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\Encryption\EncryptedPdfDocument;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\SignatureHandler;

/**
 * Signs an encrypted PDF: the signature is built on the document's clear mirror and appended to the
 * encrypted file with its objects encrypted (ISO 32000-2 §7.6.2).
 */
interface EncryptedSignedBufferBuilderInterface extends SignedBufferBuilderInterface
{
    /**
     * @param  PdfDocument  $plainMirrorDocument  {@see EncryptedPdfDocument::plainMirror()} prepared by pdf-core
     */
    public function buildEncrypted(
        EncryptedPdfDocument $encryptedDocument,
        PdfDocument $plainMirrorDocument,
        SignatureHandler $signatureHandler,
        SigningContextDto $context,
        SignatureProviderInterface $signatureProvider,
    ): Buffer;
}
