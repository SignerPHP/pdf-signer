<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Infrastructure\Native\Contract;

use SignerPHP\PdfSigner\Application\DTO\TimestampOptionsDto;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\Encryption\EncryptedPdfDocument;

/**
 * Adds a document timestamp to an encrypted PDF, with the timestamp token covering the final encrypted bytes.
 */
interface EncryptedDocumentTimestampApplierInterface extends DocumentTimestampApplierInterface
{
    public function applyToEncrypted(EncryptedPdfDocument $document, TimestampOptionsDto $options): EncryptedPdfDocument;
}
