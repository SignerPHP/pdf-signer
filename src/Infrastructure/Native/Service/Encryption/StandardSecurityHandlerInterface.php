<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Infrastructure\Native\Service\Encryption;

/**
 * Standard security handler (ISO 32000-2 §7.6.4): password based encryption of strings and streams.
 */
interface StandardSecurityHandlerInterface
{
    /**
     * Encrypts a string or stream belonging to the given indirect object.
     */
    public function encrypt(string $data, int $objectNumber, int $generation): string;

    /**
     * The /Encrypt dictionary to be referenced from the trailer.
     */
    public function encryptionDictionary(): PdfDictionaryNode;

    /**
     * Lowest PDF header version that supports this handler.
     */
    public function minimumPdfVersion(): string;

    /**
     * Adobe extension level to declare in the catalog (/Extensions /ADBE), or null when none is needed.
     */
    public function adobeExtensionLevel(): ?int;
}
