<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Infrastructure\Native\Service;

use SignerPHP\PdfSigner\Application\DTO\ProtectionOptionsDto;
use SignerPHP\PdfSigner\Infrastructure\Native\Contract\PdfProtectionApplierInterface;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\Encryption\Aes128StandardSecurityHandler;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\Encryption\Aes256StandardSecurityHandler;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\Encryption\PdfArrayNode;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\Encryption\PdfDictionaryNode;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\Encryption\PdfEncryptedDocumentWriter;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\Encryption\PdfObjectGraphReader;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\Encryption\PdfStringNode;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\Encryption\StandardSecurityPermissions;

/**
 * Encrypts a PDF with the standard security handler in pure PHP (no external binaries).
 *
 * 256-bit keys use AES-256 (/V 5 /R 6, ISO 32000-2); 128-bit keys use AES-128 (/V 4 /R 4).
 * The document is rewritten as a single revision, so any existing signature is invalidated.
 */
final readonly class NativePdfProtectionApplier implements PdfProtectionApplierInterface
{
    public function __construct(
        private PdfObjectGraphReader $graphReader = new PdfObjectGraphReader,
        private PdfEncryptedDocumentWriter $documentWriter = new PdfEncryptedDocumentWriter,
    ) {}

    public function apply(string $pdfContent, ProtectionOptionsDto $options): string
    {
        $graph = $this->graphReader->read($pdfContent);
        $documentId = self::documentId($graph->trailer);
        $ownerPassword = $options->ownerPassword ?? bin2hex(random_bytes(16));
        $permissions = StandardSecurityPermissions::fromOptions($options);

        $handler = $options->keyLengthBits === 128
            ? new Aes128StandardSecurityHandler($options->userPassword, $ownerPassword, $permissions, $options->encryptMetadata, $documentId[0])
            : new Aes256StandardSecurityHandler($options->userPassword, $ownerPassword, $permissions, $options->encryptMetadata);

        return $this->documentWriter->write($graph, $handler, $documentId, $options->encryptMetadata);
    }

    /**
     * Keeps the permanent identifier of the source document and creates a new changing identifier
     * (§14.4); a document without /ID gets a fresh one.
     *
     * @return array{0: string, 1: string}
     */
    private static function documentId(PdfDictionaryNode $trailer): array
    {
        $id = $trailer->get('ID');
        $first = $id instanceof PdfArrayNode ? ($id->items[0] ?? null) : null;
        $permanent = $first instanceof PdfStringNode && $first->bytes !== '' ? $first->bytes : random_bytes(16);

        return [$permanent, random_bytes(16)];
    }
}
