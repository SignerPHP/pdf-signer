<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Infrastructure\Native\Service\Encryption;

use SignerPHP\PdfSigner\Domain\Exception\ProtectionProcessException;

/**
 * AES-128 standard security handler, revision 4 (ISO 32000-1 §7.6.3, algorithms 1–5): /V 4 /R 4, crypt filter AESV2.
 *
 * Deprecated by ISO 32000-2 in favour of AES-256, kept because the public API offers 128-bit protection.
 */
final class Aes128StandardSecurityHandler implements StandardSecurityHandlerInterface
{
    private const KEY_LENGTH = 16;

    private readonly string $ownerEntry;

    private readonly string $userEntry;

    private readonly string $fileKey;

    public function __construct(
        string $userPassword,
        string $ownerPassword,
        private readonly int $permissions,
        private readonly bool $encryptMetadata,
        string $documentId,
    ) {
        $paddedUser = StandardSecurityPrimitives::padPassword($userPassword);
        $paddedOwner = StandardSecurityPrimitives::padPassword($ownerPassword);

        // Algorithm 3: /O.
        $ownerKey = StandardSecurityPrimitives::iterateMd5(md5($paddedOwner, true), self::KEY_LENGTH);
        $this->ownerEntry = StandardSecurityPrimitives::rc4Rounds($ownerKey, $paddedUser);

        // Algorithm 2: file encryption key.
        $keyInput = $paddedUser.$this->ownerEntry.pack('V', $this->permissions & 0xFFFFFFFF).$documentId;
        if (! $this->encryptMetadata) {
            $keyInput .= "\xFF\xFF\xFF\xFF";
        }
        $this->fileKey = StandardSecurityPrimitives::iterateMd5(md5($keyInput, true), self::KEY_LENGTH);

        // Algorithm 5: /U (16 significant bytes followed by 16 arbitrary bytes).
        $this->userEntry = StandardSecurityPrimitives::rc4Rounds($this->fileKey, md5(StandardSecurityPrimitives::PADDING.$documentId, true)).random_bytes(16);
    }

    public function encrypt(string $data, int $objectNumber, int $generation): string
    {
        // Algorithm 1 with the AES "sAlT" suffix: per-object key, then AES-128-CBC with a random IV prefix.
        $objectKey = md5(
            $this->fileKey.substr(pack('V', $objectNumber), 0, 3).substr(pack('V', $generation), 0, 2).'sAlT',
            true,
        );
        $iv = random_bytes(16);
        $encrypted = openssl_encrypt($data, 'aes-128-cbc', $objectKey, OPENSSL_RAW_DATA, $iv);
        if ($encrypted === false) {
            throw new ProtectionProcessException('OpenSSL could not encrypt data with aes-128-cbc.');
        }

        return $iv.$encrypted;
    }

    public function encryptionDictionary(): PdfDictionaryNode
    {
        $dictionary = new PdfDictionaryNode([
            ['Filter', new PdfRawNode('/Standard')],
            ['V', new PdfRawNode('4')],
            ['R', new PdfRawNode('4')],
            ['Length', new PdfRawNode('128')],
            ['CF', new PdfDictionaryNode([
                ['StdCF', new PdfDictionaryNode([
                    ['AuthEvent', new PdfRawNode('/DocOpen')],
                    ['CFM', new PdfRawNode('/AESV2')],
                    ['Length', new PdfRawNode('16')],
                ])],
            ])],
            ['StmF', new PdfRawNode('/StdCF')],
            ['StrF', new PdfRawNode('/StdCF')],
            ['O', new PdfStringNode($this->ownerEntry)],
            ['U', new PdfStringNode($this->userEntry)],
            ['P', new PdfRawNode((string) $this->permissions)],
        ]);

        if (! $this->encryptMetadata) {
            $dictionary->set('EncryptMetadata', new PdfRawNode('false'));
        }

        return $dictionary;
    }

    public function minimumPdfVersion(): string
    {
        return '1.6';
    }

    public function adobeExtensionLevel(): ?int
    {
        return null;
    }
}
