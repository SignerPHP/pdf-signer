<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Infrastructure\Native\Service\Encryption;

/**
 * AES-256 standard security handler, revision 6 (ISO 32000-2 §7.6.4.3.3–§7.6.4.4.11): /V 5 /R 6, crypt filter AESV3.
 */
final class Aes256StandardSecurityHandler implements StandardSecurityHandlerInterface
{
    private readonly string $fileKey;

    private readonly string $userEntry;

    private readonly string $userKeyEntry;

    private readonly string $ownerEntry;

    private readonly string $ownerKeyEntry;

    private readonly string $permsEntry;

    public function __construct(
        string $userPassword,
        string $ownerPassword,
        private readonly int $permissions,
        private readonly bool $encryptMetadata,
    ) {
        $userPassword = StandardSecurityPrimitives::prepareUtf8Password($userPassword);
        $ownerPassword = StandardSecurityPrimitives::prepareUtf8Password($ownerPassword);
        $this->fileKey = random_bytes(32);

        // Algorithm 8: /U and /UE.
        $userValidationSalt = random_bytes(8);
        $userKeySalt = random_bytes(8);
        $this->userEntry = StandardSecurityPrimitives::hashR6($userPassword, $userValidationSalt, '').$userValidationSalt.$userKeySalt;
        $this->userKeyEntry = self::aesCbcNoPadding($this->fileKey, StandardSecurityPrimitives::hashR6($userPassword, $userKeySalt, ''));

        // Algorithm 9: /O and /OE (salted with the full 48-byte /U).
        $ownerValidationSalt = random_bytes(8);
        $ownerKeySalt = random_bytes(8);
        $this->ownerEntry = StandardSecurityPrimitives::hashR6($ownerPassword, $ownerValidationSalt, $this->userEntry).$ownerValidationSalt.$ownerKeySalt;
        $this->ownerKeyEntry = self::aesCbcNoPadding($this->fileKey, StandardSecurityPrimitives::hashR6($ownerPassword, $ownerKeySalt, $this->userEntry));

        // Algorithm 10: /Perms.
        $perms = pack('V', $this->permissions & 0xFFFFFFFF)."\xFF\xFF\xFF\xFF"
            .($this->encryptMetadata ? 'T' : 'F').'adb'.random_bytes(4);
        $this->permsEntry = StandardSecurityPrimitives::openssl($perms, 'aes-256-ecb', $this->fileKey, OPENSSL_ZERO_PADDING, '');
    }

    public function encrypt(string $data, int $objectNumber, int $generation): string
    {
        // §7.6.3.2: with AESV3 the file key is used directly; output is a random 16-byte IV followed by the PKCS#5 padded cipher text.
        $iv = random_bytes(16);

        return $iv.StandardSecurityPrimitives::openssl($data, 'aes-256-cbc', $this->fileKey, 0, $iv);
    }

    public function encryptionDictionary(): PdfDictionaryNode
    {
        $dictionary = new PdfDictionaryNode([
            ['Filter', new PdfRawNode('/Standard')],
            ['V', new PdfRawNode('5')],
            ['R', new PdfRawNode('6')],
            ['Length', new PdfRawNode('256')],
            ['CF', new PdfDictionaryNode([
                ['StdCF', new PdfDictionaryNode([
                    ['AuthEvent', new PdfRawNode('/DocOpen')],
                    ['CFM', new PdfRawNode('/AESV3')],
                    ['Length', new PdfRawNode('32')],
                ])],
            ])],
            ['StmF', new PdfRawNode('/StdCF')],
            ['StrF', new PdfRawNode('/StdCF')],
            ['O', new PdfStringNode($this->ownerEntry)],
            ['U', new PdfStringNode($this->userEntry)],
            ['OE', new PdfStringNode($this->ownerKeyEntry)],
            ['UE', new PdfStringNode($this->userKeyEntry)],
            ['Perms', new PdfStringNode($this->permsEntry)],
            ['P', new PdfRawNode((string) $this->permissions)],
        ]);

        if (! $this->encryptMetadata) {
            $dictionary->set('EncryptMetadata', new PdfRawNode('false'));
        }

        return $dictionary;
    }

    public function minimumPdfVersion(): string
    {
        return '1.7';
    }

    public function adobeExtensionLevel(): ?int
    {
        return 8;
    }

    private static function aesCbcNoPadding(string $data, string $key): string
    {
        return StandardSecurityPrimitives::openssl($data, 'aes-256-cbc', $key, OPENSSL_ZERO_PADDING, str_repeat("\0", 16));
    }
}
