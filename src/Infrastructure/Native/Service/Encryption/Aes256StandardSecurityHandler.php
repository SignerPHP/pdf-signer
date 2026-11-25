<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Infrastructure\Native\Service\Encryption;

use SignerPHP\PdfSigner\Domain\Exception\ProtectionProcessException;

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
        $userPassword = self::preparePassword($userPassword);
        $ownerPassword = self::preparePassword($ownerPassword);
        $this->fileKey = random_bytes(32);

        // Algorithm 8: /U and /UE.
        $userValidationSalt = random_bytes(8);
        $userKeySalt = random_bytes(8);
        $this->userEntry = self::hash($userPassword, $userValidationSalt, '').$userValidationSalt.$userKeySalt;
        $this->userKeyEntry = self::aesCbcNoPadding($this->fileKey, self::hash($userPassword, $userKeySalt, ''));

        // Algorithm 9: /O and /OE (salted with the full 48-byte /U).
        $ownerValidationSalt = random_bytes(8);
        $ownerKeySalt = random_bytes(8);
        $this->ownerEntry = self::hash($ownerPassword, $ownerValidationSalt, $this->userEntry).$ownerValidationSalt.$ownerKeySalt;
        $this->ownerKeyEntry = self::aesCbcNoPadding($this->fileKey, self::hash($ownerPassword, $ownerKeySalt, $this->userEntry));

        // Algorithm 10: /Perms.
        $perms = pack('V', $this->permissions & 0xFFFFFFFF)."\xFF\xFF\xFF\xFF"
            .($this->encryptMetadata ? 'T' : 'F').'adb'.random_bytes(4);
        $this->permsEntry = self::openssl($perms, 'aes-256-ecb', $this->fileKey, OPENSSL_ZERO_PADDING, '');
    }

    public function encrypt(string $data, int $objectNumber, int $generation): string
    {
        // §7.6.3.2: with AESV3 the file key is used directly; output is a random 16-byte IV followed by the PKCS#5 padded cipher text.
        $iv = random_bytes(16);

        return $iv.self::openssl($data, 'aes-256-cbc', $this->fileKey, 0, $iv);
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

    /**
     * §7.6.4.3.3: passwords are UTF-8 (after SASLprep) truncated to 127 bytes.
     */
    private static function preparePassword(string $password): string
    {
        return substr($password, 0, 127);
    }

    /**
     * Algorithm 2.B: hardened hash for revision 6.
     */
    private static function hash(string $password, string $salt, string $userEntry): string
    {
        $key = hash('sha256', $password.$salt.$userEntry, true);
        $round = 0;

        while (true) {
            $block = str_repeat($password.$key.$userEntry, 64);
            $encrypted = self::openssl($block, 'aes-128-cbc', substr($key, 0, 16), OPENSSL_ZERO_PADDING, substr($key, 16, 16));

            // The first 16 bytes taken as a big-endian number, modulo 3, equals the sum of those bytes modulo 3 (256 ≡ 1 mod 3).
            $algorithm = match (array_sum(array_map('ord', str_split(substr($encrypted, 0, 16)))) % 3) {
                0 => 'sha256',
                1 => 'sha384',
                default => 'sha512',
            };
            $key = hash($algorithm, $encrypted, true);
            $round++;

            if ($round >= 64 && ord($encrypted[strlen($encrypted) - 1]) <= $round - 32) {
                return substr($key, 0, 32);
            }
        }
    }

    private static function aesCbcNoPadding(string $data, string $key): string
    {
        return self::openssl($data, 'aes-256-cbc', $key, OPENSSL_ZERO_PADDING, str_repeat("\0", 16));
    }

    private static function openssl(string $data, string $cipher, string $key, int $options, string $iv): string
    {
        $result = openssl_encrypt($data, $cipher, $key, OPENSSL_RAW_DATA | $options, $iv);
        if ($result === false) {
            throw new ProtectionProcessException(sprintf('OpenSSL could not encrypt data with %s.', $cipher));
        }

        return $result;
    }
}
