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
    private const PADDING = "\x28\xBF\x4E\x5E\x4E\x75\x8A\x41\x64\x00\x4E\x56\xFF\xFA\x01\x08"
        ."\x2E\x2E\x00\xB6\xD0\x68\x3E\x80\x2F\x0C\xA9\xFE\x64\x53\x69\x7A";

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
        $paddedUser = self::padPassword($userPassword);
        $paddedOwner = self::padPassword($ownerPassword);

        // Algorithm 3: /O.
        $ownerKey = self::iterateMd5(md5($paddedOwner, true));
        $this->ownerEntry = self::rc4Rounds($ownerKey, $paddedUser);

        // Algorithm 2: file encryption key.
        $keyInput = $paddedUser.$this->ownerEntry.pack('V', $this->permissions & 0xFFFFFFFF).$documentId;
        if (! $this->encryptMetadata) {
            $keyInput .= "\xFF\xFF\xFF\xFF";
        }
        $this->fileKey = self::iterateMd5(md5($keyInput, true));

        // Algorithm 5: /U (16 significant bytes followed by 16 arbitrary bytes).
        $this->userEntry = self::rc4Rounds($this->fileKey, md5(self::PADDING.$documentId, true)).random_bytes(16);
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

    /**
     * Passwords for revisions 2–4 are PDFDocEncoding; UTF-8 input in the Latin-1 range is converted
     * (PDFDocEncoding matches Latin-1 for those characters), anything else is used as raw bytes.
     */
    private static function padPassword(string $password): string
    {
        return substr(self::toLatin1($password).self::PADDING, 0, 32);
    }

    private static function toLatin1(string $password): string
    {
        if (preg_match('/^[\x00-\x7F]*$/', $password) === 1 || preg_match_all('/./su', $password, $chars) === false) {
            return $password;
        }

        $latin1 = '';
        foreach ($chars[0] as $char) {
            $codePoint = strlen($char) === 1 ? ord($char) : (((ord($char[0]) & 0x1F) << 6) | (ord($char[1] ?? "\0") & 0x3F));
            if (strlen($char) > 2 || $codePoint > 0xFF) {
                return $password;
            }

            $latin1 .= chr($codePoint);
        }

        return $latin1;
    }

    /**
     * Revision 3+: MD5 applied 50 more times to the first n bytes; returns an n-byte key.
     */
    private static function iterateMd5(string $digest): string
    {
        for ($i = 0; $i < 50; $i++) {
            $digest = md5(substr($digest, 0, self::KEY_LENGTH), true);
        }

        return substr($digest, 0, self::KEY_LENGTH);
    }

    /**
     * RC4 with the key, then 19 more passes with the key XOR-ed with the pass number (revision 3+).
     */
    private static function rc4Rounds(string $key, string $data): string
    {
        for ($round = 0; $round < 20; $round++) {
            $roundKey = '';
            for ($i = 0, $length = strlen($key); $i < $length; $i++) {
                $roundKey .= chr(ord($key[$i]) ^ $round);
            }

            $data = self::rc4($roundKey, $data);
        }

        return $data;
    }

    /**
     * RC4 is implemented in PHP because OpenSSL 3 only provides it through the legacy provider.
     */
    private static function rc4(string $key, string $data): string
    {
        $state = range(0, 255);
        $keyLength = strlen($key);

        for ($i = 0, $j = 0; $i < 256; $i++) {
            $j = ($j + $state[$i] + ord($key[$i % $keyLength])) & 0xFF;
            [$state[$i], $state[$j]] = [$state[$j], $state[$i]];
        }

        $output = '';
        for ($n = 0, $i = 0, $j = 0, $length = strlen($data); $n < $length; $n++) {
            $i = ($i + 1) & 0xFF;
            $j = ($j + $state[$i]) & 0xFF;
            [$state[$i], $state[$j]] = [$state[$j], $state[$i]];
            $output .= chr(ord($data[$n]) ^ $state[($state[$i] + $state[$j]) & 0xFF]);
        }

        return $output;
    }
}
