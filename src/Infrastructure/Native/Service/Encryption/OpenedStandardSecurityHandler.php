<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Infrastructure\Native\Service\Encryption;

use SignerPHP\PdfSigner\Domain\Exception\ProtectionProcessException;

/**
 * Standard security handler of an existing encrypted document, opened with its user or owner
 * password, so objects can be read in clear and objects appended to it encrypted with the same key.
 *
 * Supported: RC4 (/V 1–2, /R 2–3), /V 4 /R 4 with the AESV2 or V2 (RC4) crypt filter, and /V 5 /R 6 (AESV3).
 */
final class OpenedStandardSecurityHandler implements StandardSecurityHandlerInterface
{
    private const METHOD_RC4 = 'rc4';

    private const METHOD_AESV2 = 'aesv2';

    private const METHOD_AESV3 = 'aesv3';

    private function __construct(
        private readonly PdfDictionaryNode $encryptionDictionary,
        private readonly string $fileKey,
        private readonly string $method,
        public readonly bool $encryptMetadata,
    ) {}

    /**
     * @param  string  $firstDocumentId  the first element of the trailer /ID
     *
     * @throws ProtectionProcessException when the encryption is not supported or the password is wrong
     */
    public static function open(PdfDictionaryNode $encrypt, string $firstDocumentId, string $password): self
    {
        if ($encrypt->rawToken('Filter') !== '/Standard') {
            throw new ProtectionProcessException('Only the standard security handler is supported for encrypted PDFs.');
        }

        $version = (int) ($encrypt->rawToken('V') ?? '0');
        $revision = (int) ($encrypt->rawToken('R') ?? '0');
        $encryptMetadata = $encrypt->rawToken('EncryptMetadata') !== 'false';

        return match (true) {
            $version === 5 && $revision === 6 => self::openRevision6($encrypt, $password, $encryptMetadata),
            in_array($version, [1, 2], true) && in_array($revision, [2, 3], true) => self::openRevision2To4($encrypt, $firstDocumentId, $password, self::METHOD_RC4, $encryptMetadata),
            $version === 4 && $revision === 4 => self::openRevision2To4($encrypt, $firstDocumentId, $password, self::cryptFilterMethod($encrypt), $encryptMetadata),
            default => throw new ProtectionProcessException(sprintf('Unsupported PDF encryption (/V %d /R %d).', $version, $revision)),
        };
    }

    public function encrypt(string $data, int $objectNumber, int $generation): string
    {
        return match ($this->method) {
            self::METHOD_RC4 => StandardSecurityPrimitives::rc4($this->objectKey($objectNumber, $generation), $data),
            self::METHOD_AESV2 => $this->aesEncrypt($data, 'aes-128-cbc', $this->objectKey($objectNumber, $generation)),
            default => $this->aesEncrypt($data, 'aes-256-cbc', $this->fileKey),
        };
    }

    public function decrypt(string $data, int $objectNumber, int $generation): string
    {
        if ($this->method === self::METHOD_RC4) {
            return StandardSecurityPrimitives::rc4($this->objectKey($objectNumber, $generation), $data);
        }

        // AES: a 16-byte IV followed by PKCS#5 padded cipher text (§7.6.3.2).
        if (strlen($data) < 32 || strlen($data) % 16 !== 0) {
            throw new ProtectionProcessException(sprintf('Encrypted data of object %d has an invalid length.', $objectNumber));
        }

        [$cipher, $key] = $this->method === self::METHOD_AESV2
            ? ['aes-128-cbc', $this->objectKey($objectNumber, $generation)]
            : ['aes-256-cbc', $this->fileKey];
        $plain = StandardSecurityPrimitives::opensslDecrypt(substr($data, 16), $cipher, $key, 0, substr($data, 0, 16));
        if ($plain === null) {
            throw new ProtectionProcessException(sprintf('Could not decrypt data of object %d.', $objectNumber));
        }

        return $plain;
    }

    public function encryptionDictionary(): PdfDictionaryNode
    {
        return $this->encryptionDictionary;
    }

    public function minimumPdfVersion(): string
    {
        return '1.4';
    }

    public function adobeExtensionLevel(): ?int
    {
        return null;
    }

    /**
     * Algorithm 2.A: the file key is unwrapped from /OE with the owner password or from /UE with the user password.
     */
    private static function openRevision6(PdfDictionaryNode $encrypt, string $password, bool $encryptMetadata): self
    {
        $password = StandardSecurityPrimitives::prepareUtf8Password($password);
        $owner = self::stringEntry($encrypt, 'O');
        $user = self::stringEntry($encrypt, 'U');
        if (strlen($owner) < 48 || strlen($user) < 48) {
            throw new ProtectionProcessException('Malformed AES-256 encryption dictionary.');
        }
        $user = substr($user, 0, 48);

        if (hash_equals(substr($owner, 0, 32), StandardSecurityPrimitives::hashR6($password, substr($owner, 32, 8), $user))) {
            $intermediate = StandardSecurityPrimitives::hashR6($password, substr($owner, 40, 8), $user);
            $wrapped = self::stringEntry($encrypt, 'OE');
        } elseif (hash_equals(substr($user, 0, 32), StandardSecurityPrimitives::hashR6($password, substr($user, 32, 8), ''))) {
            $intermediate = StandardSecurityPrimitives::hashR6($password, substr($user, 40, 8), '');
            $wrapped = self::stringEntry($encrypt, 'UE');
        } else {
            throw new ProtectionProcessException('The password does not open this encrypted PDF.');
        }

        $fileKey = StandardSecurityPrimitives::opensslDecrypt($wrapped, 'aes-256-cbc', $intermediate, OPENSSL_ZERO_PADDING, str_repeat("\0", 16));
        if ($fileKey === null || strlen($fileKey) !== 32) {
            throw new ProtectionProcessException('Could not unwrap the AES-256 file encryption key.');
        }

        return new self($encrypt, $fileKey, self::METHOD_AESV3, $encryptMetadata);
    }

    /**
     * Algorithm 2 (file key from the user password), algorithm 7 (user password recovered from /O with the
     * owner password) and algorithms 4/5 (/U check).
     */
    private static function openRevision2To4(PdfDictionaryNode $encrypt, string $firstDocumentId, string $password, string $method, bool $encryptMetadata): self
    {
        $revision = (int) $encrypt->rawToken('R');
        $keyLength = $revision === 2 ? 5 : intdiv((int) ($encrypt->rawToken('Length') ?? '40'), 8);
        if ($keyLength < 5 || $keyLength > 16) {
            throw new ProtectionProcessException('Malformed encryption key length.');
        }

        $owner = substr(self::stringEntry($encrypt, 'O'), 0, 32);
        $user = self::stringEntry($encrypt, 'U');
        $permissions = (int) ($encrypt->rawToken('P') ?? '0');
        $fileKeyFor = static function (string $paddedUserPassword) use ($owner, $permissions, $firstDocumentId, $revision, $keyLength, $encryptMetadata): string {
            $input = $paddedUserPassword.$owner.pack('V', $permissions & 0xFFFFFFFF).$firstDocumentId;
            if ($revision >= 4 && ! $encryptMetadata) {
                $input .= "\xFF\xFF\xFF\xFF";
            }

            return $revision >= 3
                ? StandardSecurityPrimitives::iterateMd5(md5($input, true), $keyLength)
                : substr(md5($input, true), 0, $keyLength);
        };
        $userEntryFor = static fn (string $fileKey): string => $revision >= 3
            ? substr(StandardSecurityPrimitives::rc4Rounds($fileKey, md5(StandardSecurityPrimitives::PADDING.$firstDocumentId, true)), 0, 16)
            : StandardSecurityPrimitives::rc4($fileKey, StandardSecurityPrimitives::PADDING);
        $matchesUser = static fn (string $fileKey): bool => hash_equals(substr($user, 0, $revision >= 3 ? 16 : 32), $userEntryFor($fileKey));

        $padded = StandardSecurityPrimitives::padPassword($password);
        $fileKey = $fileKeyFor($padded);
        if (! $matchesUser($fileKey)) {
            $ownerKey = $revision >= 3
                ? StandardSecurityPrimitives::iterateMd5(md5($padded, true), $keyLength)
                : substr(md5($padded, true), 0, $keyLength);
            $recoveredUser = $revision >= 3
                ? StandardSecurityPrimitives::rc4Rounds($ownerKey, $owner, true)
                : StandardSecurityPrimitives::rc4($ownerKey, $owner);
            $fileKey = $fileKeyFor($recoveredUser);
            if (! $matchesUser($fileKey)) {
                throw new ProtectionProcessException('The password does not open this encrypted PDF.');
            }
        }

        return new self($encrypt, $fileKey, $method, $encryptMetadata);
    }

    private static function cryptFilterMethod(PdfDictionaryNode $encrypt): string
    {
        $streamFilter = $encrypt->rawToken('StmF') ?? '/Identity';
        $stringFilter = $encrypt->rawToken('StrF') ?? '/Identity';
        if ($streamFilter !== $stringFilter || $streamFilter === '/Identity') {
            throw new ProtectionProcessException('Encrypted PDFs with different or identity stream and string crypt filters are not supported.');
        }

        $filters = $encrypt->get('CF');
        $filter = $filters instanceof PdfDictionaryNode ? $filters->get(substr($streamFilter, 1)) : null;
        $method = $filter instanceof PdfDictionaryNode ? $filter->rawToken('CFM') : null;

        return match ($method) {
            '/AESV2' => self::METHOD_AESV2,
            '/V2' => self::METHOD_RC4,
            default => throw new ProtectionProcessException(sprintf('Unsupported crypt filter method %s.', $method ?? 'none')),
        };
    }

    /**
     * Algorithm 1: per-object key from the file key, the object number and the generation ("sAlT" for AES).
     */
    private function objectKey(int $objectNumber, int $generation): string
    {
        $input = $this->fileKey.substr(pack('V', $objectNumber), 0, 3).substr(pack('V', $generation), 0, 2);
        if ($this->method === self::METHOD_AESV2) {
            $input .= 'sAlT';
        }

        return substr(md5($input, true), 0, min(strlen($this->fileKey) + 5, 16));
    }

    private function aesEncrypt(string $data, string $cipher, string $key): string
    {
        $iv = random_bytes(16);

        return $iv.StandardSecurityPrimitives::openssl($data, $cipher, $key, 0, $iv);
    }

    private static function stringEntry(PdfDictionaryNode $dictionary, string $key): string
    {
        $value = $dictionary->get($key);
        if (! $value instanceof PdfStringNode) {
            throw new ProtectionProcessException(sprintf('Encryption dictionary has no /%s string.', $key));
        }

        return $value->bytes;
    }
}
