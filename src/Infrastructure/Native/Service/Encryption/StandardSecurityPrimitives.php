<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Infrastructure\Native\Service\Encryption;

use SignerPHP\PdfSigner\Domain\Exception\ProtectionProcessException;

/**
 * Building blocks of the standard security handler (ISO 32000-2 §7.6.4), shared by the handlers
 * that create encryption and the one that opens an encrypted document.
 */
final class StandardSecurityPrimitives
{
    public const PADDING = "\x28\xBF\x4E\x5E\x4E\x75\x8A\x41\x64\x00\x4E\x56\xFF\xFA\x01\x08"
        ."\x2E\x2E\x00\xB6\xD0\x68\x3E\x80\x2F\x0C\xA9\xFE\x64\x53\x69\x7A";

    /**
     * Revisions 2–4: the password in PDFDocEncoding, padded or truncated to 32 bytes. UTF-8 input in the
     * Latin-1 range is converted (PDFDocEncoding matches Latin-1 for those characters); anything else is raw bytes.
     */
    public static function padPassword(string $password): string
    {
        return substr(self::toLatin1($password).self::PADDING, 0, 32);
    }

    /**
     * Revision 6: passwords are UTF-8 (after SASLprep) truncated to 127 bytes (§7.6.4.3.3).
     */
    public static function prepareUtf8Password(string $password): string
    {
        return substr($password, 0, 127);
    }

    /**
     * Revision 3+: MD5 applied 50 more times to the first $length bytes; returns a $length-byte key.
     */
    public static function iterateMd5(string $digest, int $length): string
    {
        for ($i = 0; $i < 50; $i++) {
            $digest = md5(substr($digest, 0, $length), true);
        }

        return substr($digest, 0, $length);
    }

    /**
     * RC4 with the key, then 19 more passes with the key XOR-ed with the pass number (revision 3+).
     * Applying the passes in reverse order (19 down to 0) undoes them.
     */
    public static function rc4Rounds(string $key, string $data, bool $reverse = false): string
    {
        $rounds = $reverse ? range(19, 0) : range(0, 19);
        foreach ($rounds as $round) {
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
    public static function rc4(string $key, string $data): string
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

    /**
     * Algorithm 2.B: hardened hash for revision 6.
     */
    public static function hashR6(string $password, string $salt, string $userEntry): string
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

    public static function openssl(string $data, string $cipher, string $key, int $options, string $iv): string
    {
        $result = openssl_encrypt($data, $cipher, $key, OPENSSL_RAW_DATA | $options, $iv);
        if ($result === false) {
            throw new ProtectionProcessException(sprintf('OpenSSL could not encrypt data with %s.', $cipher));
        }

        return $result;
    }

    public static function opensslDecrypt(string $data, string $cipher, string $key, int $options, string $iv): ?string
    {
        $result = openssl_decrypt($data, $cipher, $key, OPENSSL_RAW_DATA | $options, $iv);

        return $result === false ? null : $result;
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
}
