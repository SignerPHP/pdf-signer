<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Tests\Support;

use RuntimeException;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\Encryption\PdfArrayNode;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\Encryption\PdfDictionaryNode;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\Encryption\PdfNode;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\Encryption\PdfStringNode;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\Encryption\PdfSyntaxParser;

/**
 * Independent implementation of the standard security handler key derivation (ISO 32000-2 §7.6.4)
 * used to check the native encryption without relying on external tools.
 */
final class StandardSecurityTestDecryptor
{
    private const PADDING = "\x28\xBF\x4E\x5E\x4E\x75\x8A\x41\x64\x00\x4E\x56\xFF\xFA\x01\x08"
        ."\x2E\x2E\x00\xB6\xD0\x68\x3E\x80\x2F\x0C\xA9\xFE\x64\x53\x69\x7A";

    public PdfDictionaryNode $trailer;

    public PdfDictionaryNode $encrypt;

    public int $encryptObjectNumber;

    /** @var array<int, array{generation: int, value: PdfNode, stream: ?string}> */
    public array $rawObjects = [];

    public function __construct(public readonly string $pdf)
    {
        if (preg_match('/xref\n0 (\d+)\n/', $pdf, $match, PREG_OFFSET_CAPTURE) !== 1) {
            throw new RuntimeException('xref table not found');
        }

        $entriesOffset = $match[0][1] + strlen($match[0][0]);
        for ($number = 1; $number < (int) $match[1][0]; $number++) {
            $line = substr($pdf, $entriesOffset + 20 * $number, 20);
            if ($line[17] !== 'n') {
                continue;
            }

            $parser = new PdfSyntaxParser($pdf, (int) substr($line, 0, 10));
            [, $generation] = (array) $parser->readObjectHeader();
            $value = $parser->parseValue();
            $stream = null;
            if ($parser->readKeyword() === 'stream' && $value instanceof PdfDictionaryNode) {
                $stream = substr($pdf, $parser->position() + 1, (int) $value->rawToken('Length'));
            }
            $this->rawObjects[$number] = ['generation' => (int) $generation, 'value' => $value, 'stream' => $stream];
        }

        $trailer = (new PdfSyntaxParser($pdf, (int) strrpos($pdf, 'trailer') + 7))->parseValue();
        assert($trailer instanceof PdfDictionaryNode);
        $this->trailer = $trailer;
        $this->encryptObjectNumber = (int) $trailer->rawToken('Encrypt');
        $encrypt = $this->rawObjects[$this->encryptObjectNumber]['value'];
        assert($encrypt instanceof PdfDictionaryNode);
        $this->encrypt = $encrypt;
    }

    public function revision(): int
    {
        return (int) $this->encrypt->rawToken('R');
    }

    public function permissions(): int
    {
        return (int) $this->encrypt->rawToken('P');
    }

    /**
     * Returns the file encryption key when the password is the user or the owner password, null otherwise.
     */
    public function fileKey(string $password): ?string
    {
        return $this->revision() === 6 ? $this->fileKeyR6($password) : $this->fileKeyR4($password);
    }

    /**
     * @return array<int, array{generation: int, value: PdfNode, stream: ?string}>
     */
    public function decryptedObjects(string $password, bool $decryptMetadata = true): array
    {
        $key = $this->fileKey($password) ?? throw new RuntimeException('Wrong password');
        $objects = [];

        foreach ($this->rawObjects as $number => $object) {
            if ($number === $this->encryptObjectNumber) {
                continue;
            }

            $decrypt = fn (string $data): string => $this->decrypt($key, $data, $number, $object['generation']);
            $isSignature = $object['value'] instanceof PdfDictionaryNode
                && ($object['value']->has('ByteRange') || in_array($object['value']->rawToken('Type'), ['/Sig', '/DocTimeStamp'], true));
            $isClearMetadata = ! $decryptMetadata && $object['value'] instanceof PdfDictionaryNode
                && $object['value']->rawToken('Type') === '/Metadata';

            $objects[$number] = [
                'generation' => $object['generation'],
                'value' => self::mapStrings($object['value'], $decrypt, $isSignature),
                'stream' => $object['stream'] === null || $isClearMetadata ? $object['stream'] : $decrypt($object['stream']),
            ];
        }

        return $objects;
    }

    public function permsBlock(string $fileKey): string
    {
        $perms = $this->encrypt->get('Perms');
        assert($perms instanceof PdfStringNode);

        return (string) openssl_decrypt($perms->bytes, 'aes-256-ecb', $fileKey, OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING);
    }

    private function decrypt(string $fileKey, string $data, int $number, int $generation): string
    {
        if ($this->revision() === 6) {
            return (string) openssl_decrypt(substr($data, 16), 'aes-256-cbc', $fileKey, OPENSSL_RAW_DATA, substr($data, 0, 16));
        }

        $key = md5($fileKey.substr(pack('V', $number), 0, 3).substr(pack('V', $generation), 0, 2).'sAlT', true);

        return (string) openssl_decrypt(substr($data, 16), 'aes-128-cbc', $key, OPENSSL_RAW_DATA, substr($data, 0, 16));
    }

    private static function mapStrings(PdfNode $node, callable $decrypt, bool $skipContents, ?string $key = null): PdfNode
    {
        if ($node instanceof PdfStringNode) {
            return $skipContents && $key === 'Contents' ? $node : new PdfStringNode($decrypt($node->bytes));
        }

        if ($node instanceof PdfArrayNode) {
            return new PdfArrayNode(array_map(static fn (PdfNode $item): PdfNode => self::mapStrings($item, $decrypt, false), $node->items));
        }

        if ($node instanceof PdfDictionaryNode) {
            $entries = [];
            foreach ($node->entries() as [$entryKey, $value]) {
                $entries[] = [$entryKey, self::mapStrings($value, $decrypt, $skipContents, $entryKey)];
            }

            return new PdfDictionaryNode($entries);
        }

        return $node;
    }

    private function bytes(string $key): string
    {
        $value = $this->encrypt->get($key);
        assert($value instanceof PdfStringNode);

        return $value->bytes;
    }

    private function fileKeyR6(string $password): ?string
    {
        $password = substr($password, 0, 127);
        $u = $this->bytes('U');
        $o = $this->bytes('O');

        if (hash_equals(substr($o, 0, 32), self::hash2b($password, substr($o, 32, 8), $u))) {
            $intermediate = self::hash2b($password, substr($o, 40, 8), $u);

            return (string) openssl_decrypt($this->bytes('OE'), 'aes-256-cbc', $intermediate, OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING, str_repeat("\0", 16));
        }

        if (hash_equals(substr($u, 0, 32), self::hash2b($password, substr($u, 32, 8), ''))) {
            $intermediate = self::hash2b($password, substr($u, 40, 8), '');

            return (string) openssl_decrypt($this->bytes('UE'), 'aes-256-cbc', $intermediate, OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING, str_repeat("\0", 16));
        }

        return null;
    }

    private function fileKeyR4(string $password): ?string
    {
        $id = $this->trailer->get('ID');
        assert($id instanceof PdfArrayNode && $id->items[0] instanceof PdfStringNode);
        $input = substr($password.self::PADDING, 0, 32).$this->bytes('O').pack('V', $this->permissions() & 0xFFFFFFFF).$id->items[0]->bytes;
        if ($this->encrypt->rawToken('EncryptMetadata') === 'false') {
            $input .= "\xFF\xFF\xFF\xFF";
        }

        $key = md5($input, true);
        for ($i = 0; $i < 50; $i++) {
            $key = md5($key, true);
        }

        $check = md5(self::PADDING.$id->items[0]->bytes, true);
        for ($round = 0; $round < 20; $round++) {
            $check = self::rc4($key ^ str_repeat(chr($round), 16), $check);
        }

        return hash_equals(substr($this->bytes('U'), 0, 16), $check) ? $key : null;
    }

    private static function hash2b(string $password, string $salt, string $userKey): string
    {
        $k = hash('sha256', $password.$salt.$userKey, true);
        for ($i = 0; $i < 64 || ord($e[strlen($e) - 1]) > $i - 32; $i++) {
            $e = (string) openssl_encrypt(str_repeat($password.$k.$userKey, 64), 'aes-128-cbc', substr($k, 0, 16), OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING, substr($k, 16, 16));
            $mod = 0;
            foreach (str_split(substr($e, 0, 16)) as $byte) {
                $mod = ($mod * 256 + ord($byte)) % 3;
            }
            $k = hash(['sha256', 'sha384', 'sha512'][$mod], $e, true);
        }

        return substr($k, 0, 32);
    }

    private static function rc4(string $key, string $data): string
    {
        $s = range(0, 255);
        for ($i = 0, $j = 0; $i < 256; $i++) {
            $j = ($j + $s[$i] + ord($key[$i % strlen($key)])) % 256;
            [$s[$i], $s[$j]] = [$s[$j], $s[$i]];
        }

        $out = '';
        for ($n = 0, $i = 0, $j = 0; $n < strlen($data); $n++) {
            $i = ($i + 1) % 256;
            $j = ($j + $s[$i]) % 256;
            [$s[$i], $s[$j]] = [$s[$j], $s[$i]];
            $out .= $data[$n] ^ chr($s[($s[$i] + $s[$j]) % 256]);
        }

        return $out;
    }
}
