<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Infrastructure\Native\Service\Encryption;

/**
 * Serializes indirect objects, encrypting their strings and streams with a security handler
 * (ISO 32000-2 §7.6.2), or writing them in clear when no handler is given.
 *
 * Never encrypted: the /Contents of signature and document timestamp dictionaries and, when
 * /EncryptMetadata is false, metadata streams.
 */
final class PdfObjectSerializer
{
    public static function writeObject(PdfIndirectObject $object, ?StandardSecurityHandlerInterface $handler, bool $encryptMetadata): string
    {
        $encryptor = $handler === null
            ? null
            : static fn (string $bytes): string => $handler->encrypt($bytes, $object->objectNumber, $object->generation);
        $header = $object->objectNumber.' '.$object->generation." obj\n";
        $value = $object->value;

        if ($object->stream === null || ! $value instanceof PdfDictionaryNode) {
            return $header.self::serializeObjectValue($value, $encryptor)."\nendobj\n";
        }

        $isClearMetadata = ! $encryptMetadata && $value->rawToken('Type') === '/Metadata';
        $stream = ($isClearMetadata || $encryptor === null) ? $object->stream : $encryptor($object->stream);
        $dictionary = (clone $value)->set('Length', new PdfRawNode((string) strlen($stream)));

        return $header.self::serializeObjectValue($dictionary, $encryptor)."\nstream\n".$stream."\nendstream\nendobj\n";
    }

    public static function isSignatureDictionary(PdfDictionaryNode $dictionary): bool
    {
        return in_array($dictionary->rawToken('Type'), ['/Sig', '/DocTimeStamp'], true) || $dictionary->has('ByteRange');
    }

    /**
     * @param  (callable(string): string)|null  $encryptor
     */
    public static function serialize(PdfNode $node, ?callable $encryptor): string
    {
        if ($node instanceof PdfStringNode) {
            return '<'.bin2hex($encryptor === null ? $node->bytes : $encryptor($node->bytes)).'>';
        }

        if ($node instanceof PdfArrayNode) {
            return '['.implode(' ', array_map(static fn (PdfNode $item): string => self::serialize($item, $encryptor), $node->items)).']';
        }

        if ($node instanceof PdfDictionaryNode) {
            $parts = [];
            foreach ($node->entries() as [$key, $value]) {
                $parts[] = '/'.$key.' '.self::serialize($value, $encryptor);
            }

            return '<<'.implode(' ', $parts).'>>';
        }

        return $node instanceof PdfRawNode ? $node->token : '';
    }

    /**
     * @param  (callable(string): string)|null  $encryptor
     */
    private static function serializeObjectValue(PdfNode $value, ?callable $encryptor): string
    {
        if (! $value instanceof PdfDictionaryNode || ! self::isSignatureDictionary($value)) {
            return self::serialize($value, $encryptor);
        }

        // §7.6.2: the /Contents string of a signature dictionary is not encrypted.
        $parts = [];
        foreach ($value->entries() as [$key, $entry]) {
            $parts[] = '/'.$key.' '.self::serialize($entry, $key === 'Contents' ? null : $encryptor);
        }

        return '<<'.implode(' ', $parts).'>>';
    }
}
