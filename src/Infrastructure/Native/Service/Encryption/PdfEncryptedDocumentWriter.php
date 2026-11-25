<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Infrastructure\Native\Service\Encryption;

/**
 * Writes an object graph as a complete, single-revision PDF with every string and stream
 * encrypted by the given security handler (ISO 32000-2 §7.6.2).
 *
 * Not encrypted: the /Encrypt dictionary itself, the trailer /ID, the /Contents of signature
 * dictionaries and, when /EncryptMetadata is false, metadata streams.
 */
final class PdfEncryptedDocumentWriter
{
    /**
     * @param  array{0: string, 1: string}  $documentId
     */
    public function write(
        PdfObjectGraph $graph,
        StandardSecurityHandlerInterface $handler,
        array $documentId,
        bool $encryptMetadata,
    ): string {
        $objects = $graph->objects;
        $rootNumber = self::referencedObjectNumber($graph->trailer->rawToken('Root'));
        $extensionLevel = $handler->adobeExtensionLevel();
        if ($extensionLevel !== null && $rootNumber !== null && isset($objects[$rootNumber])) {
            $objects[$rootNumber] = self::withAdobeExtension($objects[$rootNumber], $extensionLevel);
        }

        $version = version_compare($graph->version, $handler->minimumPdfVersion(), '<')
            ? $handler->minimumPdfVersion()
            : $graph->version;

        $output = "%PDF-{$version}\n%\xE2\xE3\xCF\xD3\n";
        /** @var array<int, array{0: int, 1: int}> $offsets */
        $offsets = [];

        foreach ($objects as $object) {
            $offsets[$object->objectNumber] = [strlen($output), $object->generation];
            $output .= $this->writeObject($object, $handler, $encryptMetadata);
        }

        $encryptNumber = ($objects === [] ? 0 : max(array_keys($objects))) + 1;
        $offsets[$encryptNumber] = [strlen($output), 0];
        $output .= $encryptNumber." 0 obj\n".self::serialize($handler->encryptionDictionary(), null)."\nendobj\n";

        $xrefOffset = strlen($output);
        $output .= 'xref'."\n".'0 '.($encryptNumber + 1)."\n".'0000000000 65535 f'."\r\n";
        for ($number = 1; $number <= $encryptNumber; $number++) {
            [$offset, $generation] = $offsets[$number] ?? [0, 0];
            $output .= sprintf('%010d %05d %s', $offset, $generation, isset($offsets[$number]) ? 'n' : 'f')."\r\n";
        }

        $trailer = new PdfDictionaryNode([
            ['Size', new PdfRawNode((string) ($encryptNumber + 1))],
            ['Root', new PdfRawNode((string) $graph->trailer->rawToken('Root'))],
        ]);
        $info = $graph->trailer->rawToken('Info');
        if ($info !== null && isset($objects[(int) self::referencedObjectNumber($info)])) {
            $trailer->set('Info', new PdfRawNode($info));
        }
        $trailer->set('ID', new PdfArrayNode([new PdfStringNode($documentId[0]), new PdfStringNode($documentId[1])]));
        $trailer->set('Encrypt', new PdfRawNode($encryptNumber.' 0 R'));

        return $output.'trailer'."\n".self::serialize($trailer, null)."\nstartxref\n".$xrefOffset."\n%%EOF\n";
    }

    private function writeObject(PdfIndirectObject $object, StandardSecurityHandlerInterface $handler, bool $encryptMetadata): string
    {
        $encryptor = static fn (string $bytes): string => $handler->encrypt($bytes, $object->objectNumber, $object->generation);
        $header = $object->objectNumber.' '.$object->generation." obj\n";
        $value = $object->value;

        if ($object->stream === null || ! $value instanceof PdfDictionaryNode) {
            return $header.self::serializeObjectValue($value, $encryptor)."\nendobj\n";
        }

        $isClearMetadata = ! $encryptMetadata && $value->rawToken('Type') === '/Metadata';
        $stream = $isClearMetadata ? $object->stream : $encryptor($object->stream);
        $dictionary = (clone $value)->set('Length', new PdfRawNode((string) strlen($stream)));

        return $header.self::serializeObjectValue($dictionary, $encryptor)."\nstream\n".$stream."\nendstream\nendobj\n";
    }

    /**
     * @param  callable(string): string  $encryptor
     */
    private static function serializeObjectValue(PdfNode $value, callable $encryptor): string
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

    private static function isSignatureDictionary(PdfDictionaryNode $dictionary): bool
    {
        return in_array($dictionary->rawToken('Type'), ['/Sig', '/DocTimeStamp'], true) || $dictionary->has('ByteRange');
    }

    /**
     * @param  (callable(string): string)|null  $encryptor
     */
    private static function serialize(PdfNode $node, ?callable $encryptor): string
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

    private static function withAdobeExtension(PdfIndirectObject $catalog, int $level): PdfIndirectObject
    {
        if (! $catalog->value instanceof PdfDictionaryNode) {
            return $catalog;
        }

        $adobe = new PdfDictionaryNode([
            ['BaseVersion', new PdfRawNode('/1.7')],
            ['ExtensionLevel', new PdfRawNode((string) $level)],
        ]);
        $extensions = $catalog->value->get('Extensions');

        if ($extensions instanceof PdfDictionaryNode) {
            if ($extensions->has('ADBE')) {
                return $catalog;
            }
            $extensions = (clone $extensions)->set('ADBE', $adobe);
        } elseif ($extensions === null) {
            $extensions = new PdfDictionaryNode([['ADBE', $adobe]]);
        } else {
            return $catalog;
        }

        $value = (clone $catalog->value)->set('Extensions', $extensions);

        return new PdfIndirectObject($catalog->objectNumber, $catalog->generation, $value, $catalog->stream);
    }

    private static function referencedObjectNumber(?string $reference): ?int
    {
        if ($reference === null || preg_match('/^(\d+) \d+ R$/', $reference, $matches) !== 1) {
            return null;
        }

        return (int) $matches[1];
    }
}
