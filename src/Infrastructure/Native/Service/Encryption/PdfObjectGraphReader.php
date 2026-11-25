<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Infrastructure\Native\Service\Encryption;

use SignerPHP\PdfCore\PdfDocument;
use SignerPHP\PdfCore\Service\PdfDocumentPreparer;
use SignerPHP\PdfCore\Struct;
use SignerPHP\PdfSigner\Domain\Exception\ProtectionProcessException;

/**
 * Loads every live object of the latest revision of a PDF, unpacking object streams,
 * so the document can be written again as a single, non-incremental revision.
 *
 * pdf-core resolves the cross-reference data (tables and streams, including /Prev chains)
 * and decodes object streams; object bodies are parsed with {@see PdfSyntaxParser} so that
 * every value, including strings and non-dictionary objects, round-trips exactly.
 */
final class PdfObjectGraphReader
{
    public function __construct(private readonly PdfDocumentPreparer $documentPreparer = new PdfDocumentPreparer) {}

    /**
     * @param  OpenedStandardSecurityHandler|null  $decryptor  required to read an encrypted document; its objects
     *                                                         are returned in clear, the /Encrypt dictionary as is
     */
    public function read(string $pdfContent, ?OpenedStandardSecurityHandler $decryptor = null): PdfObjectGraph
    {
        if (preg_match('/%PDF-(\d\.\d)/', substr($pdfContent, 0, 1024), $matches) !== 1) {
            throw new ProtectionProcessException('Input is not a PDF document: header not found.');
        }

        $document = $decryptor === null ? $this->documentPreparer->prepare($pdfContent) : self::prepareStructure($pdfContent);
        $trailer = (new PdfSyntaxParser((string) $document->getTrailerObject()))->parseValue();
        if (! $trailer instanceof PdfDictionaryNode || ! $trailer->has('Root')) {
            throw new ProtectionProcessException('PDF trailer has no /Root entry.');
        }

        $encryptObjectNumber = null;
        if ($trailer->has('Encrypt')) {
            if ($decryptor === null) {
                throw new ProtectionProcessException('PDF document is already encrypted.');
            }
            $encryptObjectNumber = self::referencedObjectNumber($trailer->rawToken('Encrypt'));
        }

        $objects = [];
        /** @var array<int, array{content: string, offsets: array<int, int>}> $objectStreams */
        $objectStreams = [];

        foreach ($document->getXrefEntries() as $objectNumber => $entry) {
            if ($objectNumber === 0 || $entry->isFree()) {
                continue;
            }

            $object = $entry->isDirectOffset()
                ? $this->readDirectObject($pdfContent, $objectNumber, (int) $entry->offset())
                : $this->readCompressedObject($document, $objectStreams, $objectNumber, (int) $entry->objectStreamId(), $pdfContent, $decryptor);

            if ($decryptor !== null && $entry->isDirectOffset() && $objectNumber !== $encryptObjectNumber) {
                $object = $this->decryptObject($object, $decryptor);
            }

            if (! $this->isStructuralObject($object)) {
                $objects[$objectNumber] = $object;
            }
        }

        ksort($objects);

        return new PdfObjectGraph($matches[1], $trailer, $objects);
    }

    /**
     * The latest trailer and, for an encrypted document, its /Encrypt dictionary and object number
     * (the encryption dictionary is never stored in an object stream, §7.5.7).
     *
     * @return array{trailer: PdfDictionaryNode, encrypt: PdfDictionaryNode|null, encryptObjectNumber: int|null}
     */
    public function encryption(string $pdfContent): array
    {
        $document = self::prepareStructure($pdfContent);
        $trailer = (new PdfSyntaxParser((string) $document->getTrailerObject()))->parseValue();
        if (! $trailer instanceof PdfDictionaryNode) {
            throw new ProtectionProcessException('PDF trailer is not a dictionary.');
        }

        $encrypt = $trailer->get('Encrypt');
        if ($encrypt === null) {
            return ['trailer' => $trailer, 'encrypt' => null, 'encryptObjectNumber' => null];
        }
        if ($encrypt instanceof PdfDictionaryNode) {
            return ['trailer' => $trailer, 'encrypt' => $encrypt, 'encryptObjectNumber' => null];
        }

        $number = self::referencedObjectNumber($encrypt instanceof PdfRawNode ? $encrypt->token : null);
        $entry = $number === null ? null : ($document->getXrefEntries()[$number] ?? null);
        if ($number === null || $entry === null || ! $entry->isDirectOffset()) {
            throw new ProtectionProcessException('Could not resolve the /Encrypt dictionary.');
        }

        $dictionary = $this->readDirectObject($pdfContent, $number, (int) $entry->offset())->value;
        if (! $dictionary instanceof PdfDictionaryNode) {
            throw new ProtectionProcessException('The /Encrypt entry is not a dictionary.');
        }

        return ['trailer' => $trailer, 'encrypt' => $dictionary, 'encryptObjectNumber' => $number];
    }

    /**
     * Cross-reference data, trailer and revisions only. pdf-core's preparer also walks the page tree,
     * which it cannot do when the pages sit in an encrypted object stream.
     */
    private static function prepareStructure(string $pdfContent): PdfDocument
    {
        $document = new PdfDocument;
        $document->setBufferFromString($pdfContent);
        $structure = Struct::new()->withPdfDocument($document)->parse();
        $document->setPdfVersion($structure->version);
        if ($structure->trailer !== null) {
            $document->setTrailerObject($structure->trailer);
        }
        $document->setXrefPosition($structure->xrefPosition);
        $document->setXrefTable($structure->xrefTable);
        $document->setXrefTableVersion($structure->xrefVersion);
        $document->setRevisions($structure->revisions);
        $numbers = array_keys($structure->xrefTable);
        $document->setMaxOid($numbers === [] ? 0 : (int) max($numbers));

        return $document;
    }

    private function readDirectObject(string $pdfContent, int $objectNumber, int $offset): PdfIndirectObject
    {
        $parser = new PdfSyntaxParser($pdfContent, $offset);
        $header = $parser->readObjectHeader();

        if ($header === null || $header[0] !== $objectNumber) {
            $parser = new PdfSyntaxParser($pdfContent, $this->locateObjectHeader($pdfContent, $objectNumber));
            $header = (array) $parser->readObjectHeader();
        }

        $generation = $header[1] ?? 0;
        $value = $parser->parseValue();

        if ($parser->readKeyword() !== 'stream') {
            return new PdfIndirectObject($objectNumber, $generation, $value);
        }

        if (! $value instanceof PdfDictionaryNode) {
            throw new ProtectionProcessException(sprintf('Stream object %d has no dictionary.', $objectNumber));
        }

        $stream = $this->readStreamData($pdfContent, $parser->position(), $this->resolveStreamLength($pdfContent, $value));

        return new PdfIndirectObject($objectNumber, $generation, $value, $stream);
    }

    private function locateObjectHeader(string $pdfContent, int $objectNumber): int
    {
        $pattern = '/(?<![0-9])'.$objectNumber.'[\0\t\n\f\r ]+[0-9]+[\0\t\n\f\r ]+obj\b/';
        if (preg_match_all($pattern, $pdfContent, $matches, PREG_OFFSET_CAPTURE) < 1) {
            throw new ProtectionProcessException(sprintf('Could not locate object %d in the PDF.', $objectNumber));
        }

        $last = array_pop($matches[0]);

        return $last === null ? 0 : $last[1];
    }

    private function resolveStreamLength(string $pdfContent, PdfDictionaryNode $dictionary): ?int
    {
        $length = $dictionary->rawToken('Length');
        if ($length === null) {
            return null;
        }

        if (ctype_digit($length)) {
            return (int) $length;
        }

        if (preg_match('/^(\d+) \d+ R$/', $length, $matches) !== 1) {
            return null;
        }

        try {
            $lengthObject = $this->readDirectObject($pdfContent, (int) $matches[1], $this->locateObjectHeader($pdfContent, (int) $matches[1]));
        } catch (ProtectionProcessException) {
            return null;
        }

        $value = $lengthObject->value;

        return $value instanceof PdfRawNode && ctype_digit($value->token) ? (int) $value->token : null;
    }

    private function readStreamData(string $pdfContent, int $afterKeyword, ?int $length): string
    {
        $start = $afterKeyword;
        if (substr($pdfContent, $start, 2) === "\r\n") {
            $start += 2;
        } elseif (in_array(substr($pdfContent, $start, 1), ["\n", "\r"], true)) {
            $start++;
        }

        if ($length !== null && $length >= 0) {
            $afterData = new PdfSyntaxParser($pdfContent, $start + $length);
            if ($afterData->readKeyword() === 'endstream') {
                return substr($pdfContent, $start, $length);
            }
        }

        // §7.3.8.1 fallback for a wrong or unresolvable /Length: the data ends at the EOL before "endstream".
        $end = strpos($pdfContent, 'endstream', $start);
        if ($end === false) {
            throw new ProtectionProcessException('Unterminated stream in PDF document.');
        }

        $data = substr($pdfContent, $start, $end - $start);
        if (str_ends_with($data, "\r\n")) {
            return substr($data, 0, -2);
        }

        return str_ends_with($data, "\n") || str_ends_with($data, "\r") ? substr($data, 0, -1) : $data;
    }

    /**
     * @param  array<int, array{content: string, offsets: array<int, int>}>  $objectStreams
     */
    private function readCompressedObject(
        PdfDocument $document,
        array &$objectStreams,
        int $objectNumber,
        int $streamNumber,
        string $pdfContent,
        ?OpenedStandardSecurityHandler $decryptor,
    ): PdfIndirectObject {
        if (! isset($objectStreams[$streamNumber])) {
            $objectStreams[$streamNumber] = $decryptor === null
                ? $this->decodeObjectStream($document, $streamNumber)
                : $this->decodeEncryptedObjectStream($document, $streamNumber, $pdfContent, $decryptor);
        }

        $objectStream = $objectStreams[$streamNumber];
        if (! isset($objectStream['offsets'][$objectNumber])) {
            throw new ProtectionProcessException(sprintf('Object %d not found in object stream %d.', $objectNumber, $streamNumber));
        }

        $parser = new PdfSyntaxParser($objectStream['content'], $objectStream['offsets'][$objectNumber]);

        return new PdfIndirectObject($objectNumber, 0, $parser->parseValue());
    }

    /**
     * @return array{content: string, offsets: array<int, int>}
     */
    private function decodeObjectStream(PdfDocument $document, int $streamNumber): array
    {
        $stream = $document->findObject($streamNumber);
        $first = $stream?->getField('First')?->asIntOrNull();
        $count = $stream?->getField('N')?->asIntOrNull();
        if ($stream === null || $first === null || $count === null) {
            throw new ProtectionProcessException(sprintf('Invalid object stream %d.', $streamNumber));
        }

        $content = $stream->getStream(false);
        preg_match_all('/\d+/', substr($content, 0, $first), $numbers);

        $offsets = [];
        $pairs = array_chunk($numbers[0], 2);
        foreach (array_slice($pairs, 0, $count) as $pair) {
            if (count($pair) === 2) {
                $offsets[(int) $pair[0]] = $first + (int) $pair[1];
            }
        }

        return ['content' => $content, 'offsets' => $offsets];
    }

    /**
     * An encrypted object stream is decrypted as a whole before being decompressed; the objects
     * inside it are not encrypted individually (§7.6.2).
     *
     * @return array{content: string, offsets: array<int, int>}
     */
    private function decodeEncryptedObjectStream(PdfDocument $document, int $streamNumber, string $pdfContent, OpenedStandardSecurityHandler $decryptor): array
    {
        $entry = $document->getXrefEntries()[$streamNumber] ?? null;
        if ($entry === null || ! $entry->isDirectOffset()) {
            throw new ProtectionProcessException(sprintf('Invalid object stream %d.', $streamNumber));
        }

        $stream = $this->readDirectObject($pdfContent, $streamNumber, (int) $entry->offset());
        $dictionary = $stream->value;
        $first = $dictionary instanceof PdfDictionaryNode ? $dictionary->rawToken('First') : null;
        $count = $dictionary instanceof PdfDictionaryNode ? $dictionary->rawToken('N') : null;
        if (! $dictionary instanceof PdfDictionaryNode || $stream->stream === null || $first === null || $count === null || ! ctype_digit($first) || ! ctype_digit($count)) {
            throw new ProtectionProcessException(sprintf('Invalid object stream %d.', $streamNumber));
        }

        $data = $decryptor->decrypt($stream->stream, $streamNumber, $stream->generation);
        $filter = $dictionary->get('Filter');
        $filterName = $filter instanceof PdfArrayNode && count($filter->items) === 1 ? $filter->items[0] : $filter;
        if ($filterName !== null) {
            if (! $filterName instanceof PdfRawNode || $filterName->token !== '/FlateDecode' || $dictionary->has('DecodeParms')) {
                throw new ProtectionProcessException(sprintf('Unsupported filter on encrypted object stream %d.', $streamNumber));
            }
            $inflated = @gzuncompress($data);
            if ($inflated === false) {
                throw new ProtectionProcessException(sprintf('Could not decompress encrypted object stream %d.', $streamNumber));
            }
            $data = $inflated;
        }

        preg_match_all('/\d+/', substr($data, 0, (int) $first), $numbers);
        $offsets = [];
        foreach (array_slice(array_chunk($numbers[0], 2), 0, (int) $count) as $pair) {
            if (count($pair) === 2) {
                $offsets[(int) $pair[0]] = (int) $first + (int) $pair[1];
            }
        }

        return ['content' => $data, 'offsets' => $offsets];
    }

    /**
     * Decrypts the strings and the stream of a directly stored object. Not encrypted in the file, so
     * left as is: the /Contents of signature dictionaries, cross-reference streams and, when
     * /EncryptMetadata is false, metadata streams (§7.6.2).
     */
    private function decryptObject(PdfIndirectObject $object, OpenedStandardSecurityHandler $decryptor): PdfIndirectObject
    {
        // Cross-reference streams, including the strings of their dictionary (/ID), are never encrypted.
        if ($object->value instanceof PdfDictionaryNode && $object->value->rawToken('Type') === '/XRef') {
            return $object;
        }

        $decrypt = static fn (string $bytes): string => $decryptor->decrypt($bytes, $object->objectNumber, $object->generation);
        $value = $object->value instanceof PdfDictionaryNode && PdfObjectSerializer::isSignatureDictionary($object->value)
            ? self::mapDictionary($object->value, static fn (string $key, PdfNode $entry): PdfNode => $key === 'Contents' ? $entry : self::decryptNode($entry, $decrypt))
            : self::decryptNode($object->value, $decrypt);

        $stream = $object->stream;
        if ($stream !== null && $object->value instanceof PdfDictionaryNode) {
            $type = $object->value->rawToken('Type');
            $clear = $type === '/Metadata' && ! $decryptor->encryptMetadata;
            $stream = $clear ? $stream : $decrypt($stream);
        }

        return new PdfIndirectObject($object->objectNumber, $object->generation, $value, $stream);
    }

    /**
     * @param  callable(string): string  $decrypt
     */
    private static function decryptNode(PdfNode $node, callable $decrypt): PdfNode
    {
        return match (true) {
            $node instanceof PdfStringNode => new PdfStringNode($decrypt($node->bytes)),
            $node instanceof PdfArrayNode => new PdfArrayNode(array_map(static fn (PdfNode $item): PdfNode => self::decryptNode($item, $decrypt), $node->items)),
            $node instanceof PdfDictionaryNode => self::mapDictionary($node, static fn (string $key, PdfNode $entry): PdfNode => self::decryptNode($entry, $decrypt)),
            default => $node,
        };
    }

    /**
     * @param  callable(string, PdfNode): PdfNode  $map
     */
    private static function mapDictionary(PdfDictionaryNode $dictionary, callable $map): PdfDictionaryNode
    {
        return new PdfDictionaryNode(array_map(
            static fn (array $entry): array => [$entry[0], $map($entry[0], $entry[1])],
            $dictionary->entries(),
        ));
    }

    private static function referencedObjectNumber(?string $reference): ?int
    {
        return $reference !== null && preg_match('/^(\d+) \d+ R$/', $reference, $matches) === 1 ? (int) $matches[1] : null;
    }

    /**
     * Object streams, cross-reference streams and linearization dictionaries describe the
     * source file layout; they are rebuilt (or dropped) when the document is rewritten.
     */
    private function isStructuralObject(PdfIndirectObject $object): bool
    {
        if (! $object->value instanceof PdfDictionaryNode) {
            return false;
        }

        return in_array($object->value->rawToken('Type'), ['/ObjStm', '/XRef'], true)
            || $object->value->has('Linearized');
    }
}
