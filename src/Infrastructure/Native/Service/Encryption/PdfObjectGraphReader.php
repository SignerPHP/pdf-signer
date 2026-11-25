<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Infrastructure\Native\Service\Encryption;

use SignerPHP\PdfCore\PdfDocument;
use SignerPHP\PdfCore\Service\PdfDocumentPreparer;
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

    public function read(string $pdfContent): PdfObjectGraph
    {
        if (preg_match('/%PDF-(\d\.\d)/', substr($pdfContent, 0, 1024), $matches) !== 1) {
            throw new ProtectionProcessException('Input is not a PDF document: header not found.');
        }

        $document = $this->documentPreparer->prepare($pdfContent);
        $trailer = (new PdfSyntaxParser((string) $document->getTrailerObject()))->parseValue();
        if (! $trailer instanceof PdfDictionaryNode || ! $trailer->has('Root')) {
            throw new ProtectionProcessException('PDF trailer has no /Root entry.');
        }

        if ($trailer->has('Encrypt')) {
            throw new ProtectionProcessException('PDF document is already encrypted.');
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
                : $this->readCompressedObject($document, $objectStreams, $objectNumber, (int) $entry->objectStreamId());

            if (! $this->isStructuralObject($object)) {
                $objects[$objectNumber] = $object;
            }
        }

        ksort($objects);

        return new PdfObjectGraph($matches[1], $trailer, $objects);
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
    private function readCompressedObject(PdfDocument $document, array &$objectStreams, int $objectNumber, int $streamNumber): PdfIndirectObject
    {
        if (! isset($objectStreams[$streamNumber])) {
            $objectStreams[$streamNumber] = $this->decodeObjectStream($document, $streamNumber);
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
