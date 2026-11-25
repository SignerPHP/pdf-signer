<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Infrastructure\Native\Service\Encryption;

use SignerPHP\PdfSigner\Domain\Exception\ProtectionProcessException;

/**
 * An encrypted PDF that receives incremental updates (signatures, document timestamps, DSS).
 *
 * pdf-core reads and writes PDFs in clear, so updates are built on a clear mirror of the document:
 * the same objects, numbers and generations, decrypted. The objects an update adds or changes are then
 * encrypted with the document key and appended to the encrypted file as a new revision (ISO 32000-2
 * §7.5.6, §7.6.2). A signature's /ByteRange and /Contents are computed on those final encrypted bytes.
 */
final class EncryptedPdfDocument
{
    private const BYTE_RANGE_WIDTH = 64;

    private ?string $mirror = null;

    private function __construct(
        private readonly string $content,
        private readonly OpenedStandardSecurityHandler $handler,
        private readonly PdfDictionaryNode $trailer,
        private readonly PdfObjectGraphReader $reader,
    ) {}

    /**
     * Returns null when the document is not encrypted.
     *
     * @throws ProtectionProcessException when the encryption is unsupported or the password does not open it
     */
    public static function open(string $content, string $password = '', PdfObjectGraphReader $reader = new PdfObjectGraphReader): ?self
    {
        $encryption = $reader->encryption($content);
        if ($encryption['encrypt'] === null) {
            return null;
        }

        $id = $encryption['trailer']->get('ID');
        $firstId = $id instanceof PdfArrayNode && ($id->items[0] ?? null) instanceof PdfStringNode ? $id->items[0]->bytes : '';
        $handler = OpenedStandardSecurityHandler::open($encryption['encrypt'], $firstId, $password);

        return new self($content, $handler, $encryption['trailer'], $reader);
    }

    public function content(): string
    {
        return $this->content;
    }

    /**
     * The document in clear, as a single revision with the same object numbers. The /Encrypt object is
     * kept (unreferenced) so numbers of objects added to the mirror never collide with it.
     */
    public function plainMirror(): string
    {
        if ($this->mirror !== null) {
            return $this->mirror;
        }

        $graph = $this->reader->read($this->content, $this->handler);
        $output = "%PDF-{$graph->version}\n%\xE2\xE3\xCF\xD3\n";
        $offsets = [];
        foreach ($graph->objects as $object) {
            $offsets[$object->objectNumber] = [strlen($output), $object->generation];
            $output .= PdfObjectSerializer::writeObject($object, null, true);
        }

        $size = max(($offsets === [] ? 0 : max(array_keys($offsets))) + 1, (int) ($this->trailer->rawToken('Size') ?? '0'));
        $xrefOffset = strlen($output);
        $output .= "xref\n0 ".$size."\n0000000000 65535 f\r\n";
        for ($number = 1; $number < $size; $number++) {
            [$offset, $generation] = $offsets[$number] ?? [0, 65535];
            $output .= sprintf('%010d %05d %s', $offset, $generation, isset($offsets[$number]) ? 'n' : 'f')."\r\n";
        }

        $trailer = new PdfDictionaryNode([['Size', new PdfRawNode((string) $size)]]);
        foreach (['Root', 'Info', 'ID'] as $key) {
            $value = $graph->trailer->get($key);
            if ($value !== null) {
                $trailer->set($key, $value);
            }
        }

        return $this->mirror = $output.'trailer'."\n".PdfObjectSerializer::serialize($trailer, null)."\nstartxref\n".$xrefOffset."\n%%EOF\n";
    }

    /**
     * Appends, encrypted, the revision that was added to the clear mirror.
     *
     * @param  string  $updatedMirror  {@see plainMirror()} followed by one incremental update
     */
    public function appendRevision(string $updatedMirror): self
    {
        // An applier with nothing to add (for example, no validation data) returns the mirror unchanged.
        if ($updatedMirror === $this->plainMirror()) {
            return $this;
        }

        [$content] = $this->append($updatedMirror, false);

        return $this->withContent($content);
    }

    /**
     * Appends, encrypted, a revision that adds one signature or document timestamp dictionary whose
     * /Contents is an all-zero placeholder. Its /ByteRange is computed on the final bytes, and the value
     * returned by $sign (hex, at most the placeholder length) fills the placeholder.
     *
     * @param  callable(string $signedBytes, array{0:int,1:int,2:int,3:int} $byteRange): string  $sign
     */
    public function appendSignedRevision(string $updatedMirror, callable $sign): self
    {
        [$content, $placeholder] = $this->append($updatedMirror, true);
        [$contentsStart, $contentsEnd, $byteRangeOffset] = $placeholder;

        $byteRange = [0, $contentsStart, $contentsEnd, strlen($content) - $contentsEnd];
        $byteRangeToken = str_pad('['.implode(' ', $byteRange), self::BYTE_RANGE_WIDTH - 1).']';
        $content = substr_replace($content, $byteRangeToken, $byteRangeOffset, self::BYTE_RANGE_WIDTH);

        $hex = $sign(substr($content, 0, $contentsStart).substr($content, $contentsEnd), $byteRange);
        $capacity = $contentsEnd - $contentsStart - 2;
        if (strlen($hex) > $capacity || strlen($hex) % 2 !== 0 || ($hex !== '' && ! ctype_xdigit($hex))) {
            throw new ProtectionProcessException('The signature does not fit the reserved /Contents of the encrypted PDF.');
        }

        return $this->withContent(substr_replace($content, str_pad($hex, $capacity, '0'), $contentsStart + 1, $capacity));
    }

    private function withContent(string $content): self
    {
        $trailer = $this->reader->encryption($content)['trailer'];

        return new self($content, $this->handler, $trailer, $this->reader);
    }

    /**
     * @return array{0: string, 1: array{0:int,1:int,2:int}|null} the new content and, for a signed revision,
     *                                                            the /Contents delimiters and the /ByteRange offset
     */
    private function append(string $updatedMirror, bool $signed): array
    {
        $mirror = $this->plainMirror();
        if (! str_starts_with($updatedMirror, $mirror) || strlen($updatedMirror) === strlen($mirror)) {
            throw new ProtectionProcessException('The update was not appended to the clear mirror of the encrypted PDF.');
        }

        [$objects, $revisionTrailer] = self::parseRevision(substr($updatedMirror, strlen($mirror)));
        $placeholderObject = $signed ? self::placeholderObjectNumber($objects) : null;

        $output = $this->content;
        if (! str_ends_with($output, "\n") && ! str_ends_with($output, "\r")) {
            $output .= "\n";
        }

        $offsets = [];
        $placeholder = null;
        foreach ($objects as $object) {
            $offsets[$object->objectNumber] = [strlen($output), $object->generation];
            if ($object->objectNumber === $placeholderObject && $object->value instanceof PdfDictionaryNode) {
                $value = (clone $object->value)->set('ByteRange', new PdfRawNode(str_pad('[0 0 0 0', self::BYTE_RANGE_WIDTH - 1).']'));
                $written = PdfObjectSerializer::writeObject(new PdfIndirectObject($object->objectNumber, $object->generation, $value), $this->handler, $this->handler->encryptMetadata);
                $placeholder = self::placeholderOffsets($written, strlen($output));
                $output .= $written;

                continue;
            }

            $output .= PdfObjectSerializer::writeObject($object, $this->handler, $this->handler->encryptMetadata);
        }

        ksort($offsets);
        $xrefOffset = strlen($output);
        $output .= "xref\n".self::xrefSubsections($offsets);

        $size = max(
            (int) ($revisionTrailer->rawToken('Size') ?? '0'),
            (int) ($this->trailer->rawToken('Size') ?? '0'),
            max(array_keys($offsets)) + 1,
        );
        $trailer = new PdfDictionaryNode([['Size', new PdfRawNode((string) $size)]]);
        foreach (['Root', 'Info'] as $key) {
            $value = $revisionTrailer->get($key) ?? $this->trailer->get($key);
            if ($value !== null) {
                $trailer->set($key, $value);
            }
        }
        foreach (['Encrypt', 'ID'] as $key) {
            $value = $this->trailer->get($key);
            if ($value !== null) {
                $trailer->set($key, $value);
            }
        }
        $trailer->set('Prev', new PdfRawNode((string) self::startXref($this->content)));

        $output .= 'trailer'."\n".PdfObjectSerializer::serialize($trailer, null)."\nstartxref\n".$xrefOffset."\n%%EOF\n";

        return [$output, $placeholder];
    }

    /**
     * Objects of one incremental update written by pdf-core (objects, then an xref table and trailer).
     *
     * @return array{0: list<PdfIndirectObject>, 1: PdfDictionaryNode}
     */
    private static function parseRevision(string $revision): array
    {
        $parser = new PdfSyntaxParser($revision);
        $objects = [];
        $trailer = null;

        while (true) {
            $parser->skipWhitespaceAndComments();
            $header = $parser->readObjectHeader();
            if ($header === null) {
                break;
            }

            $value = $parser->parseValue();
            $keyword = $parser->readKeyword();
            $stream = null;
            if ($keyword === 'stream') {
                $stream = self::readStream($revision, $parser->position(), $value);
                $parser = new PdfSyntaxParser($revision, self::afterStream($revision, $parser->position(), strlen($stream)));
                $keyword = $parser->readKeyword();
            }
            if ($keyword !== 'endobj') {
                throw new ProtectionProcessException(sprintf('Malformed object %d in the PDF update.', $header[0]));
            }

            if ($value instanceof PdfDictionaryNode && $value->rawToken('Type') === '/XRef') {
                $trailer = $value;

                continue;
            }

            $objects[] = new PdfIndirectObject($header[0], $header[1], $value, $stream);
        }

        if ($trailer === null) {
            $position = strpos($revision, 'trailer', $parser->position());
            $value = $position === false ? null : (new PdfSyntaxParser($revision, $position + 7))->parseValue();
            $trailer = $value instanceof PdfDictionaryNode ? $value : null;
        }

        if ($objects === [] || $trailer === null) {
            throw new ProtectionProcessException('The PDF update has no objects or no trailer.');
        }

        return [$objects, $trailer];
    }

    private static function readStream(string $data, int $afterKeyword, PdfNode $dictionary): string
    {
        $length = $dictionary instanceof PdfDictionaryNode ? $dictionary->rawToken('Length') : null;
        if ($length === null || ! ctype_digit($length)) {
            throw new ProtectionProcessException('Streams in a PDF update must have a direct /Length.');
        }

        return substr($data, self::streamStart($data, $afterKeyword), (int) $length);
    }

    private static function afterStream(string $data, int $afterKeyword, int $length): int
    {
        $end = self::streamStart($data, $afterKeyword) + $length;
        $parser = new PdfSyntaxParser($data, $end);
        if ($parser->readKeyword() !== 'endstream') {
            throw new ProtectionProcessException('Stream /Length does not match its data in the PDF update.');
        }

        return $parser->position();
    }

    private static function streamStart(string $data, int $afterKeyword): int
    {
        if (substr($data, $afterKeyword, 2) === "\r\n") {
            return $afterKeyword + 2;
        }

        return $afterKeyword + (in_array(substr($data, $afterKeyword, 1), ["\n", "\r"], true) ? 1 : 0);
    }

    /**
     * @param  list<PdfIndirectObject>  $objects
     */
    private static function placeholderObjectNumber(array $objects): int
    {
        $found = [];
        foreach ($objects as $object) {
            $contents = $object->value instanceof PdfDictionaryNode ? $object->value->get('Contents') : null;
            if ($object->value instanceof PdfDictionaryNode && $object->value->has('ByteRange')
                && $contents instanceof PdfStringNode && $contents->bytes !== '' && trim($contents->bytes, "\0") === '') {
                $found[] = $object->objectNumber;
            }
        }

        if (count($found) !== 1) {
            throw new ProtectionProcessException(sprintf('Expected one signature placeholder in the PDF update, found %d.', count($found)));
        }

        return $found[0];
    }

    /**
     * @return array{0:int,1:int,2:int} offsets of "<" and after ">" of /Contents, and of the /ByteRange token
     */
    private static function placeholderOffsets(string $written, int $base): array
    {
        $contents = strpos($written, '/Contents <');
        $byteRange = strpos($written, '/ByteRange [0 0 0 0');
        if ($contents === false || $byteRange === false) {
            throw new ProtectionProcessException('Could not locate the signature placeholder in the encrypted update.');
        }

        $open = $contents + strlen('/Contents ');
        // The serializer writes /Contents as a hex string, so its closing ">" always follows.
        $close = (int) strpos($written, '>', $open);

        return [$base + $open, $base + $close + 1, $base + $byteRange + strlen('/ByteRange ')];
    }

    /**
     * @param  array<int, array{0:int,1:int}>  $offsets  sorted by object number
     */
    private static function xrefSubsections(array $offsets): string
    {
        $sections = '';
        $run = [];
        $previous = null;
        foreach ($offsets as $number => $entry) {
            if ($previous !== null && $number !== $previous + 1) {
                $sections .= self::xrefSubsection($run);
                $run = [];
            }
            $run[$number] = $entry;
            $previous = $number;
        }

        return $sections.self::xrefSubsection($run);
    }

    /**
     * @param  array<int, array{0:int,1:int}>  $run
     */
    private static function xrefSubsection(array $run): string
    {
        $lines = array_key_first($run).' '.count($run)."\n";
        foreach ($run as [$offset, $generation]) {
            $lines .= sprintf('%010d %05d n', $offset, $generation)."\r\n";
        }

        return $lines;
    }

    private static function startXref(string $content): int
    {
        if (preg_match_all('/startxref\s+(\d+)/', $content, $matches) < 1) {
            throw new ProtectionProcessException('Could not find startxref in the encrypted PDF.');
        }

        return (int) end($matches[1]);
    }
}
