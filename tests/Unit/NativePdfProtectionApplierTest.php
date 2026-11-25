<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Tests\Unit;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SignerPHP\PdfSigner\Application\DTO\ProtectionOptionsDto;
use SignerPHP\PdfSigner\Domain\Exception\ProtectionProcessException;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\Encryption\PdfArrayNode;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\Encryption\PdfDictionaryNode;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\Encryption\PdfNode;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\Encryption\PdfObjectGraphReader;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\Encryption\PdfRawNode;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\Encryption\PdfStringNode;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\NativePdfProtectionApplier;
use SignerPHP\PdfSigner\Tests\Support\PdfFixtureFactory;
use SignerPHP\PdfSigner\Tests\Support\ProtectionPdfFixtures;
use SignerPHP\PdfSigner\Tests\Support\StandardSecurityTestDecryptor;

final class NativePdfProtectionApplierTest extends TestCase
{
    public function test_defaults_to_aes_256_revision_6_and_round_trips_every_object(): void
    {
        $source = ProtectionPdfFixtures::richPdf();
        $protected = $this->protect($source, new ProtectionOptionsDto(ownerPassword: 'owner-pw', userPassword: 'user-pw'));
        $decryptor = new StandardSecurityTestDecryptor($protected);

        self::assertStringStartsWith('%PDF-1.7', $protected);
        self::assertSame(6, $decryptor->revision());
        self::assertSame('5', $decryptor->encrypt->rawToken('V'));
        self::assertSame('256', $decryptor->encrypt->rawToken('Length'));
        self::assertStringContainsString('/CFM /AESV3 /Length 32', $protected);
        self::assertFalse($decryptor->encrypt->has('EncryptMetadata'));

        self::assertNull($decryptor->fileKey('wrong'));
        self::assertNull($decryptor->fileKey(''));
        $userKey = $decryptor->fileKey('user-pw');
        self::assertSame($userKey, $decryptor->fileKey('owner-pw'));
        self::assertSame(32, strlen((string) $userKey));

        $perms = $decryptor->permsBlock((string) $userKey);
        self::assertSame(pack('V', $decryptor->permissions() & 0xFFFFFFFF)."\xFF\xFF\xFF\xFFTadb", substr($perms, 0, 12));

        $this->assertSameDocument($source, $decryptor->decryptedObjects('user-pw'));
        $this->assertSameDocument($source, $decryptor->decryptedObjects('owner-pw'));

        $catalog = $decryptor->rawObjects[1]['value'];
        self::assertInstanceOf(PdfDictionaryNode::class, $catalog);
        self::assertStringContainsString('/Extensions <</ADBE <</BaseVersion /1.7 /ExtensionLevel 8>>>>', $protected);

        self::assertStringNotContainsString('Protected', $protected);
        self::assertStringNotContainsString('standalone', $protected);
        self::assertStringNotContainsString('xpacket', $protected);
        self::assertStringNotContainsString('pt-BR', $protected);
        self::assertStringContainsString('/ID [<00112233445566778899aabbccddeeff> <', $protected);
        self::assertStringContainsString('/Info 5 0 R', $protected);
    }

    public function test_aes_128_uses_revision_4_and_round_trips_every_object(): void
    {
        $source = ProtectionPdfFixtures::richPdf();
        $protected = $this->protect($source, new ProtectionOptionsDto(ownerPassword: 'owner-pw', userPassword: 'user-pw', keyLengthBits: 128));
        $decryptor = new StandardSecurityTestDecryptor($protected);

        self::assertStringStartsWith('%PDF-1.6', $protected);
        self::assertSame(4, $decryptor->revision());
        self::assertSame('4', $decryptor->encrypt->rawToken('V'));
        self::assertSame('128', $decryptor->encrypt->rawToken('Length'));
        self::assertStringContainsString('/CFM /AESV2 /Length 16', $protected);
        self::assertStringNotContainsString('/Extensions', $protected);
        self::assertFalse($decryptor->encrypt->has('OE'));

        self::assertNull($decryptor->fileKey('wrong'));
        self::assertSame(16, strlen((string) $decryptor->fileKey('user-pw')));
        $this->assertSameDocument($source, $decryptor->decryptedObjects('user-pw'));
    }

    public function test_aes_128_converts_latin1_utf8_passwords_and_keeps_other_passwords_as_bytes(): void
    {
        $source = PdfFixtureFactory::minimalPdf();

        $latin1 = new StandardSecurityTestDecryptor($this->protect($source, new ProtectionOptionsDto('dono', 'senhaçé', keyLengthBits: 128)));
        self::assertNotNull($latin1->fileKey("senha\xE7\xE9"));

        $wide = new StandardSecurityTestDecryptor($this->protect($source, new ProtectionOptionsDto('dono', 'Ωmega€', keyLengthBits: 128)));
        self::assertNotNull($wide->fileKey('Ωmega€'));

        $invalidUtf8 = new StandardSecurityTestDecryptor($this->protect($source, new ProtectionOptionsDto('dono', "\xFFabc", keyLengthBits: 128)));
        self::assertNotNull($invalidUtf8->fileKey("\xFFabc"));
    }

    public function test_aes_256_truncates_passwords_to_127_bytes(): void
    {
        $password = str_repeat('p', 130);
        $decryptor = new StandardSecurityTestDecryptor($this->protect(PdfFixtureFactory::minimalPdf(), new ProtectionOptionsDto('owner', $password)));

        self::assertNotNull($decryptor->fileKey(substr($password, 0, 127)));
    }

    /**
     * @return iterable<string, array{0: int, 1: bool, 2: bool, 3: bool, 4: int}>
     */
    public static function permissionMatrix(): iterable
    {
        foreach ([256, 128] as $bits) {
            yield "{$bits} all allowed" => [$bits, true, true, true, -4];
            yield "{$bits} nothing allowed" => [$bits, false, false, false, -3392];
            yield "{$bits} print only" => [$bits, true, false, false, -1340];
            yield "{$bits} copy only" => [$bits, false, true, false, -3376];
            yield "{$bits} modify only" => [$bits, false, false, true, -2072];
        }
    }

    #[DataProvider('permissionMatrix')]
    public function test_writes_permission_flags(int $bits, bool $print, bool $copy, bool $modify, int $expected): void
    {
        $options = new ProtectionOptionsDto('owner', '', $print, $copy, $modify, $bits);
        $decryptor = new StandardSecurityTestDecryptor($this->protect(PdfFixtureFactory::minimalPdf(), $options));
        $flags = $decryptor->permissions();

        self::assertSame($expected, $flags);
        self::assertSame($print, ($flags & 0x4) !== 0 && ($flags & 0x800) !== 0);
        self::assertSame($copy, ($flags & 0x10) !== 0);
        self::assertSame($modify, ($flags & 0x8) !== 0 && ($flags & 0x20) !== 0 && ($flags & 0x100) !== 0 && ($flags & 0x400) !== 0);
        self::assertNotSame(0, $flags & 0x200, 'accessibility extraction stays allowed');
        self::assertSame(0, $flags & 0x3, 'bits 1-2 must be zero');
        self::assertNotNull($decryptor->fileKey(''), 'empty user password opens the document');
    }

    /**
     * @return iterable<string, array{0: int}>
     */
    public static function keyLengths(): iterable
    {
        yield 'aes-256' => [256];
        yield 'aes-128' => [128];
    }

    #[DataProvider('keyLengths')]
    public function test_leaves_metadata_in_clear_when_requested(int $bits): void
    {
        $source = ProtectionPdfFixtures::richPdf();
        $protected = $this->protect($source, new ProtectionOptionsDto('owner', 'user', keyLengthBits: $bits, encryptMetadata: false));
        $decryptor = new StandardSecurityTestDecryptor($protected);

        self::assertSame('false', $decryptor->encrypt->rawToken('EncryptMetadata'));
        self::assertStringContainsString(ProtectionPdfFixtures::METADATA, $protected);
        self::assertStringNotContainsString('Protected', $protected);
        $this->assertSameDocument($source, $decryptor->decryptedObjects('user', decryptMetadata: false));

        if ($bits === 256) {
            self::assertSame('F', $decryptor->permsBlock((string) $decryptor->fileKey('user'))[8]);
        }
    }

    #[DataProvider('keyLengths')]
    public function test_generates_owner_password_and_document_id_when_absent(int $bits): void
    {
        $source = PdfFixtureFactory::minimalPdf();
        $first = new StandardSecurityTestDecryptor($this->protect($source, new ProtectionOptionsDto(keyLengthBits: $bits)));
        $second = new StandardSecurityTestDecryptor($this->protect($source, new ProtectionOptionsDto(keyLengthBits: $bits)));

        self::assertNotNull($first->fileKey(''));
        $this->assertSameDocument($source, $first->decryptedObjects(''));

        $firstId = $first->trailer->get('ID');
        $secondId = $second->trailer->get('ID');
        self::assertInstanceOf(PdfArrayNode::class, $firstId);
        self::assertInstanceOf(PdfArrayNode::class, $secondId);
        self::assertSame(16, strlen($this->stringBytes($firstId->items[0])));
        self::assertNotSame($this->stringBytes($firstId->items[0]), $this->stringBytes($secondId->items[0]));
        self::assertNotEquals($first->encrypt->get('O'), $second->encrypt->get('O'));
    }

    public function test_unpacks_object_streams_and_drops_cross_reference_streams(): void
    {
        $source = (string) file_get_contents(__DIR__.'/../Fixtures/protection/object-streams.pdf');
        self::assertStringContainsString('/ObjStm', $source);

        $protected = $this->protect($source, new ProtectionOptionsDto('owner', 'user'));
        $decryptor = new StandardSecurityTestDecryptor($protected);

        self::assertStringNotContainsString('/ObjStm', $protected);
        self::assertStringNotContainsString('/XRef', $protected);
        $this->assertSameDocument($source, $decryptor->decryptedObjects('user'));
    }

    public function test_keeps_signature_contents_in_clear(): void
    {
        $source = ProtectionPdfFixtures::build([
            1 => '<< /Type /Catalog /Pages 2 0 R >>',
            2 => '<< /Type /Pages /Kids [] /Count 0 >>',
            3 => '<< /Type /Sig /Filter /Adobe.PPKLite /ByteRange [0 10 20 30] /Contents <DEADBEEF> /Name (Signer Name) >>',
            4 => '<< /Type /DocTimeStamp /Contents <CAFEBABE> >>',
            5 => '<< /ByteRange [0 1 2 3] /Contents <0BADF00D> >>',
        ], '/Root 1 0 R');

        $protected = $this->protect($source, new ProtectionOptionsDto('owner', 'user'));

        self::assertStringContainsString('/Contents <deadbeef>', $protected);
        self::assertStringContainsString('/Contents <cafebabe>', $protected);
        self::assertStringContainsString('/Contents <0badf00d>', $protected);
        self::assertStringNotContainsString(bin2hex('Signer Name'), $protected);
        $this->assertSameDocument($source, (new StandardSecurityTestDecryptor($protected))->decryptedObjects('user'));
    }

    public function test_drops_linearization_dictionary(): void
    {
        $source = ProtectionPdfFixtures::build([
            1 => '<< /Linearized 1 /L 1000 /H [10 20] /O 3 /E 500 /N 1 /T 900 >>',
            2 => '<< /Type /Catalog /Pages 3 0 R >>',
            3 => '<< /Type /Pages /Kids [] /Count 0 >>',
        ], '/Root 2 0 R');

        $protected = $this->protect($source, new ProtectionOptionsDto('owner'));

        self::assertStringNotContainsString('/Linearized', $protected);
        self::assertStringContainsString("xref\n0 5\n0000000000 65535 f\r\n0000000000 00000 f\r\n", $protected);
    }

    public function test_uses_the_latest_revision_of_incrementally_updated_documents(): void
    {
        $base = PdfFixtureFactory::minimalPdf();
        preg_match('/startxref\n(\d+)/', $base, $matches);
        $offset = strlen($base);
        $update = "5 0 obj\n<< /Producer (Updated Producer) >>\nendobj\n6 0 obj\n(new object)\nendobj\n";
        $xref = strlen($base) + strlen($update);
        $source = $base.$update.sprintf(
            "xref\n5 2\n%010d 00000 n \n%010d 00000 n \ntrailer\n<< /Size 7 /Root 1 0 R /Info 5 0 R /Prev %d >>\nstartxref\n%d\n%%%%EOF\n",
            $offset,
            $offset + strpos($update, '6 0 obj'),
            $matches[1],
            $xref,
        );

        $objects = (new StandardSecurityTestDecryptor($this->protect($source, new ProtectionOptionsDto('owner', 'user'))))->decryptedObjects('user');

        self::assertEquals(new PdfStringNode('Updated Producer'), $this->dictionary($objects[5]['value'])->get('Producer'));
        self::assertEquals(new PdfStringNode('new object'), $objects[6]['value']);
        self::assertSame(1, substr_count($this->protect($source, new ProtectionOptionsDto('owner')), '%%EOF'));
    }

    public function test_recovers_streams_with_wrong_or_unresolvable_length(): void
    {
        $data = "0 0 m 10 10 l S\n";
        $source = ProtectionPdfFixtures::build([
            1 => '<< /Type /Catalog /Pages 2 0 R >>',
            2 => '<< /Type /Pages /Kids [] /Count 0 >>',
            3 => "<< /Length 999 >>\nstream\r\n".$data."\r\nendstream",
            4 => "<< /Length 9 0 R >>\nstream\n".$data."\nendstream",
            5 => "<< /Length 6 0 R >>\nstream\r".$data."\rendstream",
            6 => '/NotANumber',
            7 => "<< /Length [1] >>\nstream\n".$data."\nendstream",
            8 => "<< >>\nstream\n".$data."\nendstream",
        ], '/Root 1 0 R');

        $objects = (new StandardSecurityTestDecryptor($this->protect($source, new ProtectionOptionsDto('owner', 'user'))))->decryptedObjects('user');

        foreach ([3, 4, 5, 7, 8] as $number) {
            self::assertSame($data, $objects[$number]['stream'], "stream {$number}");
        }
    }

    public function test_preserves_generation_numbers_and_finds_objects_at_wrong_offsets(): void
    {
        $source = ProtectionPdfFixtures::build([
            1 => '<< /Type /Catalog /Pages 2 0 R >>',
            2 => '<< /Type /Pages /Kids [] /Count 0 /Note (gen) >>',
        ], '/Root 1 0 R');
        $source = str_replace("2 0 obj\n", "2 3 obj\n", $source);
        // Point object 1 to the header of object 2: it must be located by searching for its own header.
        $source = (string) preg_replace(
            '/xref\n0 3\n0000000000 65535 f \n\d{10}/',
            sprintf("xref\n0 3\n0000000000 65535 f \n%010d", strpos($source, '2 3 obj')),
            $source,
        );

        $protected = $this->protect($source, new ProtectionOptionsDto('owner', 'user', keyLengthBits: 128));
        $objects = (new StandardSecurityTestDecryptor($protected))->decryptedObjects('user');

        self::assertStringContainsString("2 3 obj\n", $protected);
        self::assertSame(3, $objects[2]['generation']);
        self::assertEquals(new PdfStringNode('gen'), $this->dictionary($objects[2]['value'])->get('Note'));
        self::assertSame('/Catalog', $this->dictionary($objects[1]['value'])->rawToken('Type'));
    }

    public function test_merges_adobe_extension_into_existing_catalog_extensions(): void
    {
        $catalogs = [
            '<< /Type /Catalog /Pages 2 0 R /Extensions << /XYZ << /BaseVersion /1.7 /ExtensionLevel 1 >> >> >>' => '/Extensions <</XYZ <</BaseVersion /1.7 /ExtensionLevel 1>> /ADBE <</BaseVersion /1.7 /ExtensionLevel 8>>>>',
            '<< /Type /Catalog /Pages 2 0 R /Extensions << /ADBE << /BaseVersion /1.7 /ExtensionLevel 3 >> >> >>' => '/Extensions <</ADBE <</BaseVersion /1.7 /ExtensionLevel 3>>>>',
            '<< /Type /Catalog /Pages 2 0 R /Extensions 3 0 R >>' => '/Extensions 3 0 R',
        ];

        foreach ($catalogs as $catalog => $expected) {
            $source = ProtectionPdfFixtures::build([
                1 => $catalog,
                2 => '<< /Type /Pages /Kids [] /Count 0 >>',
                3 => '<< /ADBE << /BaseVersion /1.7 /ExtensionLevel 5 >> >>',
            ], '/Root 1 0 R', '2.0');

            $protected = $this->protect($source, new ProtectionOptionsDto('owner'));

            self::assertStringStartsWith('%PDF-2.0', $protected);
            self::assertStringContainsString($expected, $protected);
        }
    }

    public function test_ignores_malformed_info_and_length_references(): void
    {
        $data = "0 0 m 1 1 l S\n";
        $source = ProtectionPdfFixtures::build([
            1 => '<< /Type /Catalog /Pages 2 0 R >>',
            2 => '<< /Type /Pages /Kids [] /Count 0 >>',
            3 => "<< /Length /Unknown >>\nstream\n".$data."\nendstream",
        ], '/Root 1 0 R /Info 3');

        $protected = $this->protect($source, new ProtectionOptionsDto('owner', 'user'));
        $decryptor = new StandardSecurityTestDecryptor($protected);

        self::assertFalse($decryptor->trailer->has('Info'));
        self::assertSame($data, $decryptor->decryptedObjects('user')[3]['stream']);
    }

    public function test_rejects_object_missing_from_its_object_stream(): void
    {
        $source = (string) file_get_contents(__DIR__.'/../Fixtures/protection/object-streams.pdf');
        $source = str_replace('/ObjStm /Length 559 /N 5 ', '/ObjStm /Length 559 /N 4 ', $source);

        $this->expectException(ProtectionProcessException::class);
        $this->expectExceptionMessage('Object 6 not found in object stream 1');

        (new PdfObjectGraphReader)->read($source);
    }

    public function test_rejects_input_that_is_not_a_pdf(): void
    {
        $this->expectException(ProtectionProcessException::class);
        $this->expectExceptionMessage('Input is not a PDF document');

        $this->protect('plain text', new ProtectionOptionsDto('owner'));
    }

    public function test_rejects_documents_that_are_already_encrypted(): void
    {
        $source = ProtectionPdfFixtures::build([
            1 => '<< /Type /Catalog /Pages 2 0 R >>',
            2 => '<< /Type /Pages /Kids [] /Count 0 >>',
            3 => '<< /Filter /Standard /V 2 /R 3 >>',
        ], '/Root 1 0 R /Encrypt 3 0 R');

        $this->expectException(ProtectionProcessException::class);
        $this->expectExceptionMessage('already encrypted');

        $this->protect($source, new ProtectionOptionsDto('owner'));
    }

    public function test_rejects_stream_without_dictionary(): void
    {
        $source = ProtectionPdfFixtures::build([
            1 => '<< /Type /Catalog /Pages 2 0 R >>',
            2 => '<< /Type /Pages /Kids [] /Count 0 >>',
            3 => "[1 2]\nstream\nabc\nendstream",
        ], '/Root 1 0 R');

        $this->expectException(ProtectionProcessException::class);
        $this->expectExceptionMessage('Stream object 3 has no dictionary');

        $this->protect($source, new ProtectionOptionsDto('owner'));
    }

    public function test_rejects_unterminated_stream(): void
    {
        $source = ProtectionPdfFixtures::build([
            1 => '<< /Type /Catalog /Pages 2 0 R >>',
            2 => '<< /Type /Pages /Kids [] /Count 0 >>',
        ], '/Root 1 0 R');
        $source = str_replace("2 0 obj\n<< /Type /Pages /Kids [] /Count 0 >>\nendobj", "2 0 obj\n<< /Type /Pages /Kids [] /Count 0 /Length 2 >>\nstream\nab", $source);

        $this->expectException(ProtectionProcessException::class);
        $this->expectExceptionMessage('Unterminated stream');

        (new PdfObjectGraphReader)->read($source);
    }

    public function test_rejects_objects_that_cannot_be_located(): void
    {
        $source = ProtectionPdfFixtures::build([
            1 => '<< /Type /Catalog /Pages 2 0 R >>',
            2 => '<< /Type /Pages /Kids [] /Count 0 >>',
        ], '/Root 1 0 R');
        $source = str_replace('2 0 obj', '9 0 obj', $source);

        $this->expectException(ProtectionProcessException::class);
        $this->expectExceptionMessage('Could not locate object 2');

        (new PdfObjectGraphReader)->read($source);
    }

    private function protect(string $pdf, ProtectionOptionsDto $options): string
    {
        return (new NativePdfProtectionApplier)->apply($pdf, $options);
    }

    /**
     * @param  array<int, array{generation: int, value: PdfNode, stream: ?string}>  $decrypted
     */
    private function assertSameDocument(string $source, array $decrypted): void
    {
        $expected = [];
        foreach ((new PdfObjectGraphReader)->read($source)->objects as $number => $object) {
            $expected[$number] = self::canonical($object->value, $object->stream !== null).($object->stream === null ? '' : ' stream:'.bin2hex($object->stream));
        }

        $actual = [];
        foreach ($decrypted as $number => $object) {
            $actual[$number] = self::canonical($object['value'], $object['stream'] !== null).($object['stream'] === null ? '' : ' stream:'.bin2hex($object['stream']));
        }

        self::assertSame($expected, $actual);
    }

    /**
     * Canonical form ignoring what encryption legitimately changes: stream /Length and the catalog /Extensions.
     */
    private static function canonical(PdfNode $node, bool $isStream = false): string
    {
        if ($node instanceof PdfStringNode) {
            return 'S:'.bin2hex($node->bytes);
        }

        if ($node instanceof PdfArrayNode) {
            return '['.implode(' ', array_map(static fn (PdfNode $item): string => self::canonical($item), $node->items)).']';
        }

        if ($node instanceof PdfDictionaryNode) {
            $parts = [];
            foreach ($node->entries() as [$key, $value]) {
                if (($isStream && $key === 'Length') || ($key === 'Extensions' && $node->rawToken('Type') === '/Catalog')) {
                    continue;
                }
                $parts[] = '/'.$key.' '.self::canonical($value);
            }

            return '<<'.implode(' ', $parts).'>>';
        }

        return $node instanceof PdfRawNode ? $node->token : '?';
    }

    private function dictionary(PdfNode $node): PdfDictionaryNode
    {
        self::assertInstanceOf(PdfDictionaryNode::class, $node);

        return $node;
    }

    private function stringBytes(PdfNode $node): string
    {
        self::assertInstanceOf(PdfStringNode::class, $node);

        return $node->bytes;
    }
}
