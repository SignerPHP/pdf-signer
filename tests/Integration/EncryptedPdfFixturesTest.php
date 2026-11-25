<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Tests\Integration;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SignerPHP\PdfSigner\Domain\Exception\ProtectionProcessException;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\Encryption\EncryptedPdfDocument;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\Encryption\PdfDictionaryNode;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\Encryption\PdfObjectGraphReader;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\Encryption\PdfStringNode;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\PdfDocumentPreparer;
use SignerPHP\PdfSigner\Presentation\Signer;

/**
 * Encrypted PDFs written by qpdf (see tests/Fixtures/encrypted/README.md): every supported standard
 * security handler, with the pages inside an encrypted object stream.
 */
final class EncryptedPdfFixturesTest extends TestCase
{
    /**
     * @return iterable<string, array{0: string, 1: string}>
     */
    public static function fixturesAndPasswords(): iterable
    {
        $fixtures = [
            'aes256-r6-object-streams.pdf' => 'user-pw',
            'aes128-r4-object-streams.pdf' => '',
            'aes128-r4-clear-metadata.pdf' => '',
            'rc4-128-r3.pdf' => 'user-pw',
            'rc4-128-v4-crypt-filter.pdf' => '',
            'rc4-40-r2.pdf' => '',
        ];
        foreach ($fixtures as $file => $userPassword) {
            yield "$file, user password" => [$file, $userPassword];
            yield "$file, owner password" => [$file, 'owner-pw'];
        }
    }

    #[DataProvider('fixturesAndPasswords')]
    public function test_the_clear_mirror_is_readable_by_pdf_core(string $file, string $password): void
    {
        $document = EncryptedPdfDocument::open(self::fixture($file), $password);
        self::assertNotNull($document);

        // The page tree lives in the encrypted object stream; pdf-core can only walk it once decrypted.
        $mirror = (new PdfDocumentPreparer)->prepare($document->plainMirror());
        self::assertNotNull($mirror->getPageInfo()->getPage(0));
        self::assertNull($mirror->getPageInfo()->getPage(1));
        self::assertSame(self::fixture($file), $document->content());
    }

    #[DataProvider('fixturesAndPasswords')]
    public function test_signs_the_encrypted_document_with_its_own_key(string $file, string $password): void
    {
        $signed = Signer::signer()
            ->withPdfContent(self::fixture($file))
            ->withPdfPassword($password)
            ->withCertificatePath(__DIR__.'/../../exemplos/cert.pfx', '1234**')
            ->withPadesBaselineB()
            ->withoutTimestamp()
            ->withoutDefaultAppearance()
            ->sign();

        self::assertStringStartsWith(self::fixture($file), $signed);
        self::assertDoesNotMatchRegularExpression('/\/M\s*\(D:/', $signed);

        $reopened = EncryptedPdfDocument::open($signed, $password);
        self::assertNotNull($reopened);
        $signingTimes = [];
        foreach ((new PdfObjectGraphReader)->read($reopened->plainMirror())->objects as $object) {
            if ($object->value instanceof PdfDictionaryNode && $object->value->rawToken('Type') === '/Sig') {
                $time = $object->value->get('M');
                $signingTimes[] = $time instanceof PdfStringNode ? $time->bytes : '';
            }
        }
        self::assertCount(1, $signingTimes);
        self::assertMatchesRegularExpression('/^D:\d{14}/', $signingTimes[0]);

        $validation = Signer::validation()->withPdfContent($signed)->validate();
        self::assertTrue($validation->allValid, (string) ($validation->entries[0]->reason ?? ''));
    }

    /**
     * @return iterable<string, array{0: string}>
     */
    public static function fixtures(): iterable
    {
        foreach (glob(dirname(__DIR__).'/Fixtures/encrypted/*.pdf') ?: [] as $file) {
            yield basename($file) => [basename($file)];
        }
    }

    #[DataProvider('fixtures')]
    public function test_a_wrong_password_is_refused(string $file): void
    {
        $this->expectException(ProtectionProcessException::class);
        $this->expectExceptionMessage('The password does not open this encrypted PDF.');

        EncryptedPdfDocument::open(self::fixture($file), 'wrong-pw');
    }

    private static function fixture(string $file): string
    {
        return (string) file_get_contents(dirname(__DIR__).'/Fixtures/encrypted/'.$file);
    }
}
