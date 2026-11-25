<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Tests\Integration;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SignerPHP\PdfSigner\Application\DTO\ProtectionOptionsDto;
use SignerPHP\PdfSigner\Application\DTO\TimestampOptionsDto;
use SignerPHP\PdfSigner\Domain\Exception\SignProcessException;
use SignerPHP\PdfSigner\Infrastructure\Native\Contract\LongTermValidationApplierInterface;
use SignerPHP\PdfSigner\Infrastructure\Native\Contract\TimestampTokenProviderInterface;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\DocumentTimestampApplier;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\Encryption\EncryptedPdfDocument;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\Encryption\PdfDictionaryNode;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\Encryption\PdfObjectGraphReader;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\Encryption\PdfStringNode;
use SignerPHP\PdfSigner\Presentation\Signer;
use SignerPHP\PdfSigner\Tests\Support\PdfFixtureFactory;

/**
 * Signing an encrypted PDF must encrypt every string and stream the signature revision adds, except
 * the signature /Contents (ISO 32000-2 §7.6.2). Before the fix, /M and the other strings were written in
 * clear, so readers decrypted them into garbage and validators lost the signing time.
 */
final class EncryptedPdfSigningTest extends TestCase
{
    private const CERTIFICATE = __DIR__.'/../../exemplos/cert.pfx';

    private const CERTIFICATE_PASSWORD = '1234**';

    /**
     * @return iterable<string, array{0: ProtectionOptionsDto}>
     */
    public static function protections(): iterable
    {
        yield 'AES-256, no user password' => [ProtectionOptionsDto::preventCopy(ownerPassword: 'owner-secret')];
        yield 'AES-128, no user password' => [new ProtectionOptionsDto(ownerPassword: 'owner-secret', allowCopy: false, keyLengthBits: 128)];
        yield 'AES-256 with a user password' => [new ProtectionOptionsDto(ownerPassword: 'owner-secret', userPassword: 'user-secret', allowCopy: false)];
    }

    #[DataProvider('protections')]
    public function test_protect_then_sign_encrypts_the_signature_revision(ProtectionOptionsDto $protection): void
    {
        $signed = Signer::signer()
            ->withPdfContent(PdfFixtureFactory::minimalPdf())
            ->withCertificatePath(self::CERTIFICATE, self::CERTIFICATE_PASSWORD)
            ->withPadesBaselineB()
            ->withoutTimestamp()
            ->withoutDefaultAppearance()
            ->withProtection($protection)
            ->protectThenSign();

        // The signing time is no longer written in clear...
        self::assertDoesNotMatchRegularExpression('/\/M\s*\(D:/', $signed);
        // ...but decrypts, with the document key, to a PDF date.
        $signature = $this->signatureDictionary($signed, $protection->userPassword);
        $signingTime = $signature->get('M');
        self::assertInstanceOf(PdfStringNode::class, $signingTime);
        self::assertMatchesRegularExpression('/^D:\d{14}/', $signingTime->bytes);

        // The CMS stays in clear and covers the final encrypted bytes.
        $validation = Signer::validation()->withPdfContent($signed)->validate();
        self::assertTrue($validation->hasSignatures);
        self::assertTrue($validation->allValid, (string) ($validation->entries[0]->reason ?? ''));

        $this->assertQpdfReadsAndDecrypts($signed, $protection->userPassword, 1);
    }

    public function test_signs_an_already_protected_pdf_with_its_password(): void
    {
        $protected = Signer::protection()
            ->withPdfContent(PdfFixtureFactory::minimalPdf())
            ->withProtection(new ProtectionOptionsDto(ownerPassword: 'owner-secret', userPassword: 'user-secret'))
            ->protect();

        $first = $this->sign($protected, 'user-secret');
        $second = $this->sign($first, 'owner-secret');

        $validation = Signer::validation()->withPdfContent($second)->validate();
        self::assertCount(2, $validation->entries);
        self::assertTrue($validation->allValid, implode(' | ', array_map(static fn ($entry): string => (string) $entry->reason, $validation->entries)));
        self::assertStringStartsWith($first, $second, 'the second signature is an incremental update of the first');

        $this->assertQpdfReadsAndDecrypts($second, 'user-secret', 2);
    }

    public function test_refuses_an_encrypted_pdf_that_its_password_does_not_open(): void
    {
        $protected = Signer::protection()
            ->withPdfContent(PdfFixtureFactory::minimalPdf())
            ->withProtection(new ProtectionOptionsDto(ownerPassword: 'owner-secret', userPassword: 'user-secret'))
            ->protect();

        $this->expectException(SignProcessException::class);
        $this->expectExceptionMessage('The password does not open this encrypted PDF.');

        $this->sign($protected, 'wrong');
    }

    public function test_document_timestamp_and_dss_revisions_are_encrypted_too(): void
    {
        $protected = Signer::protection()
            ->withPdfContent(PdfFixtureFactory::minimalPdf())
            ->withProtection(ProtectionOptionsDto::preventCopy(ownerPassword: 'owner-secret'))
            ->protect();
        $document = EncryptedPdfDocument::open($protected);
        self::assertNotNull($document);

        $tokenProvider = new class implements TimestampTokenProviderInterface
        {
            public ?string $coveredBytes = null;

            public function requestTokenHex(string $signedContent, array $byteRange, TimestampOptionsDto $options): string
            {
                $this->coveredBytes = substr($signedContent, $byteRange[0], $byteRange[1]).substr($signedContent, $byteRange[2], $byteRange[3]);

                return 'ABCDEF';
            }
        };
        $timestamped = (new DocumentTimestampApplier(timestampTokenProvider: $tokenProvider))
            ->applyToEncrypted($document, new TimestampOptionsDto('https://tsa.example'));

        $content = $timestamped->content();
        self::assertStringStartsWith($protected, $content);
        self::assertMatchesRegularExpression('/\/Contents <ABCDEF0+>/', $content);
        // The token covered exactly the final bytes outside /Contents.
        self::assertNotNull($tokenProvider->coveredBytes);
        self::assertSame($tokenProvider->coveredBytes, (string) preg_replace('/<ABCDEF0+>/', '', $content));

        $dss = (new class implements LongTermValidationApplierInterface
        {
            public function apply(string $signedPdfContent): string
            {
                // A DSS-like revision: a new stream with a string, appended by pdf-core.
                $document = (new \SignerPHP\PdfSigner\Infrastructure\Native\Service\PdfDocumentPreparer)->prepare($signedPdfContent);
                $stream = $document->createObject(['Type' => new \SignerPHP\PdfCore\PdfValue\PDFValueType('EmbeddedFile')]);
                $stream->setStream('clear dss payload', false);
                $stream['Name'] = new \SignerPHP\PdfCore\PdfValue\PDFValueString('clear dss name');
                $document->addObject($stream);

                [$docToXref, $offsets] = \SignerPHP\PdfCore\Xref\Xref::new()->withPdfDocument($document)->generateContentToXref();
                $docFromXref = (new \SignerPHP\PdfSigner\Infrastructure\Native\Service\XrefContentResolver)->resolve($document, $offsets, $docToXref->size());

                return $docToXref->raw().$docFromXref->raw();
            }
        })->apply($timestamped->plainMirror());
        $withDss = $timestamped->appendRevision($dss);

        self::assertStringNotContainsString('clear dss payload', $withDss->content());
        self::assertStringNotContainsString('clear dss name', $withDss->content());
        self::assertStringContainsString('clear dss payload', (string) $withDss->plainMirror());
        self::assertSame($withDss, $withDss->appendRevision($withDss->plainMirror()), 'an unchanged mirror appends nothing');
    }

    public function test_unencrypted_documents_are_not_opened(): void
    {
        self::assertNull(EncryptedPdfDocument::open(PdfFixtureFactory::minimalPdf()));
    }

    private function sign(string $pdf, string $password): string
    {
        return Signer::signer()
            ->withPdfContent($pdf)
            ->withPdfPassword($password)
            ->withCertificatePath(self::CERTIFICATE, self::CERTIFICATE_PASSWORD)
            ->withPadesBaselineB()
            ->withoutTimestamp()
            ->withoutDefaultAppearance()
            ->sign();
    }

    private function signatureDictionary(string $pdf, string $password): PdfDictionaryNode
    {
        $document = EncryptedPdfDocument::open($pdf, $password);
        self::assertNotNull($document);
        $graph = (new PdfObjectGraphReader)->read($document->plainMirror());
        foreach ($graph->objects as $object) {
            if ($object->value instanceof PdfDictionaryNode && $object->value->rawToken('Type') === '/Sig') {
                return $object->value;
            }
        }

        self::fail('No signature dictionary found.');
    }

    /**
     * qpdf as an independent reader: the file must be structurally valid, and decrypting it must give
     * readable signature dictionaries (a clear /M decrypts to garbage, which is the original bug).
     */
    private function assertQpdfReadsAndDecrypts(string $pdf, string $password, int $signatures): void
    {
        if (trim((string) shell_exec('command -v qpdf 2>/dev/null')) === '') {
            if (getenv('CI') !== false && getenv('CI') !== '') {
                self::fail('qpdf is required in CI to check signed encrypted PDFs.');
            }

            return;
        }

        $file = (string) tempnam(sys_get_temp_dir(), 'enc-signed');
        file_put_contents($file, $pdf);
        try {
            exec('qpdf --password='.escapeshellarg($password).' --check '.escapeshellarg($file).' 2>&1', $check, $code);
            self::assertSame(0, $code, implode("\n", $check));

            exec('qpdf --password='.escapeshellarg($password).' --qdf --object-streams=disable --decrypt '.escapeshellarg($file).' - 2>&1', $decrypted);
            preg_match_all('/\/M \(D:\d{14}/', implode("\n", $decrypted), $times);
            self::assertCount($signatures, $times[0], 'every signature /M must decrypt to a PDF date');
        } finally {
            @unlink($file);
        }
    }
}
