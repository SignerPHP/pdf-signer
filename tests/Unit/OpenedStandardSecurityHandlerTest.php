<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Tests\Unit;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SignerPHP\PdfSigner\Domain\Exception\ProtectionProcessException;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\Encryption\Aes128StandardSecurityHandler;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\Encryption\Aes256StandardSecurityHandler;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\Encryption\OpenedStandardSecurityHandler;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\Encryption\PdfDictionaryNode;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\Encryption\PdfRawNode;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\Encryption\PdfStringNode;

final class OpenedStandardSecurityHandlerTest extends TestCase
{
    private const ID = '0123456789abcdef';

    public function test_round_trips_with_the_handlers_that_create_encryption(): void
    {
        $handlers = [
            'AES-256' => new Aes256StandardSecurityHandler('user', 'owner', -4, true),
            'AES-128' => new Aes128StandardSecurityHandler('user', 'owner', -4, true, self::ID),
        ];
        foreach ($handlers as $name => $creator) {
            foreach (['user', 'owner'] as $password) {
                $opened = OpenedStandardSecurityHandler::open($creator->encryptionDictionary(), self::ID, $password);
                $cipher = $creator->encrypt('payload', 12, 0);

                self::assertSame('payload', $opened->decrypt($cipher, 12, 0), "$name / $password");
                self::assertSame('payload', $opened->decrypt($opened->encrypt('payload', 12, 0), 12, 0), "$name / $password");
                self::assertEquals($creator->encryptionDictionary(), $opened->encryptionDictionary());
                self::assertTrue($opened->encryptMetadata);
            }
        }

        $opened = OpenedStandardSecurityHandler::open((new Aes128StandardSecurityHandler('', 'owner', -4, false, self::ID))->encryptionDictionary(), self::ID, '');
        self::assertFalse($opened->encryptMetadata);
        self::assertSame('1.4', $opened->minimumPdfVersion());
        self::assertNull($opened->adobeExtensionLevel());
    }

    public function test_rejects_aes_data_that_cannot_be_decrypted(): void
    {
        $opened = OpenedStandardSecurityHandler::open((new Aes256StandardSecurityHandler('', 'owner', -4, true))->encryptionDictionary(), self::ID, '');

        foreach (['short' => 'too short', 'bad padding' => str_repeat("\x01", 48)] as $case => $data) {
            try {
                $opened->decrypt($data, 3, 0);
                self::fail("$case: accepted");
            } catch (ProtectionProcessException $exception) {
                self::assertMatchesRegularExpression('/invalid length|Could not decrypt/', $exception->getMessage(), $case);
            }
        }
    }

    /**
     * @return iterable<string, array{0: PdfDictionaryNode, 1: string}>
     */
    public static function unsupported(): iterable
    {
        $aes128 = static fn (): PdfDictionaryNode => (new Aes128StandardSecurityHandler('', 'owner', -4, true, self::ID))->encryptionDictionary();
        $aes256 = static fn (): PdfDictionaryNode => (new Aes256StandardSecurityHandler('', 'owner', -4, true))->encryptionDictionary();

        yield 'public-key handler' => [$aes256()->set('Filter', new PdfRawNode('/Adobe.PubSec')), 'Only the standard security handler'];
        yield 'revision 5' => [$aes256()->set('R', new PdfRawNode('5')), 'Unsupported PDF encryption (/V 5 /R 5)'];
        yield 'short /U' => [$aes256()->set('U', new PdfStringNode('short')), 'Malformed AES-256 encryption dictionary'];
        yield 'missing /UE' => [self::without($aes256(), 'UE'), 'Encryption dictionary has no /UE string'];
        yield 'identity crypt filter' => [$aes128()->set('StmF', new PdfRawNode('/Identity'))->set('StrF', new PdfRawNode('/Identity')), 'identity stream and string crypt filters'];
        yield 'different crypt filters' => [$aes128()->set('StrF', new PdfRawNode('/Identity')), 'different or identity'];
        yield 'unknown crypt filter method' => [$aes128()->set('CF', new PdfDictionaryNode([['StdCF', new PdfDictionaryNode([['CFM', new PdfRawNode('/None')]])]])), 'Unsupported crypt filter method /None'];
        yield 'missing crypt filter' => [self::without($aes128(), 'CF'), 'Unsupported crypt filter method none'];
        yield 'key length' => [$aes128()->set('CF', new PdfDictionaryNode([['StdCF', new PdfDictionaryNode([['CFM', new PdfRawNode('/V2')]])]]))->set('Length', new PdfRawNode('256')), 'Malformed encryption key length'];
    }

    #[DataProvider('unsupported')]
    public function test_rejects_unsupported_or_malformed_encryption(PdfDictionaryNode $encrypt, string $message): void
    {
        $this->expectException(ProtectionProcessException::class);
        $this->expectExceptionMessage($message);

        OpenedStandardSecurityHandler::open($encrypt, self::ID, '');
    }

    public function test_rejects_a_wrong_password(): void
    {
        $this->expectExceptionMessage('The password does not open this encrypted PDF.');

        OpenedStandardSecurityHandler::open((new Aes256StandardSecurityHandler('user', 'owner', -4, true))->encryptionDictionary(), self::ID, 'other');
    }

    private static function without(PdfDictionaryNode $dictionary, string $key): PdfDictionaryNode
    {
        return new PdfDictionaryNode(array_values(array_filter($dictionary->entries(), static fn (array $entry): bool => $entry[0] !== $key)));
    }
}
