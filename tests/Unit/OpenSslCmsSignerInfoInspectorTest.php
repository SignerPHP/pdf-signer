<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Tests\Unit;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SignerPHP\PdfSigner\Infrastructure\Native\Contract\ProcessRunnerInterface;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\Cms\Der;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\Inspect\OpenSslCmsSignerInfoInspector;
use SignerPHP\PdfSigner\Infrastructure\Native\ValueObject\ProcessResult;
use SignerPHP\PdfSigner\Tests\Support\CmsTestFactory;

final class OpenSslCmsSignerInfoInspectorTest extends TestCase
{
    private const EMPTY = [
        'digest_algorithm' => null,
        'signature_algorithm' => null,
        'cms_signing_time' => null,
    ];

    public function test_inspect_returns_empty_for_unusable_payloads(): void
    {
        $inspector = new OpenSslCmsSignerInfoInspector;

        self::assertSame(self::EMPTY, $inspector->inspect(''));
        self::assertSame(self::EMPTY, $inspector->inspect('0000'));
        self::assertSame(self::EMPTY, $inspector->inspect('XYZ'));
        self::assertSame(self::EMPTY, $inspector->inspect('41424344'));
    }

    public function test_inspect_returns_empty_when_the_signed_data_has_no_signer_info(): void
    {
        $cms = CmsTestFactory::mapSignedDataFields(CmsTestFactory::sign('content'), static function (array $fields): array {
            $fields[count($fields) - 1] = Der::set('');

            return $fields;
        });

        self::assertSame(self::EMPTY, (new OpenSslCmsSignerInfoInspector)->inspect(bin2hex($cms)));
    }

    public function test_inspect_reads_a_real_signature_with_whitespace_and_padding(): void
    {
        $hex = chunk_split(bin2hex(CmsTestFactory::sign('content')), 64, "\n").str_repeat('00', 32);

        $result = (new OpenSslCmsSignerInfoInspector)->inspect($hex);

        self::assertSame('sha256', $result['digest_algorithm']);
        self::assertSame('rsaEncryption', $result['signature_algorithm']);
        self::assertMatchesRegularExpression('/\A[A-Z][a-z]{2} [ \d]\d \d{2}:\d{2}:\d{2} \d{4} GMT\z/', (string) $result['cms_signing_time']);
    }

    /**
     * @return array<string, array{0:string, 1:string, 2:string}>
     */
    public static function algorithms(): array
    {
        return [
            'RSA-PSS' => ['rsa-pss.der', 'sha256', 'rsassaPss'],
            'Ed25519 (unnamed)' => ['ed25519.der', 'sha512', '1.3.101.112'],
        ];
    }

    #[DataProvider('algorithms')]
    public function test_inspect_names_algorithms_like_openssl(string $fixture, string $digest, string $signature): void
    {
        $result = (new OpenSslCmsSignerInfoInspector)->inspect(bin2hex(CmsTestFactory::fixture($fixture)));

        self::assertSame($digest, $result['digest_algorithm']);
        self::assertSame($signature, $result['signature_algorithm']);
    }

    public function test_inspect_names_ecdsa_signatures(): void
    {
        $result = (new OpenSslCmsSignerInfoInspector)->inspect(bin2hex(CmsTestFactory::sign('content', identity: CmsTestFactory::identity('ec'))));

        self::assertSame('sha256', $result['digest_algorithm']);
        self::assertSame('ecdsa-with-SHA256', $result['signature_algorithm']);
    }

    /**
     * @return array<string, array{0:int, 1:string, 2:string|null}>
     */
    public static function signingTimes(): array
    {
        return [
            'UTCTime' => [0x17, '260506185601Z', 'May  6 18:56:01 2026 GMT'],
            'UTCTime before 2000' => [0x17, '991231235959Z', 'Dec 31 23:59:59 1999 GMT'],
            'GeneralizedTime with fraction' => [0x18, '20261124093005.25Z', 'Nov 24 09:30:05.25 2026 GMT'],
            'invalid month' => [0x17, '261306185601Z', null],
            'malformed time' => [0x17, '2605Z', null],
            'not a time type' => [0x0C, '260506185601Z', null],
        ];
    }

    #[DataProvider('signingTimes')]
    public function test_inspect_formats_the_signing_time_like_openssl(int $tag, string $time, ?string $expected): void
    {
        $attributes = Der::contextSpecific(0, Der::sequence(Der::objectIdentifier('1.2.840.113549.1.9.5').Der::set(Der::tlv($tag, $time))));
        $cms = CmsTestFactory::mapFirstSignerInfoFields(CmsTestFactory::sign('content'), static function (array $fields) use ($attributes): array {
            $fields[3] = $attributes;

            return $fields;
        });

        self::assertSame($expected, (new OpenSslCmsSignerInfoInspector)->inspect(bin2hex($cms))['cms_signing_time']);
    }

    public function test_a_process_runner_is_still_accepted_and_never_used(): void
    {
        $runner = new class implements ProcessRunnerInterface
        {
            public function run(string $command): ProcessResult
            {
                throw new \LogicException('No external process may run.');
            }
        };

        self::assertSame('sha256', (new OpenSslCmsSignerInfoInspector($runner))->inspect(bin2hex(CmsTestFactory::sign('content')))['digest_algorithm']);
    }
}
