<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Tests\Unit;

use PHPUnit\Framework\TestCase;
use SignerPHP\PdfSigner\Infrastructure\Native\Contract\ProcessRunnerInterface;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\Inspect\OpenSslCmsSignerInfoInspector;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\NativeFunctionOverrideState;
use SignerPHP\PdfSigner\Infrastructure\Native\ValueObject\ProcessResult;

final class OpenSslCmsSignerInfoInspectorTest extends TestCase
{
    protected function tearDown(): void
    {
        NativeFunctionOverrideState::$forceTempnamFailure = false;
    }

    public function test_inspect_returns_empty_for_invalid_or_placeholder_hex(): void
    {
        $inspector = new OpenSslCmsSignerInfoInspector;

        self::assertSame([
            'digest_algorithm' => null,
            'signature_algorithm' => null,
            'cms_signing_time' => null,
        ], $inspector->inspect(''));

        self::assertSame([
            'digest_algorithm' => null,
            'signature_algorithm' => null,
            'cms_signing_time' => null,
        ], $inspector->inspect(str_repeat('0', 20)));

        self::assertSame([
            'digest_algorithm' => null,
            'signature_algorithm' => null,
            'cms_signing_time' => null,
        ], $inspector->inspect('XYZ'));
    }

    public function test_inspect_returns_empty_when_process_fails_or_output_has_no_signer_infos(): void
    {
        $failing = new OpenSslCmsSignerInfoInspector(new class implements ProcessRunnerInterface
        {
            public function run(string $command): ProcessResult
            {
                return new ProcessResult(1, ['boom']);
            }
        });

        self::assertSame([
            'digest_algorithm' => null,
            'signature_algorithm' => null,
            'cms_signing_time' => null,
        ], $failing->inspect('41424344'));

        $missingSignerInfos = new OpenSslCmsSignerInfoInspector(new class implements ProcessRunnerInterface
        {
            public function run(string $command): ProcessResult
            {
                return new ProcessResult(0, ['CMS_ContentInfo:', '  contentType: pkcs7-signedData']);
            }
        });

        self::assertSame([
            'digest_algorithm' => null,
            'signature_algorithm' => null,
            'cms_signing_time' => null,
        ], $missingSignerInfos->inspect('41424344'));
    }

    public function test_inspect_extracts_signer_info_fields_from_openssl_output(): void
    {
        $inspector = new OpenSslCmsSignerInfoInspector(new class implements ProcessRunnerInterface
        {
            public function run(string $command): ProcessResult
            {
                return new ProcessResult(0, [
                    'CMS_ContentInfo:',
                    '  signerInfos:',
                    '      version: 1',
                    '      digestAlgorithm: ',
                    '        algorithm: sha256 (2.16.840.1.101.3.4.2.1)',
                    '      signedAttrs:',
                    '            object: signingTime (1.2.840.113549.1.9.5)',
                    '            set:',
                    '              UTCTIME:May  6 18:56:01 2026 GMT',
                    '      signatureAlgorithm: ',
                    '        algorithm: rsaEncryption (1.2.840.113549.1.1.1)',
                ]);
            }
        });

        self::assertSame([
            'digest_algorithm' => 'sha256',
            'signature_algorithm' => 'rsaEncryption',
            'cms_signing_time' => 'May  6 18:56:01 2026 GMT',
        ], $inspector->inspect('41424344'));
    }

    public function test_inspect_accepts_whitespace_and_zero_padding_in_hex_payload(): void
    {
        $inspector = new OpenSslCmsSignerInfoInspector(new class implements ProcessRunnerInterface
        {
            public function run(string $command): ProcessResult
            {
                return new ProcessResult(0, [
                    'CMS_ContentInfo:',
                    '  signerInfos:',
                    '      digestAlgorithm: ',
                    '        algorithm: sha512 (2.16.840.1.101.3.4.2.3)',
                    '      signatureAlgorithm: ',
                    '        algorithm: rsaEncryption (1.2.840.113549.1.1.1)',
                ]);
            }
        });

        $result = $inspector->inspect('41 42 43 44 00 00');

        self::assertSame('sha512', $result['digest_algorithm']);
        self::assertSame('rsaEncryption', $result['signature_algorithm']);
        self::assertNull($result['cms_signing_time']);
    }

    public function test_inspect_returns_empty_when_temp_file_cannot_be_allocated(): void
    {
        NativeFunctionOverrideState::$forceTempnamFailure = true;

        $inspector = new OpenSslCmsSignerInfoInspector(new class implements ProcessRunnerInterface
        {
            public function run(string $command): ProcessResult
            {
                return new ProcessResult(0, ['unexpected']);
            }
        });

        self::assertSame([
            'digest_algorithm' => null,
            'signature_algorithm' => null,
            'cms_signing_time' => null,
        ], $inspector->inspect('41424344'));
    }
}
