<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Tests\Unit;

use PHPUnit\Framework\TestCase;
use SignerPHP\PdfSigner\Infrastructure\Native\Contract\ProcessRunnerInterface;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\OpenSslCmsCertificateCollector;
use SignerPHP\PdfSigner\Infrastructure\Native\ValueObject\ProcessResult;
use SignerPHP\PdfSigner\Tests\Support\CmsTestFactory;

final class OpenSslCmsCertificateCollectorTest extends TestCase
{
    public function test_collect_returns_empty_for_invalid_hex(): void
    {
        $collector = new OpenSslCmsCertificateCollector;

        self::assertSame([], $collector->collectDerCertificates('NOT-HEX'));
    }

    public function test_collect_returns_empty_for_odd_length_hex(): void
    {
        $collector = new OpenSslCmsCertificateCollector;

        self::assertSame([], $collector->collectDerCertificates('A'));
    }

    public function test_collect_returns_empty_for_zero_padded_placeholder(): void
    {
        $collector = new OpenSslCmsCertificateCollector;

        self::assertSame([], $collector->collectDerCertificates(str_repeat('0', 100)));
    }

    public function test_collect_returns_empty_for_a_payload_that_is_not_cms(): void
    {
        self::assertSame([], (new OpenSslCmsCertificateCollector)->collectDerCertificates('41424344'));
    }

    public function test_collect_returns_every_embedded_certificate_in_order(): void
    {
        $cms = CmsTestFactory::fixture('two-signers.der');
        $hex = str_pad(bin2hex($cms), 2 * strlen($cms) + 64, '0');

        $certificates = (new OpenSslCmsCertificateCollector)->collectDerCertificates(" $hex\n");

        self::assertCount(2, $certificates);
        $subjects = array_map(
            static fn (string $der): string => (string) openssl_x509_parse("-----BEGIN CERTIFICATE-----\n".chunk_split(base64_encode($der), 64, "\n")."-----END CERTIFICATE-----\n")['subject']['CN'],
            $certificates,
        );
        sort($subjects);
        self::assertSame(['Fixture-RSA', 'Fixture-RSA-2'], $subjects);
    }

    public function test_collect_returns_empty_when_the_cms_carries_no_certificates(): void
    {
        $cms = CmsTestFactory::sign('content', flags: OPENSSL_CMS_NOCERTS);

        self::assertSame([], (new OpenSslCmsCertificateCollector)->collectDerCertificates(bin2hex($cms)));
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

        self::assertCount(1, (new OpenSslCmsCertificateCollector($runner))->collectDerCertificates(bin2hex(CmsTestFactory::sign('content'))));
    }
}
