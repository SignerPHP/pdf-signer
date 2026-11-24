<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Tests\Integration;

use PHPUnit\Framework\TestCase;
use SignerPHP\PdfSigner\Application\DTO\IcpBrasilPadesPolicy;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\OpenSslCmsCertificateCollector;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\PdfSignatureExtractor;
use SignerPHP\PdfSigner\Presentation\Signer;
use SignerPHP\PdfSigner\Tests\Support\PdfFixtureFactory;

/**
 * A PKCS#12 with root -> intermediate -> signer: the signature must embed the intermediate so a
 * validator that only trusts the root can build the path from the signature alone.
 */
final class CertificateChainInSignatureTest extends TestCase
{
    private static string $dir;

    public static function setUpBeforeClass(): void
    {
        self::$dir = sys_get_temp_dir().'/cms-chain-'.bin2hex(random_bytes(4));
        mkdir(self::$dir);
        file_put_contents(self::$dir.'/ext.cnf', implode("\n", [
            '[req]', 'distinguished_name = dn', '[dn]',
            '[v3_ca]', 'basicConstraints = critical, CA:TRUE', 'keyUsage = critical, keyCertSign, cRLSign',
            'subjectKeyIdentifier = hash', 'authorityKeyIdentifier = keyid',
            '[v3_leaf]', 'basicConstraints = critical, CA:FALSE', 'keyUsage = critical, digitalSignature, nonRepudiation',
            'subjectKeyIdentifier = hash', 'authorityKeyIdentifier = keyid', '',
        ]));

        $d = escapeshellarg(self::$dir);
        exec(<<<SH
            set -e; cd $d
            openssl req -x509 -newkey rsa:2048 -nodes -keyout root.key -out root.crt -days 2 -subj /CN=Chain-Test-Root -config ext.cnf -extensions v3_ca
            openssl req -new -newkey rsa:2048 -nodes -keyout int.key -out int.csr -subj /CN=Chain-Test-Intermediate -config ext.cnf
            openssl x509 -req -in int.csr -CA root.crt -CAkey root.key -CAcreateserial -out int.crt -days 2 -extfile ext.cnf -extensions v3_ca
            openssl req -new -newkey rsa:2048 -nodes -keyout leaf.key -out leaf.csr -subj /CN=Chain-Test-Signer -config ext.cnf
            openssl x509 -req -in leaf.csr -CA int.crt -CAkey int.key -CAcreateserial -out leaf.crt -days 2 -extfile ext.cnf -extensions v3_leaf
            cat int.crt root.crt > chain.pem
            openssl pkcs12 -export -inkey leaf.key -in leaf.crt -certfile chain.pem -passout pass:secret -out signer.pfx
            SH.' 2>&1', $output, $exitCode);
        if ($exitCode !== 0) {
            self::fail(implode("\n", $output));
        }
    }

    public static function tearDownAfterClass(): void
    {
        exec('rm -rf '.escapeshellarg(self::$dir));
    }

    public function test_signature_embeds_the_pkcs12_chain(): void
    {
        self::assertSame(['Chain-Test-Intermediate', 'Chain-Test-Root', 'Chain-Test-Signer'], $this->embeddedSubjects($this->signedPdf()));
    }

    public function test_signature_with_an_icp_brasil_policy_still_embeds_the_chain(): void
    {
        $pdf = Signer::signer()
            ->withPdfContent(PdfFixtureFactory::minimalPdf())
            ->withCertificatePath(self::$dir.'/signer.pfx', 'secret')
            ->withPadesBaselineB()
            ->withSignaturePolicy(IcpBrasilPadesPolicy::AdRbV1_3)
            ->withoutTimestamp()
            ->withoutDefaultAppearance()
            ->sign();

        self::assertSame(['Chain-Test-Intermediate', 'Chain-Test-Root', 'Chain-Test-Signer'], $this->embeddedSubjects($pdf));
    }

    /**
     * @return list<string>
     */
    private function embeddedSubjects(string $pdf): array
    {
        $signature = (new PdfSignatureExtractor)->extract($pdf)[0];
        $subjects = array_map(
            static fn (string $der): string => (string) openssl_x509_parse(
                "-----BEGIN CERTIFICATE-----\n".chunk_split(base64_encode($der), 64, "\n")."-----END CERTIFICATE-----\n"
            )['subject']['CN'],
            (new OpenSslCmsCertificateCollector)->collectDerCertificates($signature->signatureHex),
        );

        sort($subjects);

        return $subjects;
    }

    public function test_validator_trusting_only_the_root_validates_the_chain(): void
    {
        $validation = Signer::validation()
            ->withPdfContent($this->signedPdf())
            ->enableTrustChainValidation(self::$dir.'/root.crt')
            ->validate();

        self::assertTrue($validation->hasSignatures);
        self::assertTrue($validation->entries[0]->cryptoValid, (string) $validation->entries[0]->reason);
        self::assertTrue($validation->entries[0]->trustValid, (string) $validation->entries[0]->reason);
        self::assertTrue($validation->allValid);
    }

    private function signedPdf(): string
    {
        return Signer::signer()
            ->withPdfContent(PdfFixtureFactory::minimalPdf())
            ->withCertificatePath(self::$dir.'/signer.pfx', 'secret')
            ->withPadesBaselineB()
            ->withoutTimestamp()
            ->withoutDefaultAppearance()
            ->sign();
    }
}
