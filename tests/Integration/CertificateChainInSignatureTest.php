<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Tests\Integration;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SignerPHP\PdfCore\Buffer;
use SignerPHP\PdfSigner\Application\DTO\IcpBrasilPadesPolicy;
use SignerPHP\PdfSigner\Application\DTO\SignatureProfile;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\Cms\DetachedCmsAssembler;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\Cms\X509Certificate;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\LocalPrivateKeySignatureProvider;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\OpenSslCmsCertificateCollector;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\PdfSignatureExtractor;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\Pkcs7Signer;
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
            openssl pkcs12 -export -inkey leaf.key -in leaf.crt -certfile int.crt -passout pass:secret -out intermediate-only.pfx
            openssl pkcs12 -export -inkey leaf.key -in leaf.crt -certfile root.crt -passout pass:secret -out missing-intermediate.pfx
            openssl req -x509 -newkey rsa:2048 -nodes -keyout unrelated.key -out unrelated.crt -days 2 -subj /CN=Unrelated-Root -config ext.cnf -extensions v3_ca
            SH.' 2>&1', $output, $exitCode);
        if ($exitCode !== 0) {
            self::fail(implode("\n", $output));
        }
    }

    public static function tearDownAfterClass(): void
    {
        exec('rm -rf '.escapeshellarg(self::$dir));
    }

    #[DataProvider('localSigningProfiles')]
    public function test_signature_embeds_the_pkcs12_chain(bool $pades): void
    {
        self::assertSame(['Chain-Test-Intermediate', 'Chain-Test-Root', 'Chain-Test-Signer'], $this->embeddedSubjects($this->signedPdf(pades: $pades)));
    }

    public static function localSigningProfiles(): array
    {
        return [
            'PDF basic' => [false],
            'PAdES baseline B' => [true],
        ];
    }

    public function test_assembler_accepts_pem_bundles_and_deduplicates_the_same_der(): void
    {
        $leaf = (string) file_get_contents(self::$dir.'/leaf.crt');
        $key = (string) file_get_contents(self::$dir.'/leaf.key');
        $intermediate = (string) file_get_contents(self::$dir.'/int.crt');
        $root = (string) file_get_contents(self::$dir.'/root.crt');
        $chain = [" \n", $root.$intermediate, str_replace("\n", "\r\n", $intermediate), X509Certificate::fromPem($root)->der, $leaf];
        $cms = (new DetachedCmsAssembler)->assemble(
            'payload', $leaf, new LocalPrivateKeySignatureProvider($key),
            certificateChainPem: $chain, profile: SignatureProfile::PadesBaselineB,
        );

        $localHex = (new Pkcs7Signer)->signWithChain(
            new Buffer('payload'), new LocalPrivateKeySignatureProvider($key), $leaf,
            SignatureProfile::PadesBaselineB, $chain,
        );

        file_put_contents(self::$dir.'/payload.dat', 'payload');
        file_put_contents(self::$dir.'/chain-test.der', $cms);
        $d = escapeshellarg(self::$dir);
        exec("cd $d && openssl cms -verify -binary -inform DER -in chain-test.der -content payload.dat -CAfile root.crt -purpose any -out /dev/null 2>&1", $output, $exitCode);
        self::assertSame(0, $exitCode, implode("\n", $output));

        foreach ([bin2hex($cms), $localHex] as $hex) {
            $certificates = (new OpenSslCmsCertificateCollector)->collectDerCertificates($hex);
            self::assertCount(3, $certificates);
            foreach ([$leaf, $intermediate, $root] as $pem) {
                self::assertContains(X509Certificate::fromPem($pem)->der, $certificates);
            }
        }
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

    #[DataProvider('trustScenarios')]
    public function test_validation_uses_the_configured_trust_anchor(string $pfx, string $trustStore, bool $trusted): void
    {
        $pdf = $this->signedPdf($pfx);
        $validation = Signer::validation()
            ->withPdfContent($pdf)
            ->enableTrustChainValidation(self::$dir.'/'.$trustStore)
            ->validate();

        self::assertTrue($validation->hasSignatures);
        self::assertTrue($validation->entries[0]->cryptoValid, (string) $validation->entries[0]->reason);
        self::assertSame($trusted, $validation->entries[0]->trustValid, (string) $validation->entries[0]->reason);
        self::assertSame($trusted, $validation->allValid);
    }

    /** @return array<string, array{string, string, bool}> */
    public static function trustScenarios(): array
    {
        return [
            'complete chain, unrelated root' => ['signer.pfx', 'unrelated.crt', false],
            'root need not be embedded' => ['intermediate-only.pfx', 'root.crt', true],
            'embedded root without intermediate' => ['missing-intermediate.pfx', 'root.crt', false],
        ];
    }

    private function signedPdf(string $pfx = 'signer.pfx', bool $pades = true): string
    {
        $signer = Signer::signer()
            ->withPdfContent(PdfFixtureFactory::minimalPdf())
            ->withCertificatePath(self::$dir.'/'.$pfx, 'secret')
            ->withoutTimestamp()
            ->withoutDefaultAppearance();
        if ($pades) {
            $signer->withPadesBaselineB();
        }

        return $signer->sign();
    }
}
