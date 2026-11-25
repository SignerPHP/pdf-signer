<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Tests\Unit;

use PHPUnit\Framework\TestCase;
use SignerPHP\PdfSigner\Infrastructure\Native\Contract\ProcessRunnerInterface;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\Cms\Asn1Node;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\Cms\Der;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\Cms\DetachedCmsAssembler;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\LocalPrivateKeySignatureProvider;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\OpenSslTimestampTokenVerifier;
use SignerPHP\PdfSigner\Infrastructure\Native\ValueObject\ProcessResult;
use SignerPHP\PdfSigner\Infrastructure\Native\ValueObject\SignatureCryptoVerification;
use SignerPHP\PdfSigner\Tests\Support\CmsTestFactory;
use SignerPHP\PdfSigner\Tests\Support\Pkcs12Fixture;

/**
 * Uses real RFC 3161 tokens issued by a throwaway TSA through `openssl ts -reply`.
 */
final class OpenSslTimestampTokenVerifierTest extends TestCase
{
    private const CONTENT = "%PDF-1.7 bytes covered by the document timestamp ByteRange\n";

    private static string $dir;

    public static function setUpBeforeClass(): void
    {
        self::$dir = sys_get_temp_dir().'/rfc3161-test-'.bin2hex(random_bytes(4));
        mkdir(self::$dir);
        $d = escapeshellarg(self::$dir);

        file_put_contents(self::$dir.'/ext.cnf', implode("\n", [
            '[req]', 'distinguished_name = dn', 'prompt = no', '[dn]', 'CN = TSA Test',
            '[v3_ca]', 'basicConstraints = critical, CA:TRUE', 'keyUsage = critical, keyCertSign',
            '[v3_tsa]', 'basicConstraints = critical, CA:FALSE', 'keyUsage = critical, digitalSignature', 'extendedKeyUsage = critical, timeStamping', '',
        ]));
        file_put_contents(self::$dir.'/tsa.cnf', implode("\n", [
            '[tsa]', 'default_tsa = t', '[t]',
            'serial = '.self::$dir.'/serial', 'crypto_device = builtin',
            'signer_cert = '.self::$dir.'/tsa.crt', 'signer_key = '.self::$dir.'/tsa.key', 'certs = '.self::$dir.'/ca.crt',
            'signer_digest = sha256', 'default_policy = 1.2.3.4.1', 'digests = sha256, sha512', 'ess_cert_id_alg = sha256', '',
        ]));
        file_put_contents(self::$dir.'/serial', "01\n");
        file_put_contents(self::$dir.'/content.bin', self::CONTENT);

        self::shell(<<<SH
            cd $d
            openssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.crt -days 2 -subj /CN=TSA-Test-CA -config ext.cnf -extensions v3_ca
            openssl req -new -newkey rsa:2048 -nodes -keyout tsa.key -out tsa.csr -subj /CN=TSA-Test -config ext.cnf
            openssl x509 -req -in tsa.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out tsa.crt -days 2 -extfile ext.cnf -extensions v3_tsa
            openssl ts -query -data content.bin -sha256 -cert -out sha256.tsq
            openssl ts -reply -config tsa.cnf -queryfile sha256.tsq -token_out -out sha256.tst
            openssl ts -query -data content.bin -sha512 -cert -out sha512.tsq
            openssl ts -reply -config tsa.cnf -queryfile sha512.tsq -token_out -out sha512.tst
            openssl cms -verify -binary -inform DER -in sha256.tst -noverify -out sha256.tstinfo
            SH);
    }

    public static function tearDownAfterClass(): void
    {
        self::shell('rm -rf '.escapeshellarg(self::$dir));
    }

    public function test_accepts_a_real_token_over_the_byte_range(): void
    {
        foreach (['sha256', 'sha512'] as $algorithm) {
            $result = (new OpenSslTimestampTokenVerifier)->verify(self::CONTENT, $this->contentsHex($algorithm.'.tst'));

            self::assertTrue($result->valid, $algorithm.': '.($result->message ?? ''));
        }
    }

    public function test_rejects_a_token_whose_imprint_does_not_match_the_byte_range(): void
    {
        $result = (new OpenSslTimestampTokenVerifier)->verify(self::CONTENT.'tampered', $this->contentsHex('sha256.tst'));

        self::assertFalse($result->valid);
        self::assertSame('Timestamp message imprint does not match the signed ByteRange.', $result->message);
    }

    public function test_rejects_a_token_with_a_broken_signature(): void
    {
        $token = (string) file_get_contents(self::$dir.'/sha256.tst');
        // Flip one byte of the TSA signature value, which sits at the end of the SignerInfo.
        $token[strlen($token) - 10] = chr(ord($token[strlen($token) - 10]) ^ 0xFF);

        $result = (new OpenSslTimestampTokenVerifier)->verify(self::CONTENT, str_pad(bin2hex($token), 2 * strlen($token) + 64, '0'));

        self::assertFalse($result->valid);
        self::assertStringStartsWith('Timestamp token signature is invalid', (string) $result->message);
    }

    public function test_rejects_a_regular_cms_signature(): void
    {
        $bundle = Pkcs12Fixture::load();
        $cms = (new DetachedCmsAssembler)->assemble(self::CONTENT, $bundle['cert'], new LocalPrivateKeySignatureProvider($bundle['pkey']));

        $result = (new OpenSslTimestampTokenVerifier)->verify(self::CONTENT, bin2hex($cms));

        self::assertFalse($result->valid);
        self::assertSame('Document timestamp does not encapsulate an RFC 3161 TSTInfo.', $result->message);
    }

    public function test_rejects_empty_or_malformed_contents(): void
    {
        $verifier = new OpenSslTimestampTokenVerifier;

        self::assertFalse($verifier->verify(self::CONTENT, str_repeat('0', 64))->valid);
        self::assertFalse($verifier->verify(self::CONTENT, 'not-hex')->valid);
        self::assertFalse($verifier->verify(self::CONTENT, '3003020101'.str_repeat('0', 22))->valid);
    }

    public function test_rejects_a_signer_certificate_without_the_time_stamping_usage(): void
    {
        // The CA certificate has no timeStamping EKU; `openssl ts -reply` would refuse to sign with it.
        $result = $this->verifyWithOpenSslOutput((string) file_get_contents(self::$dir.'/sha256.tstinfo'), 'ca.crt');

        self::assertFalse($result->valid);
        self::assertSame('Timestamp signer certificate does not satisfy the RFC 3161 timeStamping purpose.', $result->message);
    }

    public function test_rejects_a_malformed_tst_info(): void
    {
        $result = $this->verifyWithOpenSslOutput("\x30\x03\x02\x01\x01", 'tsa.crt');

        self::assertFalse($result->valid);
        self::assertSame('Timestamp token has a malformed TSTInfo.', $result->message);
    }

    public function test_rejects_an_imprint_with_an_unsupported_hash_algorithm(): void
    {
        $sha256 = "\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01";
        $tstInfo = (string) file_get_contents(self::$dir.'/sha256.tstinfo');
        self::assertStringContainsString($sha256, $tstInfo);

        $result = $this->verifyWithOpenSslOutput(str_replace($sha256, substr($sha256, 0, -1)."\x7F", $tstInfo), 'tsa.crt');

        self::assertFalse($result->valid);
        self::assertSame('Timestamp message imprint uses an unsupported hash algorithm.', $result->message);
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

        self::assertTrue((new OpenSslTimestampTokenVerifier($runner))->verify(self::CONTENT, $this->contentsHex('sha256.tst'))->valid);
    }

    /**
     * Signs $tstInfo as a real TimeStampToken: an attached CMS without signed attributes, so its
     * encapsulated content type can be set to id-ct-TSTInfo without invalidating the signature.
     */
    private function verifyWithOpenSslOutput(string $tstInfo, string $signerCertificate): SignatureCryptoVerification
    {
        $name = basename($signerCertificate, '.crt');
        $cms = CmsTestFactory::sign($tstInfo, attached: true, identity: [
            'cert' => (string) file_get_contents(self::$dir.'/'.$name.'.crt'),
            'key' => (string) file_get_contents(self::$dir.'/'.$name.'.key'),
        ], flags: OPENSSL_CMS_NOATTR);
        $token = CmsTestFactory::mapSignedDataFields($cms, static function (array $fields): array {
            $eContent = Asn1Node::read($fields[2])->child(1)->encoded;
            $fields[2] = Der::sequence(Der::objectIdentifier('1.2.840.113549.1.9.16.1.4').$eContent);

            return $fields;
        });

        return (new OpenSslTimestampTokenVerifier)->verify(self::CONTENT, str_pad(bin2hex($token), 2 * strlen($token) + 64, '0'));
    }

    private function contentsHex(string $file): string
    {
        $token = (string) file_get_contents(self::$dir.'/'.$file);

        // /Contents is zero-padded after the token, as in a signed PDF.
        return str_pad(strtoupper(bin2hex($token)), 2 * strlen($token) + 256, '0');
    }

    private static function shell(string $script): void
    {
        exec('set -e; '.$script.' 2>&1', $output, $exitCode);
        if ($exitCode !== 0) {
            self::fail(implode("\n", $output));
        }
    }
}
