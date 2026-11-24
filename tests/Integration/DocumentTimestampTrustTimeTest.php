<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Tests\Integration;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SignerPHP\PdfSigner\Application\DTO\PdfContentDto;
use SignerPHP\PdfSigner\Application\DTO\SignatureValidationEntryDto;
use SignerPHP\PdfSigner\Application\DTO\SignatureValidationOptionsDto;
use SignerPHP\PdfSigner\Application\DTO\ValidatePdfRequestDto;
use SignerPHP\PdfSigner\Infrastructure\Native\Contract\PdfSignatureExtractorInterface;
use SignerPHP\PdfSigner\Infrastructure\Native\NativePdfSignatureValidationEngine;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\Cms\Der;
use SignerPHP\PdfSigner\Infrastructure\Native\ValueObject\ExtractedPdfSignature;

/**
 * Document timestamps validated end to end with the real OpenSSL verifiers: the TSA chain must
 * be judged at the token's genTime, not today. Tokens are built here (TSTInfo with a chosen
 * genTime, signed with `openssl cms -sign -econtent_type id-ct-TSTInfo`) because `openssl ts`
 * always stamps the current time. Certificates use `openssl ca -startdate/-enddate`, available
 * in OpenSSL 3.0.
 */
final class DocumentTimestampTrustTimeTest extends TestCase
{
    private const CONTENT = "%PDF-1.7 bytes covered by the document timestamp ByteRange\n";

    private static string $dir;

    public static function setUpBeforeClass(): void
    {
        self::$dir = sys_get_temp_dir().'/doc-ts-trust-'.bin2hex(random_bytes(4));
        mkdir(self::$dir.'/newcerts', 0777, true);
        touch(self::$dir.'/index.txt');
        file_put_contents(self::$dir.'/serial', "1000\n");
        file_put_contents(self::$dir.'/ca.cnf', implode("\n", [
            '[req]', 'distinguished_name = dn', 'prompt = no', '[dn]', 'CN = Timestamp Trust Test CA',
            '[ca]', 'default_ca = test_ca',
            '[test_ca]', 'dir = '.self::$dir, 'database = $dir/index.txt', 'new_certs_dir = $dir/newcerts',
            'serial = $dir/serial', 'default_md = sha256', 'policy = any', 'unique_subject = no',
            '[any]', 'commonName = supplied',
            '[v3_ca]', 'basicConstraints = critical, CA:TRUE', 'keyUsage = critical, keyCertSign, cRLSign',
            '[v3_tsa]', 'basicConstraints = critical, CA:FALSE', 'keyUsage = critical, digitalSignature',
            'extendedKeyUsage = critical, timeStamping',
            '[v3_tsa_noncritical]', 'basicConstraints = critical, CA:FALSE', 'keyUsage = critical, digitalSignature',
            'extendedKeyUsage = timeStamping',
            '[v3_tsa_multiple]', 'basicConstraints = critical, CA:FALSE', 'keyUsage = critical, digitalSignature',
            'extendedKeyUsage = critical, timeStamping, codeSigning', '',
        ]));

        $d = escapeshellarg(self::$dir);
        self::shell(<<<SH
            cd $d
            openssl req -new -newkey rsa:2048 -nodes -keyout ca.key -out ca.csr -config ca.cnf
            openssl ca -batch -selfsign -config ca.cnf -keyfile ca.key -in ca.csr -out ca.crt -extensions v3_ca -startdate 20150101000000Z -enddate 20450101000000Z -notext
            SH);

        // Expired today, valid during 2020.
        self::issueTsa('tsa-2020', '20200101000000Z', '20210101000000Z');
        // Not valid before 2040.
        self::issueTsa('tsa-2040', '20400101000000Z', '20410101000000Z');
        self::issueTsa('tsa-noncritical', '20200101000000Z', '20210101000000Z', 'v3_tsa_noncritical');
        self::issueTsa('tsa-multiple', '20200101000000Z', '20210101000000Z', 'v3_tsa_multiple');
    }

    public static function tearDownAfterClass(): void
    {
        self::shell('rm -rf '.escapeshellarg(self::$dir));
    }

    public function test_accepts_a_tsa_certificate_valid_at_gen_time_but_expired_today(): void
    {
        $entry = $this->validate($this->token('tsa-2020', self::CONTENT, '20200615120000Z'));

        self::assertTrue($entry->cryptoValid, (string) $entry->reason);
        self::assertTrue($entry->trustValid, (string) $entry->reason);
        self::assertTrue($entry->valid);
    }

    public function test_rejects_a_tsa_certificate_already_expired_at_gen_time(): void
    {
        $entry = $this->validate($this->token('tsa-2020', self::CONTENT, '20220615120000Z'));

        self::assertTrue($entry->cryptoValid, (string) $entry->reason);
        self::assertFalse($entry->trustValid);
        self::assertFalse($entry->valid);
        self::assertStringContainsString('expired', (string) $entry->reason);
    }

    public function test_rejects_a_tsa_certificate_not_yet_valid_at_gen_time(): void
    {
        $entry = $this->validate($this->token('tsa-2040', self::CONTENT, '20300615120000Z'));

        self::assertTrue($entry->cryptoValid, (string) $entry->reason);
        self::assertFalse($entry->trustValid);
        self::assertFalse($entry->valid);
        self::assertStringContainsString('not yet valid', (string) $entry->reason);
    }

    public function test_rejects_a_token_with_a_missing_or_invalid_gen_time(): void
    {
        foreach (['missing' => null, 'month 13' => '20201315120000Z', 'no zone' => '20200615120000', 'trailing zero fraction' => '20200615120000.50Z'] as $case => $genTime) {
            $entry = $this->validate($this->token('tsa-2020', self::CONTENT, $genTime));

            self::assertFalse($entry->cryptoValid, $case);
            self::assertFalse($entry->valid, $case);
            self::assertSame('Timestamp token has a missing or invalid genTime.', $entry->reason, $case);
        }
    }

    public function test_rejects_a_token_whose_message_imprint_does_not_match(): void
    {
        $entry = $this->validate($this->token('tsa-2020', 'other bytes than the ByteRange', '20200615120000Z'));

        self::assertFalse($entry->cryptoValid);
        self::assertFalse($entry->valid);
        self::assertSame('Timestamp message imprint does not match the signed ByteRange.', $entry->reason);
    }

    #[DataProvider('invalidTimestampCertificatePurposes')]
    public function test_rejects_a_tsa_certificate_without_a_critical_exclusive_timestamping_eku(string $tsa): void
    {
        $entry = $this->validate($this->token($tsa, self::CONTENT, '20200615120000Z'));

        self::assertFalse($entry->cryptoValid);
        self::assertFalse($entry->valid);
    }

    public static function invalidTimestampCertificatePurposes(): array
    {
        return [
            'noncritical EKU' => ['tsa-noncritical'],
            'multiple EKU purposes' => ['tsa-multiple'],
        ];
    }

    public function test_accepts_a_token_whose_der_ends_in_a_zero_byte(): void
    {
        $token = $this->token('tsa-2020', self::CONTENT, '20200615120000Z');

        // Add a CMS unsigned attribute ending in an actual zero byte, not PDF padding.
        // This leaves the signed TSTInfo and its cryptographic signature unchanged.
        [, $contentInfo] = Der::readTlv($token);
        [, , $afterOid] = Der::readTlv($contentInfo);
        [, $explicit] = Der::readTlv($contentInfo, $afterOid);
        [, $signedData] = Der::readTlv($explicit);
        $offset = 0;
        do {
            $signerInfosOffset = $offset;
            [$tag, $value, $offset] = Der::readTlv($signedData, $offset);
        } while ($offset < strlen($signedData));
        self::assertSame(0x31, $tag);
        [, $signerInfo] = Der::readTlv($value);
        $unsignedAttribute = Der::sequence(Der::objectIdentifier('1.2.3.4.5').Der::set(Der::octetString("\0")));
        $signerInfos = Der::set(Der::sequence($signerInfo.Der::contextSpecific(1, $unsignedAttribute)));
        $token = Der::sequence(substr($contentInfo, 0, $afterOid)
            .Der::contextSpecific(0, Der::sequence(substr($signedData, 0, $signerInfosOffset).$signerInfos)));

        self::assertStringEndsWith("\0", $token);
        $entry = $this->validate($token);
        self::assertTrue($entry->cryptoValid, (string) $entry->reason);
        self::assertTrue($entry->trustValid, (string) $entry->reason);
        self::assertTrue($entry->valid);
    }

    private function validate(string $tokenDer): SignatureValidationEntryDto
    {
        $signature = new ExtractedPdfSignature(
            index: 0,
            byteRange: [0, 10, 20, 5],
            signatureHex: str_pad(bin2hex($tokenDer), 2 * strlen($tokenDer) + 128, '0'),
            signedContent: self::CONTENT,
            byteRangeValid: true,
            subFilter: 'ETSI.RFC3161',
        );
        $extractor = new class($signature) implements PdfSignatureExtractorInterface
        {
            public function __construct(private ExtractedPdfSignature $signature) {}

            public function extract(string $pdfContent): array
            {
                return [$this->signature];
            }
        };

        $result = (new NativePdfSignatureValidationEngine($extractor))->validate(new ValidatePdfRequestDto(
            new PdfContentDto('%PDF'),
            new SignatureValidationOptionsDto(checkTrustChain: true, trustStorePath: self::$dir.'/ca.crt'),
        ));

        return $result->entries[0];
    }

    /**
     * TSTInfo { version 1, policy, messageImprint { sha256, hash(content) }, serialNumber, genTime? }
     */
    private function token(string $tsa, string $imprintedContent, ?string $genTime): string
    {
        $tstInfo = Der::sequence(
            Der::tlv(0x02, "\x01")
            .Der::objectIdentifier('1.2.3.4.1')
            .Der::sequence(
                Der::algorithmIdentifier('2.16.840.1.101.3.4.2.1')
                .Der::octetString(hash('sha256', $imprintedContent, true))
            )
            .Der::tlv(0x02, random_bytes(1) & "\x7F")
            .($genTime === null ? '' : Der::tlv(0x18, $genTime))
        );

        $name = bin2hex(random_bytes(4));
        file_put_contents(self::$dir."/$name.tst-info", $tstInfo);
        $d = escapeshellarg(self::$dir);
        self::shell(<<<SH
            cd $d
            openssl cms -sign -binary -nodetach -outform DER -md sha256 -econtent_type 1.2.840.113549.1.9.16.1.4 \
              -signer $tsa.crt -inkey $tsa.key -certfile ca.crt -in $name.tst-info -out $name.token
            SH);

        return (string) file_get_contents(self::$dir."/$name.token");
    }

    private static function issueTsa(string $name, string $notBefore, string $notAfter, string $extensions = 'v3_tsa'): void
    {
        $d = escapeshellarg(self::$dir);
        self::shell(<<<SH
            cd $d
            openssl req -new -newkey rsa:2048 -nodes -keyout $name.key -out $name.csr -subj /CN=$name -config ca.cnf
            openssl ca -batch -config ca.cnf -cert ca.crt -keyfile ca.key -in $name.csr -out $name.crt -extensions $extensions -startdate $notBefore -enddate $notAfter -notext
            SH);
    }

    private static function shell(string $script): void
    {
        exec('set -e; '.$script.' 2>&1', $output, $exitCode);
        if ($exitCode !== 0) {
            self::fail(implode("\n", $output));
        }
    }
}
