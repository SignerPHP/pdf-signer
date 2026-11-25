<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Tests\Unit;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\Cms\Asn1Node;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\Cms\CmsSignatureVerification;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\Cms\CmsSignatureVerifier;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\Cms\CmsSignedData;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\Cms\Der;
use SignerPHP\PdfSigner\Tests\Support\CmsTestFactory;

final class CmsSignatureVerifierTest extends TestCase
{
    private const CONTENT = "%PDF-1.7 bytes covered by the ByteRange\n";

    private const OID_SHA256 = '0609608648016503040201';

    private const OID_RSASSA_PSS = '06092a864886f70d01010a';

    public function test_verifies_detached_rsa_and_ecdsa_signatures(): void
    {
        foreach (['rsa', 'ec'] as $type) {
            $identity = CmsTestFactory::identity($type);
            $result = $this->verify(CmsTestFactory::sign(self::CONTENT, identity: $identity), self::CONTENT);

            self::assertTrue($result->valid, $type.': '.$result->message);
            self::assertSame(openssl_x509_fingerprint($identity['cert'], 'sha256'), openssl_x509_fingerprint((string) $result->signerCertificatePem(), 'sha256'));
        }
    }

    public function test_verifies_attached_signatures_and_signatures_without_attributes(): void
    {
        self::assertTrue($this->verify(CmsTestFactory::sign(self::CONTENT, attached: true))->valid);
        self::assertTrue($this->verify(CmsTestFactory::sign(self::CONTENT, flags: OPENSSL_CMS_NOATTR), self::CONTENT)->valid);
        self::assertFalse($this->verify(CmsTestFactory::sign(self::CONTENT, flags: OPENSSL_CMS_NOATTR), self::CONTENT.'x')->valid);
    }

    /**
     * @return array<string, array{0:string}>
     */
    public static function fixtures(): array
    {
        return [
            'RSA-PSS SHA-256' => ['rsa-pss.der'],
            'RSA-PSS default parameters' => ['rsa-pss-sha1-defaults.der'],
            'sid as subjectKeyIdentifier' => ['rsa-keyid.der'],
            'BER with indefinite lengths' => ['rsa-ber-stream.der'],
            'two signers' => ['two-signers.der'],
        ];
    }

    #[DataProvider('fixtures')]
    public function test_verifies_openssl_generated_variants(string $fixture): void
    {
        $content = CmsTestFactory::fixture('content.bin');
        $cms = CmsTestFactory::fixture($fixture);

        $result = $this->verify($cms, $content);
        self::assertTrue($result->valid, (string) $result->message);

        self::assertFalse($this->verify($cms, $content.'tampered')->valid);
        self::assertFalse($this->verify($this->flipLastSignatureByte($cms), $content)->valid, 'a modified signature value must not verify');
    }

    public function test_rejects_a_modified_signature_value(): void
    {
        foreach (['rsa', 'ec'] as $type) {
            $cms = CmsTestFactory::sign(self::CONTENT, identity: CmsTestFactory::identity($type));
            $result = $this->verify($this->flipLastSignatureByte($cms), self::CONTENT);

            self::assertFalse($result->valid);
            self::assertSame('CMS signature value does not verify with the signer certificate.', $result->message);
        }
    }

    public function test_rejects_content_that_does_not_match_the_message_digest(): void
    {
        $result = $this->verify(CmsTestFactory::sign(self::CONTENT), 'other bytes');

        self::assertFalse($result->valid);
        self::assertSame('CMS message digest does not match the signed content.', $result->message);
    }

    public function test_requires_content_for_a_detached_signature(): void
    {
        $result = $this->verify(CmsTestFactory::sign(self::CONTENT));

        self::assertFalse($result->valid);
        self::assertSame('CMS signature is detached and no content was supplied.', $result->message);
    }

    public function test_requires_the_signer_certificate(): void
    {
        $result = $this->verify(CmsTestFactory::sign(self::CONTENT, flags: OPENSSL_CMS_NOCERTS), self::CONTENT);

        self::assertFalse($result->valid);
        self::assertSame('Signer certificate not found in the CMS certificates.', $result->message);
    }

    public function test_requires_the_content_type_and_message_digest_attributes(): void
    {
        $cms = CmsTestFactory::sign(self::CONTENT);

        // contentType (1.2.840.113549.1.9.3) -> 1.2.840.113549.1.9.98: the attribute is gone.
        $withoutContentType = CmsTestFactory::replaceOnce($cms, '06092a864886f70d010903', '06092a864886f70d010962');
        self::assertSame('CMS content-type attribute is missing or does not match the encapsulated content type.', $this->verify($withoutContentType, self::CONTENT)->message);

        // messageDigest (1.2.840.113549.1.9.4) -> 1.2.840.113549.1.9.99
        $withoutDigest = CmsTestFactory::replaceOnce($cms, '06092a864886f70d010904', '06092a864886f70d010963');
        self::assertSame('CMS message-digest attribute is missing.', $this->verify($withoutDigest, self::CONTENT)->message);
    }

    public function test_rejects_unsupported_algorithms(): void
    {
        $content = CmsTestFactory::fixture('content.bin');
        self::assertSame('Unsupported CMS signature algorithm 1.3.101.112.', $this->verify(CmsTestFactory::fixture('ed25519.der'), $content)->message);

        // sha256 -> sha3-256 (2.16.840.1.101.3.4.2.8) in both digestAlgorithms and the SignerInfo.
        $cms = str_replace((string) hex2bin(self::OID_SHA256), (string) hex2bin('0609608648016503040208'), CmsTestFactory::sign(self::CONTENT));
        self::assertSame('Unsupported CMS digest algorithm 2.16.840.1.101.3.4.2.8.', $this->verify($cms, self::CONTENT)->message);
    }

    public function test_rejects_unsupported_rsassa_pss_parameters(): void
    {
        $content = CmsTestFactory::fixture('content.bin');
        $cms = CmsTestFactory::fixture('rsa-pss.der');
        $parameters = strrpos($cms, (string) hex2bin(self::OID_RSASSA_PSS));
        self::assertNotFalse($parameters);
        $head = substr($cms, 0, $parameters);
        $tail = substr($cms, $parameters);

        $cases = [
            // MGF1 (1.2.840.113549.1.1.8) -> 1.2.840.113549.1.1.9
            'Unsupported RSASSA-PSS mask generation function.' => ['06092a864886f70d010108', '06092a864886f70d010109'],
            // saltLength [2] INTEGER 32 -> trailerField [3] INTEGER 32
            'Unsupported RSASSA-PSS trailer field.' => ['a203020120', 'a303020120'],
            // saltLength [2] -> [4]
            'Malformed RSASSA-PSS parameters.' => ['a203020120', 'a403020120'],
            // saltLength INTEGER 32 -> INTEGER -32
            'Malformed RSASSA-PSS integer parameter.' => ['a203020120', 'a2030201e0'],
        ];
        foreach ($cases as $message => [$search, $replace]) {
            $mutated = $head.CmsTestFactory::replaceOnce($tail, $search, $replace);
            self::assertSame($message, $this->verify($mutated, $content)->message);
        }

        // hashAlgorithm sha256 -> sha3-256 inside the parameters (the first sha256 after the PSS OID).
        $position = strpos($tail, (string) hex2bin(self::OID_SHA256));
        self::assertNotFalse($position);
        $mutated = $head.substr_replace($tail, (string) hex2bin('0609608648016503040208'), $position, 11);
        self::assertSame('Unsupported RSASSA-PSS hash algorithm.', $this->verify($mutated, $content)->message);
    }

    public function test_rsassa_pss_is_rejected_for_a_non_rsa_key(): void
    {
        // An ECDSA signature relabelled as RSASSA-PSS with default parameters.
        $cms = CmsTestFactory::mapFirstSignerInfoFields(
            CmsTestFactory::sign(self::CONTENT, identity: CmsTestFactory::identity('ec')),
            static function (array $fields): array {
                $fields[4] = Der::sequence(Der::objectIdentifier('1.2.840.113549.1.1.10'));

                return $fields;
            },
        );

        self::assertSame('CMS signature value does not verify with the signer certificate.', $this->verify($cms, self::CONTENT)->message);
    }

    public function test_rsassa_pss_rejects_a_signature_of_the_wrong_length(): void
    {
        $content = CmsTestFactory::fixture('content.bin');
        $cms = CmsTestFactory::mapFirstSignerInfoFields(CmsTestFactory::fixture('rsa-pss.der'), static function (array $fields): array {
            $fields[5] = Der::octetString(substr(Asn1Node::read($fields[5])->content, 1));

            return $fields;
        });

        self::assertSame('CMS signature value does not verify with the signer certificate.', $this->verify($cms, $content)->message);
    }

    public function test_reports_a_signed_data_without_signer_infos(): void
    {
        $cms = CmsTestFactory::mapSignedDataFields(CmsTestFactory::sign(self::CONTENT, attached: true), static function (array $fields): array {
            $fields[count($fields) - 1] = Der::set('');

            return $fields;
        });
        $signedData = CmsSignedData::fromDer($cms);

        self::assertSame([], $signedData->signerInfos);
        self::assertSame('CMS SignedData has no SignerInfo.', (new CmsSignatureVerifier)->verify($signedData)->message);
    }

    public function test_requires_a_public_key_that_openssl_can_read(): void
    {
        // Replace the embedded certificate's public key BIT STRING contents with garbage.
        $cms = CmsTestFactory::mapSignedDataFields(CmsTestFactory::sign(self::CONTENT), static function (array $fields): array {
            $certificate = Asn1Node::read($fields[3])->child(0);
            $tbs = $certificate->child(0);
            $tbsFields = array_map(static fn (Asn1Node $node): string => $node->encoded, $tbs->children());
            $tbsFields[6] = Der::sequence(Der::algorithmIdentifier('1.2.840.113549.1.1.1').Der::tlv(0x03, "\x00\x30\x00"));
            $broken = Der::sequence(Der::sequence(implode('', $tbsFields)).$certificate->child(1)->encoded.$certificate->child(2)->encoded);
            $fields[3] = Der::contextSpecific(0, $broken);

            return $fields;
        });

        self::assertSame('Could not read the signer certificate public key.', $this->verify($cms, self::CONTENT)->message);
    }

    private function verify(string $cms, ?string $content = null): CmsSignatureVerification
    {
        return (new CmsSignatureVerifier)->verify(CmsSignedData::fromDer($cms), $content);
    }

    private function flipLastSignatureByte(string $cms): string
    {
        $signedData = CmsSignedData::fromDer($cms);
        $signature = $signedData->signerInfos[count($signedData->signerInfos) - 1]->signature;
        $position = strrpos($cms, $signature);
        self::assertNotFalse($position);
        $last = $position + strlen($signature) - 1;
        $cms[$last] = chr(ord($cms[$last]) ^ 0x01);

        return $cms;
    }
}
