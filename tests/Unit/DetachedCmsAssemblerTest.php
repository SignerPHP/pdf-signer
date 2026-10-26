<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Tests\Unit;

use PHPUnit\Framework\TestCase;
use SignerPHP\PdfSigner\Application\Contract\SignatureProviderInterface;
use SignerPHP\PdfSigner\Application\DTO\HashAlgorithm;
use SignerPHP\PdfSigner\Application\DTO\SignatureAlgorithm;
use SignerPHP\PdfSigner\Application\DTO\SignatureProfile;
use SignerPHP\PdfSigner\Application\DTO\SignatureValue;
use SignerPHP\PdfSigner\Application\DTO\SigningPayload;
use SignerPHP\PdfSigner\Domain\Exception\SignProcessException;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\Cms\Der;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\Cms\DetachedCmsAssembler;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\Cms\PreparedDetachedCms;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\Cms\X509Certificate;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\LocalPrivateKeySignatureProvider;
use SignerPHP\PdfSigner\Tests\Support\Pkcs12Fixture;

final class DetachedCmsAssemblerTest extends TestCase
{
    public function test_sha256_oid_matches_known_der(): void
    {
        self::assertSame('0609608648016503040201', bin2hex(Der::objectIdentifier([2, 16, 840, 1, 101, 3, 4, 2, 1])));
    }

    public function test_assemble_produces_cms_that_openssl_verifies(): void
    {
        $bundle = Pkcs12Fixture::load();
        $payload = "%PDF-1.4\n1 0 obj<<>>endobj\nstartxref\n0\n%%EOF\n";
        $provider = new LocalPrivateKeySignatureProvider($bundle['pkey']);

        $cms = (new DetachedCmsAssembler)->assemble(
            $payload,
            $bundle['cert'],
            $provider,
            signingTime: new \DateTimeImmutable('2024-01-02 03:04:05 UTC'),
        );

        self::assertNotSame('', $cms);
        self::assertTrue(Pkcs12Fixture::cmsVerifies($cms, $payload), 'Detached CMS must verify against the signed PDF bytes.');
    }

    public function test_pades_baseline_has_ess_certificate_reference_without_cms_signing_time(): void
    {
        $rsa = Pkcs12Fixture::load();
        foreach ([SignatureProfile::PadesBaselineB, SignatureProfile::PadesBaselineT, SignatureProfile::PadesBaselineLT, SignatureProfile::PadesBaselineLTA] as $profile) {
            foreach ([$rsa, $this->selfSignedEc()] as $bundle) {
                $provider = new LocalPrivateKeySignatureProvider($bundle['pkey']);
                foreach ([HashAlgorithm::Sha1, HashAlgorithm::Sha224, HashAlgorithm::Sha256, HashAlgorithm::Sha384, HashAlgorithm::Sha512] as $algorithm) {
                    $assembler = new DetachedCmsAssembler;
                    $prepared = $assembler->prepare('payload', $bundle['cert'], $algorithm, profile: $profile);
                    $certificate = X509Certificate::fromPem($bundle['cert']);
                    $v2 = $algorithm !== HashAlgorithm::Sha1;
                    $oid = Der::objectIdentifier($v2 ? '1.2.840.113549.1.9.16.2.47' : '1.2.840.113549.1.9.16.2.12');
                    self::assertStringContainsString($oid, $prepared->signedAttributes);
                    self::assertStringContainsString(hash($algorithm->value, $certificate->der, true), $prepared->signedAttributes);
                    self::assertStringNotContainsString(Der::objectIdentifier('1.2.840.113549.1.9.5'), $prepared->signedAttributes);
                    self::assertStringContainsString(Der::objectIdentifier('1.2.840.113549.1.9.3'), $prepared->signedAttributes);
                    self::assertStringContainsString(Der::objectIdentifier('1.2.840.113549.1.9.4'), $prepared->signedAttributes);
                    $cms = $assembler->complete($prepared, $provider->sign(new SigningPayload($prepared->signedAttributes, $algorithm)));
                    self::assertTrue(Pkcs12Fixture::cmsVerifies($cms, 'payload'));
                }
            }
        }
    }

    public function test_openssl_independently_decodes_pades_signed_attributes(): void
    {
        $bundle = Pkcs12Fixture::load();
        $provider = new LocalPrivateKeySignatureProvider($bundle['pkey']);
        $cms = (new DetachedCmsAssembler)->assemble('payload', $bundle['cert'], $provider, profile: SignatureProfile::PadesBaselineB);
        $filename = tempnam(sys_get_temp_dir(), 'pades-cms-');
        self::assertNotFalse($filename);
        try {
            file_put_contents($filename, $cms);
            $output = [];
            $exitCode = -1;
            exec('openssl cms -inform DER -in '.escapeshellarg($filename).' -cmsout -print 2>&1', $output, $exitCode);
            self::assertSame(0, $exitCode, implode("\n", $output));
            $decoded = implode("\n", $output);
            self::assertStringContainsString('id-smime-aa-signingCertificateV2', $decoded);
            self::assertStringNotContainsString('object: signingTime', $decoded);
            self::assertStringContainsString('object: contentType', $decoded);
            self::assertStringContainsString('object: messageDigest', $decoded);
        } finally {
            unlink($filename);
        }
    }

    public function test_basic_profile_preserves_cms_signing_time(): void
    {
        $certificate = Pkcs12Fixture::load()['cert'];
        $attributes = (new DetachedCmsAssembler)->prepare('payload', $certificate)->signedAttributes;
        self::assertStringContainsString(Der::objectIdentifier('1.2.840.113549.1.9.5'), $attributes);
        self::assertStringNotContainsString(Der::objectIdentifier('1.2.840.113549.1.9.16.2.47'), $attributes);
    }

    public function test_assemble_throws_when_provider_returns_empty_signature(): void
    {
        $bundle = Pkcs12Fixture::load();
        $provider = new class implements SignatureProviderInterface
        {
            public function sign(SigningPayload $payload): SignatureValue
            {
                return new SignatureValue('');
            }
        };

        $this->expectException(SignProcessException::class);
        $this->expectExceptionMessage('Signature provider returned an empty signature.');

        (new DetachedCmsAssembler)->assemble('payload', $bundle['cert'], $provider);
    }

    public function test_assemble_supports_all_rsa_hash_algorithms(): void
    {
        $bundle = Pkcs12Fixture::load();
        $provider = new LocalPrivateKeySignatureProvider($bundle['pkey']);

        foreach (HashAlgorithm::cases() as $algorithm) {
            $cms = (new DetachedCmsAssembler)->assemble('payload', $bundle['cert'], $provider, $algorithm);

            self::assertNotSame('', $cms);
        }
    }

    public function test_assemble_supports_all_ec_hash_algorithms(): void
    {
        $bundle = $this->selfSignedEc();
        $provider = new LocalPrivateKeySignatureProvider($bundle['pkey']);

        foreach (HashAlgorithm::cases() as $algorithm) {
            $cms = (new DetachedCmsAssembler)->assemble('payload', $bundle['cert'], $provider, $algorithm);

            self::assertNotSame('', $cms);
        }
    }

    public function test_ecdsa_algorithm_identifier_omits_null_parameters(): void
    {
        $bundle = $this->selfSignedEc();
        $provider = new LocalPrivateKeySignatureProvider($bundle['pkey']);
        $cms = (new DetachedCmsAssembler)->assemble('payload', $bundle['cert'], $provider);
        $oid = Der::objectIdentifier('1.2.840.10045.4.3.2');

        self::assertStringContainsString(Der::sequence($oid), $cms);
        self::assertStringNotContainsString(Der::sequence($oid.Der::null()), $cms);
    }

    public function test_complete_includes_the_available_certificate_chain(): void
    {
        $signer = Pkcs12Fixture::load();
        $chainCertificate = $this->selfSignedEc()['cert'];
        $provider = new LocalPrivateKeySignatureProvider($signer['pkey']);
        $cms = (new DetachedCmsAssembler)->assemble(
            'payload',
            $signer['cert'],
            $provider,
            certificateChainPem: [$chainCertificate],
        );

        self::assertStringContainsString(X509Certificate::fromPem($chainCertificate)->der, $cms);
    }

    public function test_complete_rejects_a_prepared_algorithm_that_is_incompatible_with_the_certificate(): void
    {
        $bundle = Pkcs12Fixture::load();
        $prepared = (new DetachedCmsAssembler)->prepare('payload', $bundle['cert']);

        $this->expectException(SignProcessException::class);
        $this->expectExceptionMessage('is not compatible with the rsa certificate key');

        (new DetachedCmsAssembler)->complete(new PreparedDetachedCms(
            $prepared->certificatePem,
            $prepared->signedAttributes,
            $prepared->digestAlgorithm,
            SignatureAlgorithm::Ecdsa,
        ), new SignatureValue('signature'));
    }

    /**
     * @return array{cert: string, pkey: string}
     */
    private function selfSignedEc(): array
    {
        $key = openssl_pkey_new([
            'private_key_type' => OPENSSL_KEYTYPE_EC,
            'curve_name' => 'prime256v1',
        ]);
        self::assertNotFalse($key);

        $csr = openssl_csr_new(['CN' => 'cms-ec-test'], $key, ['digest_alg' => 'sha256']);
        self::assertNotFalse($csr);

        $cert = openssl_csr_sign($csr, null, $key, 1, ['digest_alg' => 'sha256']);
        self::assertNotFalse($cert);

        openssl_x509_export($cert, $certPem);
        openssl_pkey_export($key, $pkeyPem);

        return [
            'cert' => (string) $certPem,
            'pkey' => (string) $pkeyPem,
        ];
    }
}
