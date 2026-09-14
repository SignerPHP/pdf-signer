<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Tests\Unit;

use PHPUnit\Framework\TestCase;
use SignerPHP\PdfSigner\Application\Contract\SignatureProviderInterface;
use SignerPHP\PdfSigner\Application\DTO\HashAlgorithm;
use SignerPHP\PdfSigner\Application\DTO\SignatureValue;
use SignerPHP\PdfSigner\Application\DTO\SigningPayload;
use SignerPHP\PdfSigner\Domain\Exception\SignProcessException;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\Cms\Der;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\Cms\DetachedCmsAssembler;
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
