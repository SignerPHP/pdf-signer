<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Infrastructure\Native\Service\Cms;

use SignerPHP\PdfSigner\Application\Contract\SignatureProviderInterface;
use SignerPHP\PdfSigner\Application\DTO\HashAlgorithm;
use SignerPHP\PdfSigner\Application\DTO\SigningPayload;
use SignerPHP\PdfSigner\Domain\Exception\SignProcessException;

final class DetachedCmsAssembler
{
    private const OID_DATA = '1.2.840.113549.1.7.1';

    private const OID_SIGNED_DATA = '1.2.840.113549.1.7.2';

    private const OID_CONTENT_TYPE = '1.2.840.113549.1.9.3';

    private const OID_MESSAGE_DIGEST = '1.2.840.113549.1.9.4';

    private const OID_SIGNING_TIME = '1.2.840.113549.1.9.5';

    public function assemble(
        string $dataToSign,
        string $certificatePem,
        SignatureProviderInterface $signatureProvider,
        HashAlgorithm $algorithm = HashAlgorithm::Sha256,
        ?\DateTimeInterface $signingTime = null,
    ): string {
        $certificate = X509Certificate::fromPem($certificatePem);
        $digest = hash($algorithm->value, $dataToSign, true);
        $signedAttrsSet = $this->signedAttributesSet($digest, $signingTime ?? new \DateTimeImmutable('now'));
        $signature = $signatureProvider->sign(new SigningPayload($signedAttrsSet, $algorithm));
        if ($signature->bytes === '') {
            throw new SignProcessException('Signature provider returned an empty signature.');
        }

        $digestAlgorithm = Der::algorithmIdentifier($this->digestOid($algorithm));
        $signatureAlgorithm = Der::algorithmIdentifier($this->signatureOid($algorithm, $certificate->keyType()));
        $signedAttrsImplicit = "\xA0".substr($signedAttrsSet, 1);

        $signerInfo = Der::sequence(
            Der::tlv(0x02, "\x01")
            .Der::sequence($certificate->issuerNameDer.$certificate->serialIntegerDer)
            .$digestAlgorithm
            .$signedAttrsImplicit
            .$signatureAlgorithm
            .Der::octetString($signature->bytes)
        );

        $signedData = Der::sequence(
            Der::tlv(0x02, "\x01")
            .Der::set($digestAlgorithm)
            .Der::sequence(Der::objectIdentifier(self::OID_DATA))
            .Der::contextSpecific(0, $certificate->der)
            .Der::set($signerInfo)
        );

        return Der::sequence(
            Der::objectIdentifier(self::OID_SIGNED_DATA)
            .Der::contextSpecific(0, $signedData)
        );
    }

    private function signedAttributesSet(string $messageDigest, \DateTimeInterface $signingTime): string
    {
        $attributes = [
            Der::sequence(
                Der::objectIdentifier(self::OID_CONTENT_TYPE)
                .Der::set(Der::objectIdentifier(self::OID_DATA))
            ),
            Der::sequence(
                Der::objectIdentifier(self::OID_SIGNING_TIME)
                .Der::set(Der::utcTime($signingTime))
            ),
            Der::sequence(
                Der::objectIdentifier(self::OID_MESSAGE_DIGEST)
                .Der::set(Der::octetString($messageDigest))
            ),
        ];
        sort($attributes, SORT_STRING);

        return Der::set(implode('', $attributes));
    }

    private function digestOid(HashAlgorithm $algorithm): array
    {
        return match ($algorithm) {
            HashAlgorithm::Sha1 => [1, 3, 14, 3, 2, 26],
            HashAlgorithm::Sha224 => [2, 16, 840, 1, 101, 3, 4, 2, 4],
            HashAlgorithm::Sha256 => [2, 16, 840, 1, 101, 3, 4, 2, 1],
            HashAlgorithm::Sha384 => [2, 16, 840, 1, 101, 3, 4, 2, 2],
            HashAlgorithm::Sha512 => [2, 16, 840, 1, 101, 3, 4, 2, 3],
        };
    }

    private function signatureOid(HashAlgorithm $algorithm, string $keyType): string
    {
        if ($keyType === 'ec') {
            return match ($algorithm) {
                HashAlgorithm::Sha1 => '1.2.840.10045.4.1',
                HashAlgorithm::Sha224 => '1.2.840.10045.4.3.1',
                HashAlgorithm::Sha256 => '1.2.840.10045.4.3.2',
                HashAlgorithm::Sha384 => '1.2.840.10045.4.3.3',
                HashAlgorithm::Sha512 => '1.2.840.10045.4.3.4',
            };
        }

        return match ($algorithm) {
            HashAlgorithm::Sha1 => '1.2.840.113549.1.1.5',
            HashAlgorithm::Sha224 => '1.2.840.113549.1.1.14',
            HashAlgorithm::Sha256 => '1.2.840.113549.1.1.11',
            HashAlgorithm::Sha384 => '1.2.840.113549.1.1.12',
            HashAlgorithm::Sha512 => '1.2.840.113549.1.1.13',
        };
    }
}
