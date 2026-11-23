<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Infrastructure\Native\Service;

use SignerPHP\PdfCore\Buffer;
use SignerPHP\PdfCore\SignatureObject;
use SignerPHP\PdfSigner\Application\Contract\SignatureProviderInterface;
use SignerPHP\PdfSigner\Application\DTO\SignaturePolicyIdentifierDto;
use SignerPHP\PdfSigner\Application\DTO\SignatureProfile;
use SignerPHP\PdfSigner\Domain\Exception\SignProcessException;
use SignerPHP\PdfSigner\Infrastructure\Native\Contract\PolicyAwarePkcs7SignerInterface;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\Cms\DetachedCmsAssembler;

final class Pkcs7Signer implements PolicyAwarePkcs7SignerInterface
{
    public function __construct(
        private readonly DetachedCmsAssembler $cmsAssembler = new DetachedCmsAssembler,
    ) {}

    public function sign(
        Buffer $signableDocument,
        SignatureProviderInterface $signatureProvider,
        string $certificatePem,
    ): string {
        return $this->signWithProfile($signableDocument, $signatureProvider, $certificatePem, SignatureProfile::PdfBasic);
    }

    public function signWithProfile(Buffer $signableDocument, SignatureProviderInterface $signatureProvider, string $certificatePem, SignatureProfile $profile): string
    {
        return $this->assembleHex($signableDocument, $signatureProvider, $certificatePem, $profile, null);
    }

    public function signWithPolicy(
        Buffer $signableDocument,
        SignatureProviderInterface $signatureProvider,
        string $certificatePem,
        SignatureProfile $profile,
        SignaturePolicyIdentifierDto $signaturePolicy,
    ): string {
        return $this->assembleHex($signableDocument, $signatureProvider, $certificatePem, $profile, $signaturePolicy);
    }

    private function assembleHex(
        Buffer $signableDocument,
        SignatureProviderInterface $signatureProvider,
        string $certificatePem,
        SignatureProfile $profile,
        ?SignaturePolicyIdentifierDto $signaturePolicy,
    ): string {
        if ($certificatePem === '') {
            throw new SignProcessException('Signing certificate PEM is required to assemble CMS.');
        }

        $cms = $this->cmsAssembler->assemble(
            $signableDocument->raw(),
            $certificatePem,
            $signatureProvider,
            profile: $profile,
            signaturePolicy: $signaturePolicy,
        );

        return str_pad(bin2hex($cms), SignatureObject::SIGNATURE_MAX_LENGTH, '0');
    }
}
