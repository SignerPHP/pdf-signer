<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Infrastructure\Native\Service;

use SignerPHP\PdfCore\Buffer;
use SignerPHP\PdfCore\SignatureObject;
use SignerPHP\PdfSigner\Application\Contract\SignatureProviderInterface;
use SignerPHP\PdfSigner\Application\DTO\SignatureProfile;
use SignerPHP\PdfSigner\Domain\Exception\SignProcessException;
use SignerPHP\PdfSigner\Infrastructure\Native\Contract\ChainAwarePkcs7SignerInterface;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\Cms\DetachedCmsAssembler;

final class Pkcs7Signer implements ChainAwarePkcs7SignerInterface
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
        return $this->signWithChain($signableDocument, $signatureProvider, $certificatePem, $profile, []);
    }

    public function signWithChain(
        Buffer $signableDocument,
        SignatureProviderInterface $signatureProvider,
        string $certificatePem,
        SignatureProfile $profile,
        array $certificateChainPem,
    ): string {
        if ($certificatePem === '') {
            throw new SignProcessException('Signing certificate PEM is required to assemble CMS.');
        }

        $cms = $this->cmsAssembler->assemble(
            $signableDocument->raw(),
            $certificatePem,
            $signatureProvider,
            certificateChainPem: $this->certificateBlocks($certificateChainPem),
            profile: $profile,
        );

        return str_pad(bin2hex($cms), SignatureObject::SIGNATURE_MAX_LENGTH, '0');
    }

    /**
     * PKCS#12 "extracerts" may hold empty entries or several certificates in one string;
     * keep each PEM certificate block once.
     *
     * @param  array<int, string>  $certificateChainPem
     * @return list<string>
     */
    private function certificateBlocks(array $certificateChainPem): array
    {
        $blocks = [];
        foreach ($certificateChainPem as $pem) {
            preg_match_all('/-----BEGIN CERTIFICATE-----[A-Za-z0-9+\/=\s]+-----END CERTIFICATE-----/', $pem, $matches);
            foreach ($matches[0] as $block) {
                $blocks[$block] = $block."\n";
            }
        }

        return array_values($blocks);
    }
}
