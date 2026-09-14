<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Infrastructure\Native\Service;

use SignerPHP\PdfSigner\Application\Contract\SignatureProviderInterface;
use SignerPHP\PdfSigner\Application\DTO\SignatureValue;
use SignerPHP\PdfSigner\Application\DTO\SigningPayload;
use SignerPHP\PdfSigner\Domain\Exception\SignProcessException;
use SignerPHP\PdfSigner\Infrastructure\PdfCore\Contract\SignatureRuntimeInterface;
use SignerPHP\PdfSigner\Infrastructure\PdfCore\Service\NativeSignatureRuntime;

final readonly class LocalPrivateKeySignatureProvider implements SignatureProviderInterface
{
    public function __construct(
        private string $certificatePem,
        private string $privateKeyPem,
        private SignatureRuntimeInterface $runtime = new NativeSignatureRuntime,
    ) {}

    public function sign(SigningPayload $payload): SignatureValue
    {
        $tmpFolder = sys_get_temp_dir();
        $inputFile = tempnam($tmpFolder, 'pdfsign');
        if ($inputFile === false) {
            throw new SignProcessException('Could not allocate temporary file to sign payload.');
        }

        $outputFile = $this->runtime->createTempFile($tmpFolder, 'pdfsign');
        if ($outputFile === false) {
            @unlink($inputFile);

            throw new SignProcessException('Could not create a temporary filename for the local signature.');
        }

        try {
            if (file_put_contents($inputFile, $payload->data) === false) {
                throw new SignProcessException('Could not write signing payload to temporary file.');
            }

            if (! $this->runtime->signPkcs7($inputFile, $outputFile, $this->certificatePem, $this->privateKeyPem)) {
                throw new SignProcessException('Failed to sign payload with the local private key.');
            }

            return new SignatureValue($this->extractCmsDer($inputFile, $outputFile));
        } finally {
            @unlink($inputFile);
            if ($this->runtime->isFile($outputFile)) {
                $this->runtime->removeFile($outputFile);
            }
        }
    }

    private function extractCmsDer(string $inputFile, string $outputFile): string
    {
        $filesizeOriginal = $this->runtime->fileSize($inputFile);
        if ($filesizeOriginal === false) {
            throw new SignProcessException('Could not read signing payload size.');
        }

        $signature = $this->runtime->readFile($outputFile);
        if ($signature === false) {
            throw new SignProcessException('Could not read generated signature file.');
        }

        $signature = substr($signature, $filesizeOriginal);
        $separatorPosition = strpos($signature, "%%EOF\n\n------");
        if ($separatorPosition === false) {
            throw new SignProcessException('Could not extract PKCS7 payload from signed output.');
        }

        $signature = substr($signature, $separatorPosition + 13);
        $tmpArr = explode("\n\n", $signature);
        if (! isset($tmpArr[1])) {
            throw new SignProcessException('Malformed PKCS7 output.');
        }

        $decoded = $this->runtime->decodeBase64(trim($tmpArr[1]));
        if ($decoded === false) {
            throw new SignProcessException('Could not decode PKCS7 base64 payload.');
        }

        return $decoded;
    }
}
