<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Tests\Support;

use SignerPHP\PdfSigner\Infrastructure\PdfCore\Contract\SignatureRuntimeInterface;

final class SignatureRuntimeSpy implements SignatureRuntimeInterface
{
    public int|false $fileSize = 3;

    public string|false $tempFile = '/tmp/fake-signature.p7m';

    public bool $signResult = true;

    public string|false $readContent = "abc%%EOF\n\n------header\n\nQQ==";

    public bool $isFile = true;

    public string|false $decodedBase64 = 'A';

    public string $hex = '41';

    /** @var array<int, string> */
    public array $removedFiles = [];

    public function fileSize(string $path): int|false
    {
        return $this->fileSize;
    }

    public function createTempFile(string $directory, string $prefix): string|false
    {
        return $this->tempFile;
    }

    public function signPkcs7(string $inputFile, string $outputFile, string $certificate, string $privateKey): bool
    {
        return $this->signResult;
    }

    public function readFile(string $path): string|false
    {
        return $this->readContent;
    }

    public function removeFile(string $path): void
    {
        $this->removedFiles[] = $path;
    }

    public function isFile(string $path): bool
    {
        return $this->isFile;
    }

    public function decodeBase64(string $value): string|false
    {
        return $this->decodedBase64;
    }

    public function toHex(string $binary): string
    {
        return $this->hex;
    }
}
