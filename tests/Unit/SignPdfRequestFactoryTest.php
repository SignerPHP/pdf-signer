<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Tests\Unit;

use PHPUnit\Framework\TestCase;
use SignerPHP\PdfSigner\Application\DTO\CertificateCredentialsDto;
use SignerPHP\PdfSigner\Application\DTO\PdfContentDto;
use SignerPHP\PdfSigner\Application\DTO\SignatureActorDto;
use SignerPHP\PdfSigner\Application\DTO\SignatureAppearanceDto;
use SignerPHP\PdfSigner\Application\DTO\SignatureMetadataDto;
use SignerPHP\PdfSigner\Application\DTO\SigningOptionsDto;
use SignerPHP\PdfSigner\Application\Factory\SignPdfRequestFactory;

final class SignPdfRequestFactoryTest extends TestCase
{
    public function test_factory_builds_request_with_all_inputs(): void
    {
        $factory = new SignPdfRequestFactory;
        $metadata = new SignatureMetadataDto(actor: new SignatureActorDto(name: 'Jeidison'));
        $appearance = new SignatureAppearanceDto('/tmp/a.png', [1, 2, 3, 4], 0);
        $options = new SigningOptionsDto($metadata, $appearance);

        $request = $factory->fromParts(
            new PdfContentDto('pdf-content'),
            new CertificateCredentialsDto('/tmp/cert.pfx', 'pwd'),
            $options,
        );

        self::assertSame('pdf-content', $request->pdf->content);
        self::assertSame('/tmp/cert.pfx', $request->certificate->certificatePath);
        self::assertSame('pwd', $request->certificate->password);
        self::assertSame($metadata, $request->options->metadata);
        self::assertSame($appearance, $request->options->appearance);
    }
}
