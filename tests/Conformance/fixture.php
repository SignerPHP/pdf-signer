<?php

declare(strict_types=1);

// Test-only executable. Each invocation runs in a separate PHP process.
require_once __DIR__.'/../../vendor/autoload.php';

use SignerPHP\PdfSigner\Application\DTO\SignatureAlgorithm;
use SignerPHP\PdfSigner\Application\DTO\SignatureEncoding;
use SignerPHP\PdfSigner\Application\DTO\SigningInputType;
use SignerPHP\PdfSigner\Presentation\Signer;
use SignerPHP\PdfSigner\Tests\Support\PdfFixtureFactory;

if ($argc !== 3 || ! in_array($argv[1], ['prepare', 'complete'], true) || ! is_dir($argv[2])) {
    fwrite(STDERR, "Usage: php fixture.php prepare|complete DIRECTORY\n");
    exit(2);
}

$directory = realpath($argv[2]);
if ($directory === false) {
    throw new RuntimeException('Fixture directory does not exist.');
}

foreach (['rsa', 'ec'] as $keyType) {
    $path = $directory.'/'.$keyType;
    if ($argv[1] === 'prepare') {
        if (! mkdir($path, 0700) && ! is_dir($path)) {
            throw new RuntimeException('Could not create fixture directory.');
        }
        $key = openssl_pkey_new($keyType === 'ec'
            ? ['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']
            : ['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048]);
        if ($key === false) {
            throw new RuntimeException('Cannot generate '.$keyType.' private key.');
        }
        $csr = openssl_csr_new(['CN' => 'SignerPHP conformance '.$keyType], $key, ['digest_alg' => 'sha256']);
        $cert = $csr === false ? false : openssl_csr_sign($csr, null, $key, 1, ['digest_alg' => 'sha256'], random_int(2, 2147483647));
        if ($cert === false || ! openssl_x509_export($cert, $certPem) || ! openssl_pkey_export($key, $privateKey)) {
            throw new RuntimeException('Cannot issue conformance test certificate.');
        }
        if (! openssl_pkcs12_export($cert, $pfx, $key, 'fixture-secret')) {
            throw new RuntimeException('Cannot export conformance test PKCS#12.');
        }
        file_put_contents($path.'/cert.pem', $certPem);
        file_put_contents($path.'/key.pem', $privateKey);
        $pdf = PdfFixtureFactory::minimalPdf();
        foreach (['basic', 'pades'] as $profile) {
            $signer = Signer::signer()
                ->withPdfContent($pdf)
                ->withCertificateContent($pfx, 'fixture-secret')
                ->withoutDefaultAppearance();
            if ($profile === 'pades') {
                $signer->withPadesBaselineB();
            }
            file_put_contents($path.'/sync-'.$profile.'.pdf', $signer->sign());
        }
        $prepared = Signer::externalSigner()
            ->withPdfContent($pdf)
            ->withCertificate($certPem)
            ->withoutDefaultAppearance()
            ->withPadesBaselineB()
            ->prepare();
        if ($prepared->payload->inputType !== SigningInputType::Digest
            || $prepared->payload->digestAlgorithm->value !== 'sha256'
            || $prepared->payload->signatureAlgorithm !== ($keyType === 'rsa' ? SignatureAlgorithm::RsaPkcs1V15 : SignatureAlgorithm::Ecdsa)
            || $prepared->payload->signatureEncoding !== ($keyType === 'rsa' ? SignatureEncoding::RsaPkcs1 : SignatureEncoding::EcdsaDer)
            || strlen($prepared->payload->input()) !== 32
            || str_contains($prepared->state, $privateKey)
        ) {
            throw new RuntimeException('The external signing payload contract changed.');
        }
        file_put_contents($path.'/digest.bin', $prepared->payload->input());
        file_put_contents($path.'/state.json', $prepared->state);
        // The private key is intentionally not needed by the completion process.
    } else {
        $state = file_get_contents($path.'/state.json');
        $signature = file_get_contents($path.'/signature.der');
        if ($state === false || $signature === false || $signature === '') {
            throw new RuntimeException('Missing state or externally generated signature.');
        }
        file_put_contents($path.'/external-pades.pdf', Signer::externalSigner()->complete($state, $signature));
    }
}
