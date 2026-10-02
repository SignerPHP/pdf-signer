<?php

declare(strict_types=1);

use SignerPHP\PdfSigner\Infrastructure\Native\Service\CurlHttpClient;
use SignerPHP\PdfSigner\Infrastructure\Remote\Vidaas\VidaasAuthorization;
use SignerPHP\PdfSigner\Infrastructure\Remote\Vidaas\VidaasCertificateDiscovery;
use SignerPHP\PdfSigner\Infrastructure\Remote\Vidaas\VidaasClient;
use SignerPHP\PdfSigner\Infrastructure\Remote\Vidaas\VidaasSignatureProvider;

require dirname(__DIR__, 3).'/vendor/autoload.php';

session_start();

function env(string $name, ?string $default = null): string
{
    $value = getenv($name);
    if ($value === false || trim($value) === '') {
        if ($default !== null) {
            return $default;
        }

        throw new RuntimeException(sprintf('Configure a variável %s antes de iniciar o exemplo.', $name));
    }

    return trim($value);
}

function authorization(): VidaasAuthorization
{
    return new VidaasAuthorization(
        new CurlHttpClient,
        env('VIDAAS_CLIENT_ID'),
        env('VIDAAS_CLIENT_SECRET'),
        env('VIDAAS_BASE_URL', VidaasClient::SANDBOX_URL),
    );
}

function vidaasClient(): VidaasClient
{
    $token = $_SESSION['vidaas_access_token'] ?? null;
    if (! is_string($token) || $token === '') {
        throw new RuntimeException('Autorize a sessão VIDaaS antes de consultar certificados ou assinar.');
    }

    return new VidaasClient($token, new CurlHttpClient, env('VIDAAS_BASE_URL', VidaasClient::SANDBOX_URL));
}

function certificateDiscovery(): VidaasCertificateDiscovery
{
    return new VidaasCertificateDiscovery(vidaasClient());
}

function signatureProvider(): VidaasSignatureProvider
{
    return new VidaasSignatureProvider(vidaasClient());
}

function callbackUrl(): string
{
    return env('VIDAAS_REDIRECT_URI', 'http://127.0.0.1:8080/');
}

function redirectHome(): never
{
    header('Location: /');
    exit;
}

function escape(string $value): string
{
    return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}
