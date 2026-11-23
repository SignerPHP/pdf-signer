<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Infrastructure\Remote\Csc;

use SignerPHP\PdfSigner\Domain\Exception\SignerException;
use SignerPHP\PdfSigner\Infrastructure\Native\Contract\HttpClientInterface;
use SignerPHP\PdfSigner\Infrastructure\Native\ValueObject\HttpResponse;

final readonly class CscClient
{
    public function __construct(
        private HttpClientInterface $httpClient,
        private string $baseUrl,
        #[\SensitiveParameter] private ?string $accessToken = null,
        private int $timeoutSeconds = 20,
    ) {
        $parts = parse_url($baseUrl);
        if (! is_array($parts) || ! in_array($parts['scheme'] ?? '', ['http', 'https'], true)
            || ! isset($parts['host']) || isset($parts['user']) || isset($parts['pass'])
            || ($parts['scheme'] === 'http' && ! in_array($parts['host'], ['localhost', '127.0.0.1', '::1'], true))) {
            throw new \InvalidArgumentException('CSC endpoint must use HTTPS or loopback HTTP.');
        }
        if ($timeoutSeconds < 1) {
            throw new \InvalidArgumentException('CSC timeout must be positive.');
        }
    }

    /**
     * @param  array<string, mixed>  $payload
     * @return array<string, mixed>
     */
    public function post(string $operation, #[\SensitiveParameter] array $payload = []): array
    {
        if (! in_array($operation, ['info', 'credentials/list', 'credentials/info', 'credentials/authorize', 'signatures/signHash'], true)) {
            throw new \InvalidArgumentException('Unsupported CSC operation.');
        }

        // An ambiguous timeout after signHash must not trigger an automatic retry.
        // Prepare the request before crossing the uncertain submission boundary.
        $url = rtrim($this->baseUrl, '/').'/csc/v1/'.$operation;
        $headers = $this->headers();
        $body = json_encode($payload, JSON_THROW_ON_ERROR);

        try {
            $response = $this->httpClient->request('POST', $url, $headers, $body, $this->timeoutSeconds);
        } catch (\RuntimeException) {
            if ($operation === 'signatures/signHash') {
                throw new CscSignHashOutcomeUnknownException(
                    'CSC signHash outcome is unknown; reconcile before resubmission.',
                );
            }

            // Transport exception messages may contain tokens or URLs.
            throw new SignerException(sprintf('CSC %s transport failed.', $operation));
        }

        try {
            return $this->decodeResponse($response, $operation);
        } catch (SignerException $exception) {
            if ($operation !== 'signatures/signHash') {
                throw $exception;
            }

            // The key operation could have completed despite a missing, malformed,
            // or otherwise unusable HTTP response.
            throw new CscSignHashOutcomeUnknownException(
                'CSC signHash outcome is unknown; reconcile before resubmission.',
            );
        }
    }

    /** @return list<string> */
    private function headers(): array
    {
        $headers = ['Accept: application/json', 'Content-Type: application/json'];
        if ($this->accessToken !== null && $this->accessToken !== '') {
            $headers[] = 'Authorization: Bearer '.$this->accessToken;
        }

        return $headers;
    }

    /** @return array<string, mixed> */
    private function decodeResponse(HttpResponse $response, string $operation): array
    {
        // A transport error invalidates even a seemingly successful status/body.
        // The error text may contain URLs or authorization material.
        if ($response->transportError !== null) {
            throw new SignerException(sprintf('CSC %s transport failed.', $operation));
        }
        if (! $response->isSuccessful()) {
            throw new SignerException(sprintf('CSC %s failed with HTTP %d.', $operation, $response->statusCode));
        }
        try {
            $data = json_decode($response->body, true, flags: JSON_THROW_ON_ERROR);
        } catch (\JsonException) {
            throw new SignerException(sprintf('CSC %s returned invalid JSON.', $operation));
        }
        if (! is_array($data) || array_is_list($data)) {
            throw new SignerException(sprintf('CSC %s returned an invalid response.', $operation));
        }

        return $data;
    }

    public function assertVersion(): void
    {
        if (($this->post('info')['specs'] ?? null) !== '1.0.4.0') {
            throw new SignerException('CSC service does not advertise supported version 1.0.4.0.');
        }
    }
}
