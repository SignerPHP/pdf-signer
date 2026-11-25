<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Tests\Support;

use SignerPHP\PdfSigner\Infrastructure\Native\Contract\HttpClientInterface;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\Cms\Der;
use SignerPHP\PdfSigner\Infrastructure\Native\ValueObject\HttpResponse;

/**
 * Throwaway PKI (root -> issuing CA -> signers / OCSP responders) whose OCSP responses are
 * produced by the OpenSSL CLI responder (`openssl ocsp -index ... -respout`) from the request
 * the code under test actually sends. Only tests use the CLI; the library does not.
 */
final class OcspTestPki
{
    /** @var array<string, string> name => PEM certificate */
    public array $certificates = [];

    /** @var array<string, string> name => PEM private key */
    private array $keys = [];

    private string $directory;

    public function __construct()
    {
        $this->directory = sys_get_temp_dir().'/signer-php-ocsp-'.bin2hex(random_bytes(6));
        mkdir($this->directory, 0700, true);

        $config = $this->path('openssl.cnf');
        file_put_contents($config, implode("\n", [
            '[req]',
            'distinguished_name = dn',
            '[dn]',
            '[v3_ca]',
            'basicConstraints = critical, CA:TRUE',
            'keyUsage = critical, keyCertSign, cRLSign',
            '[v3_leaf]',
            'basicConstraints = critical, CA:FALSE',
            'authorityInfoAccess = OCSP;URI:http://ocsp.example.test/',
            '[v3_two]',
            'basicConstraints = critical, CA:FALSE',
            'authorityInfoAccess = OCSP;URI:http://ocsp-a.example.test/, OCSP;URI:http://ocsp-b.example.test/',
            '[v3_plain]',
            'basicConstraints = critical, CA:FALSE',
            '[v3_responder]',
            'basicConstraints = critical, CA:FALSE',
            'extendedKeyUsage = OCSPSigning',
            '[v3_no_eku]',
            'basicConstraints = critical, CA:FALSE',
            'extendedKeyUsage = clientAuth',
            '',
        ]));

        $this->issue('root', 'OCSP Test Root', null, 'v3_ca', 1);
        $this->issue('ca', 'OCSP Test Issuing CA', 'root', 'v3_ca', 2);
        $this->issue('leaf', 'Revocation Test Signer', 'ca', 'v3_leaf', 3);
        $this->issue('twoResponders', 'Two Responders Signer', 'ca', 'v3_two', 4);
        $this->issue('leafWithoutOcsp', 'Signer Without OCSP', 'ca', 'v3_plain', 5);
        $this->issue('responder', 'OCSP Delegated Responder', 'ca', 'v3_responder', 6);
        $this->issue('responderWithoutEku', 'OCSP Responder Without EKU', 'ca', 'v3_no_eku', 7);
        $this->issue('rogueRoot', 'OCSP Test Root', null, 'v3_ca', 1);
        $this->issue('rogueCa', 'OCSP Test Issuing CA', 'rogueRoot', 'v3_ca', 2);
    }

    public function __destruct()
    {
        foreach (glob($this->directory.'/*') ?: [] as $file) {
            unlink($file);
        }
        rmdir($this->directory);
    }

    public static function opensslAvailable(): bool
    {
        exec('openssl version 2>&1', $output, $code);

        return $code === 0;
    }

    public function pem(string $name): string
    {
        return $this->certificates[$name];
    }

    public function der(string $name): string
    {
        return self::pemToDer($this->certificates[$name]);
    }

    /**
     * Answers $requestDer with the OpenSSL OCSP responder.
     *
     * @param  string  $status  good|revoked|unknown-to-responder
     * @param  string  $signer  certificate that signs the response
     * @param  string  $issuer  CA whose index the responder serves
     * @param  ?int  $days  nextUpdate in days, null for a response without nextUpdate
     */
    public function respond(
        string $requestDer,
        string $status = 'good',
        string $signer = 'ca',
        string $issuer = 'ca',
        ?int $days = 1,
        string $certificate = 'leaf',
        bool $byKey = false,
    ): string {
        $serial = strtoupper(bin2hex($this->serialBytes($certificate)));
        $line = match ($status) {
            'revoked' => "R\t301231000000Z\t".gmdate('ymdHis', time() - 3600)."Z,keyCompromise\t{$serial}\tunknown\t/CN=x",
            default => "V\t301231000000Z\t\t{$serial}\tunknown\t/CN=x",
        };
        file_put_contents($this->path('index.txt'), $line."\n");
        file_put_contents($this->path('index.txt.attr'), "unique_subject = no\n");
        file_put_contents($this->path('request.der'), $requestDer);
        if (is_file($this->path('response.der'))) {
            unlink($this->path('response.der'));
        }

        $command = sprintf(
            'openssl ocsp -index %s -CA %s -rsigner %s -rkey %s -reqin %s -respout %s%s%s 2>&1',
            escapeshellarg($this->path('index.txt')),
            escapeshellarg($this->path($issuer.'.pem')),
            escapeshellarg($this->path($signer.'.pem')),
            escapeshellarg($this->path($signer.'.key')),
            escapeshellarg($this->path('request.der')),
            escapeshellarg($this->path('response.der')),
            $days === null ? '' : ' -ndays '.$days,
            $byKey ? ' -resp_key_id' : '',
        );
        exec($command, $output, $code);
        $response = @file_get_contents($this->path('response.der'));
        if ($code !== 0 || ! is_string($response) || $response === '') {
            throw new \RuntimeException('openssl ocsp failed: '.implode("\n", $output));
        }

        return $response;
    }

    /**
     * An OCSP request built by the OpenSSL CLI client, without nonce.
     */
    public function cliRequest(string $certificate, string $issuer, string $digest): string
    {
        $command = sprintf(
            'openssl ocsp -issuer %s -%s -cert %s -no_nonce -reqout %s 2>&1',
            escapeshellarg($this->path($issuer.'.pem')),
            $digest,
            escapeshellarg($this->path($certificate.'.pem')),
            escapeshellarg($this->path('cli-request.der')),
        );
        exec($command, $output, $code);
        $request = @file_get_contents($this->path('cli-request.der'));
        if ($code !== 0 || ! is_string($request) || $request === '') {
            throw new \RuntimeException('openssl ocsp failed: '.implode("\n", $output));
        }

        return $request;
    }

    /**
     * Rewrites tbsResponseData and signs it again with $signer's key, so the response stays
     * correctly signed: used to move its times or change its nonce.
     *
     * @param  callable(string): string  $mutate
     */
    public function resign(string $responseDer, callable $mutate, string $signer = 'ca'): string
    {
        [$basic, $rebuild] = self::basicResponse($responseDer);
        [$tbs, $algorithm, , $rest] = $basic;
        $tbs = $mutate($tbs);
        openssl_sign($tbs, $signature, $this->keys[$signer], 'sha256');

        return $rebuild(Der::sequence($tbs.$algorithm.Der::tlv(0x03, "\x00".$signature).$rest));
    }

    /**
     * Flips one byte of the response signature.
     */
    public static function corruptSignature(string $responseDer): string
    {
        [$basic, $rebuild] = self::basicResponse($responseDer);
        [$tbs, $algorithm, $signature, $rest] = $basic;
        $signature[strlen($signature) - 1] = chr(ord($signature[strlen($signature) - 1]) ^ 0x01);

        return $rebuild(Der::sequence($tbs.$algorithm.Der::tlv(0x03, "\x00".$signature).$rest));
    }

    /**
     * Shifts every GeneralizedTime of a tbsResponseData by $seconds.
     */
    public static function shiftTimes(string $tbs, int $seconds): string
    {
        return (string) preg_replace_callback('/\x18\x0f(\d{14})Z/', static function (array $match) use ($seconds): string {
            $time = \DateTimeImmutable::createFromFormat('!YmdHis', $match[1], new \DateTimeZone('UTC'));

            return "\x18\x0f".gmdate('YmdHis', $time->getTimestamp() + $seconds).'Z';
        }, $tbs);
    }

    /**
     * An HTTP client that answers OCSP POSTs with $responder($requestDer, $url) and records the requests.
     *
     * @param  callable(string, string): HttpResponse  $responder
     */
    public static function httpClient(callable $responder): HttpClientInterface
    {
        return new class($responder) implements HttpClientInterface
        {
            /** @var list<array{method: string, url: string, headers: array<int, string>, body: string, timeout: int}> */
            public array $requests = [];

            /** @var callable(string, string): HttpResponse */
            private $responder;

            public function __construct(callable $responder)
            {
                $this->responder = $responder;
            }

            public function request(
                string $method,
                string $url,
                array $headers = [],
                string $body = '',
                int $timeoutSeconds = 10,
                bool $followRedirects = false,
            ): HttpResponse {
                $this->requests[] = ['method' => $method, 'url' => $url, 'headers' => $headers, 'body' => $body, 'timeout' => $timeoutSeconds];

                return ($this->responder)($body, $url);
            }
        };
    }

    public static function pemToDer(string $pem): string
    {
        return (string) base64_decode((string) preg_replace('/-----[^-]+-----|\s+/', '', $pem), true);
    }

    /**
     * @return array{0: array{0: string, 1: string, 2: string, 3: string}, 1: \Closure(string): string}
     *                                                                                                  [tbs TLV, signatureAlgorithm TLV, signature bytes, trailing certs TLV] and a rebuilder
     */
    private static function basicResponse(string $responseDer): array
    {
        [, $outer] = Der::readTlvStrict($responseDer);
        [, $status, $offset] = Der::readTlvStrict($outer);
        [, $explicit] = Der::readTlvStrict($outer, $offset);
        [, $responseBytes] = Der::readTlvStrict($explicit);
        [, , $typeEnd] = Der::readTlvStrict($responseBytes);
        $type = substr($responseBytes, 0, $typeEnd);
        [, $basicDer] = Der::readTlvStrict($responseBytes, $typeEnd);
        [, $basic] = Der::readTlvStrict($basicDer);

        $parts = [];
        for ($position = 0; $position < strlen($basic);) {
            $start = $position;
            [, $value, $position] = Der::readTlvStrict($basic, $position);
            $parts[] = [substr($basic, $start, $position - $start), $value];
        }

        $rebuild = static fn (string $newBasic): string => Der::sequence(
            Der::tlv(0x0A, $status).Der::contextSpecific(0, Der::sequence($type.Der::octetString($newBasic)))
        );

        return [[$parts[0][0], $parts[1][0], substr($parts[2][1], 1), $parts[3][0] ?? ''], $rebuild];
    }

    private function serialBytes(string $name): string
    {
        $serial = openssl_x509_parse($this->certificates[$name])['serialNumberHex'] ?? '';

        return (string) hex2bin(strlen($serial) % 2 === 1 ? '0'.$serial : $serial);
    }

    private function issue(string $name, string $commonName, ?string $issuer, string $section, int $serial): void
    {
        $options = [
            'config' => $this->path('openssl.cnf'),
            'digest_alg' => 'sha256',
            'private_key_bits' => 2048,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
            'x509_extensions' => $section,
        ];
        $key = openssl_pkey_new($options);
        $csr = openssl_csr_new(['commonName' => $commonName], $key, $options);
        $certificate = openssl_csr_sign(
            $csr,
            $issuer === null ? null : $this->certificates[$issuer],
            $issuer === null ? $key : $this->keys[$issuer],
            2,
            $options,
            $serial,
        );
        openssl_x509_export($certificate, $pem);
        openssl_pkey_export($key, $keyPem, null, $options);

        $this->certificates[$name] = $pem;
        $this->keys[$name] = $keyPem;
        file_put_contents($this->path($name.'.pem'), $pem);
        file_put_contents($this->path($name.'.key'), $keyPem);
    }

    private function path(string $file): string
    {
        return $this->directory.'/'.$file;
    }
}
