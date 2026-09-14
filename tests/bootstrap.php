<?php

declare(strict_types=1);

$autoloadCandidates = [
    __DIR__.'/../../vendor/autoload.php',
    __DIR__.'/../vendor/autoload.php',
];

foreach ($autoloadCandidates as $autoload) {
    if (is_file($autoload)) {
        require_once $autoload;
        require_once __DIR__.'/Support/FunctionOverrides.php';

        return;
    }
}

spl_autoload_register(static function (string $class): void {
    $prefix = 'SignerPHP\\PdfSigner\\';
    $baseDir = __DIR__.'/../src/';

    if (! str_starts_with($class, $prefix)) {
        return;
    }

    $relative = str_replace('\\', '/', substr($class, strlen($prefix)));
    $file = $baseDir.$relative.'.php';

    if (is_file($file)) {
        require_once $file;
    }
});

require_once __DIR__.'/Support/FunctionOverrides.php';
