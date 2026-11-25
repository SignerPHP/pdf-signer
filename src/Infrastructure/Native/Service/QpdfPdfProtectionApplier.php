<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Infrastructure\Native\Service;

use SignerPHP\PdfSigner\Application\DTO\ProtectionOptionsDto;
use SignerPHP\PdfSigner\Infrastructure\Native\Contract\CommandExecutorInterface;
use SignerPHP\PdfSigner\Infrastructure\Native\Contract\PdfProtectionApplierInterface;

/**
 * @deprecated Since 1.1. PDF protection no longer shells out to qpdf; use {@see NativePdfProtectionApplier}.
 *             Kept for backwards compatibility: it now delegates to the native implementation.
 */
final readonly class QpdfPdfProtectionApplier implements PdfProtectionApplierInterface
{
    private NativePdfProtectionApplier $nativeApplier;

    /**
     * @param  CommandExecutorInterface  $commandExecutor  Deprecated and unused: no external command is executed anymore.
     */
    public function __construct(private CommandExecutorInterface $commandExecutor = new ShellCommandExecutor)
    {
        $this->nativeApplier = new NativePdfProtectionApplier;
    }

    public function apply(string $pdfContent, ProtectionOptionsDto $options): string
    {
        return $this->nativeApplier->apply($pdfContent, $options);
    }
}
