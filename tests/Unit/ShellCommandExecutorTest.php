<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Tests\Unit;

use PHPUnit\Framework\TestCase;
use SignerPHP\PdfSigner\Domain\Exception\ProtectionProcessException;
use SignerPHP\PdfSigner\Infrastructure\Native\Contract\ProcessRunnerInterface;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\ShellCommandExecutor;
use SignerPHP\PdfSigner\Infrastructure\Native\ValueObject\ProcessResult;

final class ShellCommandExecutorTest extends TestCase
{
    public function test_run_does_not_throw_when_process_succeeds(): void
    {
        $runner = new class implements ProcessRunnerInterface
        {
            public function run(string $command): ProcessResult
            {
                return new ProcessResult(0, ['ok']);
            }
        };

        $executor = new ShellCommandExecutor($runner);
        $executor->run('echo ok', 'failed');

        self::assertTrue(true);
    }

    public function test_run_throws_when_process_fails(): void
    {
        $runner = new class implements ProcessRunnerInterface
        {
            public function run(string $command): ProcessResult
            {
                return new ProcessResult(2, ['boom']);
            }
        };

        $executor = new ShellCommandExecutor($runner);

        $this->expectException(ProtectionProcessException::class);
        $this->expectExceptionMessage('custom fail boom');
        $executor->run('echo nope', 'custom fail');
    }
}
