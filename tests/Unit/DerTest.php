<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Tests\Unit;

use PHPUnit\Framework\TestCase;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\Cms\Der;

final class DerTest extends TestCase
{
    public function test_object_identifier_rejects_oid_with_fewer_than_two_arcs(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('OID must have at least two arcs.');

        Der::objectIdentifier('1');
    }
}
