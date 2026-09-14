<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Tests\Unit;

use PHPUnit\Framework\TestCase;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\Inspect\PdfStructureInspector;

final class PdfStructureInspectorTest extends TestCase
{
    public function test_detect_pdf_version_and_xref_mode_and_revisions(): void
    {
        $pdf = <<<'PDF'
%PDF-1.4
1 0 obj
<< /Type /Catalog >>
endobj
xref
0 1
0000000000 65535 f
trailer
<< /Size 1 >>
startxref
123
%%EOF
2 0 obj
<< /Type /XRef >>
endobj
startxref
456
%%EOF
PDF;

        $inspector = new PdfStructureInspector;

        self::assertSame('1.4', $inspector->detectPdfVersion($pdf));

        $xref = $inspector->detectXrefMode($pdf);
        self::assertSame('hybrid', $xref['mode']);
        self::assertTrue($xref['has_xref_table']);
        self::assertTrue($xref['has_xref_stream']);
        self::assertSame(456, $xref['startxref']);

        $revisions = $inspector->detectIncrementalRevisions($pdf);
        self::assertCount(2, $revisions);
        self::assertSame(0, $revisions[0]['index']);
        self::assertSame(1, $revisions[1]['index']);
        self::assertSame($revisions[0]['revision_end'] + 1, $revisions[1]['revision_start']);
    }

    public function test_analyze_appearance_and_ltv_assembly(): void
    {
        $pdf = <<<'PDF'
%PDF-1.7
<< /Subtype /Widget /AP << /N 10 0 R >> >>
<< /Type /XObject >>
<< /DSS << /VRI << /Key 1 0 R >> /OCSPs [1 0 R] /CRLs [2 0 R] /Certs [3 0 R] >> >>
PDF;

        $inspector = new PdfStructureInspector;

        $appearance = $inspector->analyzeAppearance($pdf);
        self::assertTrue($appearance['has_appearance']);
        self::assertSame(1, $appearance['widget_count']);
        self::assertSame(1, $appearance['ap_n_count']);
        self::assertSame(1, $appearance['xobject_count']);
        self::assertContains('widget-annotations-detected', $appearance['trace']);

        $ltv = $inspector->analyzeLtvAssembly($pdf);
        self::assertTrue($ltv['has_dss']);
        self::assertTrue($ltv['has_vri']);
        self::assertTrue($ltv['has_ocsps']);
        self::assertTrue($ltv['has_crls']);
        self::assertTrue($ltv['has_certs']);
        self::assertSame(1, $ltv['vri_entry_hint_count']);
        self::assertSame(1, $ltv['ocsp_stream_hint_count']);
        self::assertSame(1, $ltv['crl_stream_hint_count']);
        self::assertSame(1, $ltv['cert_stream_hint_count']);
    }

    public function test_detectors_handle_unknown_xref_and_missing_pdf_version(): void
    {
        $pdf = 'plain text without pdf markers';

        $inspector = new PdfStructureInspector;

        self::assertNull($inspector->detectPdfVersion($pdf));

        $xref = $inspector->detectXrefMode($pdf);
        self::assertSame('unknown', $xref['mode']);
        self::assertFalse($xref['has_xref_table']);
        self::assertFalse($xref['has_xref_stream']);
        self::assertNull($xref['startxref']);
        self::assertSame([], $inspector->detectIncrementalRevisions($pdf));

        $tableOnly = $inspector->detectXrefMode("xref\n0 1\nstartxref\n7\n%%EOF");
        self::assertSame('table', $tableOnly['mode']);

        $streamOnly = $inspector->detectXrefMode("<< /Type /XRef >>\nstartxref\n9\n%%EOF");
        self::assertSame('stream', $streamOnly['mode']);
    }
}
