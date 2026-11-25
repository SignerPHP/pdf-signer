<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Tests\Support;

/**
 * Hand-built PDFs exercising the syntax the native encryption has to preserve.
 */
final class ProtectionPdfFixtures
{
    public const PAGE_TEXT = 'Protected (native) text';

    public const METADATA = '<?xpacket begin="" id="W5M0MpCehiHzreSzNTczkc9d"?><x:xmpmeta xmlns:x="adobe:ns:meta/"/><?xpacket end="w"?>';

    /**
     * @param  array<int, string>  $objects  object number => object body (between "obj" and "endobj")
     */
    public static function build(array $objects, string $trailer, string $version = '1.4'): string
    {
        $pdf = "%PDF-{$version}\n%\xE2\xE3\xCF\xD3\n";
        $offsets = [];

        foreach ($objects as $number => $body) {
            $offsets[$number] = strlen($pdf);
            $pdf .= $number." 0 obj\n".$body."\nendobj\n";
        }

        $size = max(array_keys($objects)) + 1;
        $xrefOffset = strlen($pdf);
        $pdf .= "xref\n0 {$size}\n0000000000 65535 f \n";
        for ($number = 1; $number < $size; $number++) {
            $pdf .= isset($offsets[$number])
                ? sprintf("%010d 00000 n \n", $offsets[$number])
                : "0000000000 00000 f \n";
        }

        return $pdf."trailer\n<< /Size {$size} {$trailer} >>\nstartxref\n{$xrefOffset}\n%%EOF\n";
    }

    /**
     * A document with literal/hex strings (escapes, nested parentheses, UTF-16BE), a compressed content
     * stream, an indirect /Length, non-dictionary objects, an annotation, metadata and an /ID.
     */
    public static function richPdf(): string
    {
        $content = gzcompress("BT /F1 18 Tf 36 100 Td (Protected \\(native\\) text) Tj ET\n");
        $plain = "q 0 0 1 rg 10 10 50 50 re f Q\n";

        return self::build([
            1 => '<< /Type /Catalog /Pages 2 0 R /Metadata 9 0 R /Lang (pt-BR) >>',
            2 => '<< /Type /Pages /Kids [3 0 R] /Count 1 >>',
            3 => '<< /Type /Page /Parent 2 0 R /MediaBox [0 0 300 144] /Contents [4 0 R 6 0 R] '
                .'/Resources << /Font << /F1 << /Type /Font /Subtype /Type1 /BaseFont /Helvetica >> >> >> /Annots [8 0 R] >>',
            4 => '<< /Length '.strlen($content)." /Filter /FlateDecode >>\nstream\n".$content."\nendstream",
            5 => '<< /Title (Caf\\351 \\(com\\) \\\\barra\\\\ e linha\\nnova) /Author <FEFF00C1006E0061> /Producer (SignerPHP % not a comment) /Keywords (a(b)c) >>',
            6 => "<< /Length 7 0 R >>\nstream\n".$plain.'endstream',
            7 => (string) strlen($plain),
            8 => '<< /Type /Annot /Subtype /Text /Rect [10 10 30 30] /Contents (Nota \\(anota\\347\\343o\\)) /NM <6E6F7461> >>',
            9 => '<< /Type /Metadata /Subtype /XML /Length '.strlen(self::METADATA)." >>\nstream\n".self::METADATA."\nendstream",
            10 => '[(item) 1 2.5 -3 true null /Name <00ff>]',
            11 => '(standalone string)',
        ], '/Root 1 0 R /Info 5 0 R /ID [<00112233445566778899AABBCCDDEEFF> <00112233445566778899AABBCCDDEEFF>]');
    }
}
