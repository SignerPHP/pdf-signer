# PDF core extraction dependency analysis

## Boundary and migration

PDF parsing, object representation, document manipulation and serialization move to the sibling `../pdf-core` package. Cryptography and signing orchestration remain here. Public Presentation APIs and signing DTO names remain unchanged.

Sequence: baseline tests; extract PDF source and decouple mixed types; move focused tests; install Composer path dependency; run both full suites and static checks.

## Complete original PdfCore inventory

| Original class (relative to Infrastructure/PdfCore) | Destination | External source consumers |
|---|---|---|
| `Buffer` | pdf-core | `src/Infrastructure/Native/Contract/XrefContentResolverInterface.php`, `src/Infrastructure/Native/Contract/Pkcs7SignerInterface.php`, `src/Infrastructure/Native/Contract/SignedBufferBuilderInterface.php`, `src/Infrastructure/Native/Service/Pkcs7Signer.php`, `src/Infrastructure/Native/Service/DocumentLongTermValidationApplier.php`, `src/Infrastructure/Native/Service/XrefContentResolver.php`, `src/Infrastructure/Native/Service/SignedBufferBuilder.php`, `src/Infrastructure/Native/Service/DocumentTimestampApplier.php` |
| `Compat/LegacyPdfValueCompat` | pdf-core | None directly |
| `Contract/SignatureRuntimeInterface` | Signer PHP (signing) | None directly |
| `DocumentTimestampObject` | pdf-core | None directly |
| `Exception/PdfCoreException` | pdf-core | None directly |
| `Exception/PdfCoreParsingException` | pdf-core | None directly |
| `Exception/PdfCoreSigningException` | Signer PHP (signing) | None directly |
| `Exception/PdfCoreStructureException` | pdf-core | None directly |
| `Metadata` | pdf-core | `src/Infrastructure/Native/Service/PdfSignatureFactory.php` |
| `ObjectParser` | pdf-core | None directly |
| `PDFObject` | pdf-core | None directly |
| `PageDescriptor` | pdf-core | None directly |
| `PageInfo` | pdf-core | None directly |
| `ParsedDocumentStructure` | pdf-core | None directly |
| `Parsing/ObjectLexer` | pdf-core | None directly |
| `PdfDocument` | pdf-core | `src/Infrastructure/Native/Contract/XrefContentResolverInterface.php`, `src/Infrastructure/Native/Contract/SignatureFactoryInterface.php`, `src/Infrastructure/Native/Contract/PdfDocumentPreparerInterface.php`, `src/Infrastructure/Native/Contract/SignedBufferBuilderInterface.php`, `src/Infrastructure/Native/Service/PdfSignatureFactory.php`, `src/Infrastructure/Native/Service/XrefContentResolver.php`, `src/Infrastructure/Native/Service/PdfDocumentPreparer.php`, `src/Infrastructure/Native/Service/SignedBufferBuilder.php` |
| `PdfValue/PDFValue` | pdf-core | `src/Infrastructure/Native/Service/DocumentLongTermValidationApplier.php`, `src/Infrastructure/Native/Service/XrefContentResolver.php`, `src/Infrastructure/Native/Service/SignedBufferBuilder.php`, `src/Infrastructure/Native/Service/DocumentTimestampApplier.php` |
| `PdfValue/PDFValueHexString` | pdf-core | `src/Infrastructure/Native/Service/XrefContentResolver.php`, `src/Infrastructure/Native/Service/SignedBufferBuilder.php`, `src/Infrastructure/Native/Service/DocumentTimestampApplier.php` |
| `PdfValue/PDFValueList` | pdf-core | `src/Infrastructure/Native/Service/DocumentLongTermValidationApplier.php` |
| `PdfValue/PDFValueObject` | pdf-core | `src/Infrastructure/Native/Service/DocumentLongTermValidationApplier.php` |
| `PdfValue/PDFValueReference` | pdf-core | `src/Infrastructure/Native/Service/DocumentLongTermValidationApplier.php` |
| `PdfValue/PDFValueSimple` | pdf-core | `src/Infrastructure/Native/Service/SignedBufferBuilder.php`, `src/Infrastructure/Native/Service/DocumentTimestampApplier.php` |
| `PdfValue/PDFValueString` | pdf-core | None directly |
| `PdfValue/PDFValueType` | pdf-core | None directly |
| `Service/Ascii85Codec` | pdf-core | None directly |
| `Service/DocumentMetadataUpdater` | pdf-core | None directly |
| `Service/DocumentTimestampObjectAssembler` | pdf-core | `src/Infrastructure/Native/Service/DocumentTimestampApplier.php` |
| `Service/NativeSignatureRuntime` | Signer PHP (signing) | None directly |
| `Service/ObjectStreamResolver` | pdf-core | None directly |
| `Service/PdfObjectReader` | pdf-core | None directly |
| `Service/SignatureObjectAssembler` | pdf-core | None directly |
| `Service/TrailerObjectResolver` | pdf-core | `src/Infrastructure/Native/Service/DocumentLongTermValidationApplier.php` |
| `Signature` | Signer PHP (signing) | `src/Infrastructure/Native/Contract/SignatureFactoryInterface.php`, `src/Infrastructure/Native/Contract/Pkcs7SignerInterface.php`, `src/Infrastructure/Native/Contract/SignedBufferBuilderInterface.php`, `src/Infrastructure/Native/Service/PdfSignatureFactory.php`, `src/Infrastructure/Native/Service/Pkcs7Signer.php`, `src/Infrastructure/Native/Service/SignedBufferBuilder.php`, `src/Infrastructure/Native/Service/DocumentTimestampApplier.php` |
| `SignatureAppearance` | pdf-core | `src/Infrastructure/Native/Service/PdfSignatureFactory.php` |
| `SignatureObject` | pdf-core | `src/Infrastructure/Native/Service/PdfSignatureFactory.php` |
| `Signer` | Signer PHP (signing) | None directly |
| `StreamReader` | pdf-core | None directly |
| `Struct` | pdf-core | `src/Infrastructure/Native/Service/PdfDocumentPreparer.php` |
| `Trailer` | pdf-core | None directly |
| `Utils/BinaryStreamReader` | pdf-core | None directly |
| `Utils/ContentGeneration` | pdf-core | None directly |
| `Utils/Date` | pdf-core | None directly |
| `Utils/ImageParser` | pdf-core | None directly |
| `Utils/Img` | pdf-core | None directly |
| `Utils/Mime` | pdf-core | None directly |
| `Utils/Str` | pdf-core | None directly |
| `Xref/CrossReferenceManager` | pdf-core | None directly |
| `Xref/CrossReferenceTableParser14` | pdf-core | None directly |
| `Xref/CrossReferenceTableParser15` | pdf-core | None directly |
| `Xref/Service/XRef14Parser` | pdf-core | None directly |
| `Xref/Service/XRef15Parser` | pdf-core | None directly |
| `Xref/Service/XrefContentBuilder` | pdf-core | None directly |
| `Xref/XRef14` | pdf-core | None directly |
| `Xref/XRef15` | pdf-core | None directly |
| `Xref/Xref` | pdf-core | `src/Infrastructure/Native/Service/DocumentLongTermValidationApplier.php`, `src/Infrastructure/Native/Service/XrefContentResolver.php`, `src/Infrastructure/Native/Service/SignedBufferBuilder.php`, `src/Infrastructure/Native/Service/DocumentTimestampApplier.php` |
| `Xref/XrefParseResult` | pdf-core | None directly |
| `XrefEntry` | pdf-core | None directly |

## Dependency findings

- PdfDocument, Trailer, Xref, both parser versions and object-stream services use PDF types only. The lexer/parser and document/xref relationships remain internal package dependencies, not package cycles.
- SignatureObject uses Signature::SIGNATURE_MAX_LENGTH: move ownership of the constant to SignatureObject and retain the signing constant as a forward reference.
- SignatureObjectAssembler performs AcroForm/widget and DocMDP manipulation, but accepts Application CertificationLevel. Replace the package parameter with its integer PDF permission value; signing maps the existing enum.
- SignatureAppearance renders PDF objects but accepts Application SignatureAppearanceXObjectDto. Introduce a PDF-owned XObject value, with the public DTO preserving construction and properties.
- Native PdfDocumentPreparer and XrefContentResolver contain only PDF parsing/serialization. Their existing Native contracts/adapters can delegate into pdf-core without reversing dependencies.
- Native ByteRangeInspector and SignatureDictionaryInspector inspect PDF structures only and move. PdfStructureInspector also reports LTV-specific details; retain that facade while extracting generic structure inspection.
- SignedBufferBuilder, DocumentTimestampApplier and DocumentLongTermValidationApplier mix serialization calls with signing policy. Keep orchestration here and consume the PDF serializer; do not move timestamp/revocation operations.
- Application and Domain have no direct PdfCore imports. Existing unrelated inversions include Application TimestampService depending on Native and Domain VerifiedCertificate depending on Application DTOs; these are outside this extraction.

## Tests

Move Infrastructure/PdfCore tests and Unit tests that exercise only extracted classes (including parsing, buffers, xrefs, object streams, values, images, document metadata, signature dictionaries and AcroForm assembly). Preserve assertions and separate test namespaces. Signing runtime, public API, providers, PAdES/LTV, validation and E2E golden contracts remain in Signer PHP. Record the exact resulting test inventory after migration.

## Composer

New library: signerphp/pdf-core; PHP ^8.2; ext-zlib, ext-fileinfo, ext-ctype. PSR-4 SignerPHP\PdfCore\ => src/. No dependency on signer-php, OpenSSL or network clients. PHPUnit/Pest and formatting tools are development dependencies only. Signer PHP uses a sibling path repository during development; publish/tag pdf-core before distributing the dependent release. Preserve the existing signer package name to avoid an unrelated package identity change.

## Risks and deferred work

- Preserve fixed container length, ByteRange padding and serialization byte offsets.
- Hybrid /XRefStm and /Prev parsing remain PDF-core responsibilities. Existing recovery heuristics and revision merge behavior must not be changed incidentally.
- AcroForm inline dictionaries and Perms inline dictionaries have existing resolution behavior that deserves focused review; extraction preserves it.
- Xref stream entry widths and generation serialization retain existing limitations.
- Structure/signature inspection uses regular expressions and is not a replacement for authoritative object parsing.
- FormMDP has no dedicated implementation to extract; PDF dictionaries can represent it. A dedicated manipulation API is future pdf-core work.
- Existing Producer metadata text is retained for behavior compatibility.
- Signing orchestration lives in Native (`SignatureHandler`, CMS assembler). `Infrastructure/PdfCore` was removed; pdf-core owns PDF objects and serialization.

## Exact moved test inventory

- `Unit/PdfValueConvertTest.php`
- `Unit/PDFValueSimpleTest.php`
- `Unit/XRef14Test.php`
- `Unit/PDFObjectTest.php`
- `Unit/StructTest.php`
- `Unit/DocumentTimestampObjectAssemblerTest.php`
- `Unit/ByteRangeInspectorTest.php`
- `Unit/ImageParserTest.php`
- `Unit/PdfObjectReaderTest.php`
- `Unit/ImgTest.php`
- `Unit/XRef15Test.php`
- `Unit/SignatureAppearanceRichTextTest.php`
- `Unit/PDFValueBaseTest.php`
- `Unit/ParsedDocumentStructureTest.php`
- `Unit/XRef14ParserTest.php`
- `Unit/SignatureDictionaryInspectorTest.php`
- `Unit/TrailerObjectResolverTest.php`
- `Unit/PdfCoreNoLegacyWrapperUsageTest.php`
- `Unit/PdfDocumentObjectStreamTest.php`
- `Unit/ContentGenerationTest.php`
- `Unit/PDFValueObjectTest.php`
- `Unit/DocumentMetadataUpdaterTest.php`
- `Unit/PdfDocumentCoreTest.php`
- `Unit/PdfDocumentGetObjectTest.php`
- `Unit/PDFValueListTest.php`
- `Unit/XrefParseResultTest.php`
- `Unit/SignatureAppearanceTest.php`
- `Unit/MimeTest.php`
- `Unit/ImageParserPixelIntegrityTest.php`
- `Unit/PdfDocumentXrefEntriesTest.php`
- `Unit/SignatureObjectAssemblerTest.php`
- `Unit/StreamReaderTest.php`
- `Unit/SignatureAppearanceStateTest.php`
- `Unit/XRef15ParserTest.php`
- `Unit/PageInfoTest.php`
- `Unit/XrefContentBuilderTest.php`
- `Unit/BufferTest.php`
- `Unit/ObjectLexerTest.php`
- `Unit/TrailerTest.php`
- `Unit/XrefFacadeTest.php`
- `Unit/PdfDocumentPreparerTest.php`
- `Unit/XrefContentResolverServiceTest.php`
- `Unit/PdfCoreObjectModelTest.php`
- `Unit/XrefEntryTest.php`
- `Unit/SignatureObjectTest.php`
- `Unit/ObjectStreamResolverTest.php`
- `Unit/MetadataTest.php`
- `Unit/BinaryStreamReaderTest.php`
- `Unit/PdfValueOptionalApiTest.php`
- `Unit/ObjectParserTest.php`
- `Unit/StrTest.php`
- `Infrastructure/PdfCore/PDFObjectTest.php`
- `Infrastructure/PdfCore/PageInfoTest.php`
- `Infrastructure/PdfCore/ObjectParserTest.php`
- `Infrastructure/PdfCore/Xref/XrefTest.php`
- `Infrastructure/PdfCore/Xref/Service/XRef14ParserTest.php`
- `Infrastructure/PdfCore/Xref/Service/XRef15ParserTest.php`
- `Infrastructure/PdfCore/Service/PdfObjectReaderTest.php`
- `Infrastructure/PdfCore/Service/Ascii85CodecTest.php`
- `Infrastructure/PdfCore/Service/ObjectStreamResolverTest.php`
