"""Independent PAdES B-B contract check using pyHanko and asn1crypto.

Checks the completed PDF, not internal CMS assembler output or the SignerPHP
validator. All certificates are disposable, locally generated trust anchors.
"""

import hashlib
import sys
from pathlib import Path

from asn1crypto import pem, x509
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign.validation import validate_pdf_signature
from pyhanko.sign.validation.settings import KeyUsageConstraints
from pyhanko_certvalidator import ValidationContext


def check_pdf(path: Path, cert: x509.Certificate, profile: str) -> None:
    original = path.read_bytes()
    with path.open('rb') as stream:
        signatures = PdfFileReader(stream).embedded_signatures
        assert len(signatures) == 1, f'{path}: expected one PDF signature'
        signature = signatures[0]
        pdf_sig = signature.sig_object

        subfilter = str(pdf_sig['/SubFilter'])
        expected = '/ETSI.CAdES.detached' if profile == 'pades' else '/adbe.pkcs7.detached'
        assert subfilter == expected, f'{path}: incorrect SubFilter {subfilter}'
        assert '/M' in pdf_sig and str(pdf_sig['/M']).startswith('D:'), f'{path}: missing PDF /M signing time'
        byte_range = [int(value) for value in pdf_sig['/ByteRange']]
        offset, first_length, second_offset, second_length = byte_range
        assert offset == 0 and second_offset + second_length == len(original), f'{path}: incomplete ByteRange'
        assert original[first_length:first_length + 1] == b'<' and original[second_offset - 1:second_offset] == b'>', f'{path}: unexpected Contents exclusion'
        assert first_length < second_offset < len(original), f'{path}: invalid ByteRange'

        signed_data = signature.signed_data
        assert len(signed_data['signer_infos']) == 1, f'{path}: multiple signerInfos'
        assert signed_data['encap_content_info']['content'].native is None, f'{path}: CMS content must be detached'
        assert signed_data['certificates'] is not None, f'{path}: missing certificate set'
        assert any(choice.chosen.dump() == cert.dump() for choice in signed_data['certificates'] if choice.name == 'certificate'), f'{path}: missing signer certificate'

        signer_info = signed_data['signer_infos'][0]
        attrs = {attr['type'].native: attr['values'][0] for attr in signer_info['signed_attrs']}
        assert 'content_type' in attrs and attrs['content_type'].native == 'data', f'{path}: incorrect contentType'
        assert 'message_digest' in attrs, f'{path}: missing messageDigest'
        expected_digest = hashlib.sha256(original[:first_length] + original[second_offset:]).digest()
        assert attrs['message_digest'].native == expected_digest == signature.compute_digest(), f'{path}: incorrect messageDigest'
        assert signer_info['digest_algorithm']['algorithm'].native == 'sha256', f'{path}: unexpected CMS digest algorithm'

        if profile == 'pades':
            assert 'signing_time' not in attrs, f'{path}: PAdES must not contain CMS signingTime'
            assert 'signing_certificate' not in attrs, f'{path}: wrong ESS certificate reference'
            assert 'signing_certificate_v2' in attrs, f'{path}: missing ESS signingCertificateV2'
            ess_certificates = attrs['signing_certificate_v2']['certs']
            assert len(ess_certificates) == 1, f'{path}: multiple ESS certificate references'
            reference = ess_certificates[0]
            assert reference['hash_algorithm']['algorithm'].native == 'sha256', f'{path}: wrong ESS hash algorithm'
            assert reference.contents[0] == 0x04, f'{path}: SHA-256 ESS default must be omitted'
            assert reference['cert_hash'].native == hashlib.sha256(cert.dump()).digest(), f'{path}: wrong signer certificate hash'
            issuer_serial = reference['issuer_serial']
            assert issuer_serial['serial_number'].native == cert.serial_number, f'{path}: wrong issuer serial'
            issuer_names = issuer_serial['issuer']
            assert len(issuer_names) == 1 and issuer_names[0].name == 'directory_name', f'{path}: invalid issuer GeneralNames'
            assert issuer_names[0].chosen.contents == cert.issuer.contents, f'{path}: wrong certificate issuer'
        else:
            assert 'signing_time' in attrs, f'{path}: PDF basic signingTime changed'
            assert 'signing_certificate_v2' not in attrs, f'{path}: unexpected ESS in PDF basic'

        status = validate_pdf_signature(
            signature,
            signer_validation_context=ValidationContext(
                trust_roots=[cert], allow_fetching=False, revocation_mode='soft-fail'
            ),
            key_usage_settings=KeyUsageConstraints(key_usage=set()),
        )
        assert status.intact and status.valid and status.trusted, f'{path}: pyHanko validation failed: {status.summary()}'
    print(f'OK: {path.parent.name}/{path.name}: {profile}, pyHanko cryptographic + trust + profile checks')


def main(root: Path) -> None:
    for key_type in ('rsa', 'ec'):
        folder = root / key_type
        _, _, certificate_der = pem.unarmor((folder / 'cert.pem').read_bytes())
        certificate = x509.Certificate.load(certificate_der)
        for filename, profile in (
            ('sync-basic.pdf', 'basic'),
            ('sync-pades.pdf', 'pades'),
            ('external-pades.pdf', 'pades'),
        ):
            check_pdf(folder / filename, certificate, profile)


if __name__ == '__main__':
    if len(sys.argv) != 2:
        raise SystemExit('Usage: python3 check.py FIXTURE_DIRECTORY')
    main(Path(sys.argv[1]))
