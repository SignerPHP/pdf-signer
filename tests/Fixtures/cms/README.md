# CMS fixtures

Signatures over `content.bin` for CMS variants that PHP's `openssl_cms_sign()` cannot produce.
Generated once with OpenSSL 3 (`openssl cms -sign -binary -outform DER -in content.bin ...`):

| File | Extra options |
|---|---|
| `rsa-pss.der` | `-keyopt rsa_padding_mode:pss -keyopt rsa_pss_saltlen:32` (SHA-256) |
| `rsa-pss-sha1-defaults.der` | `-md sha1 -keyopt rsa_padding_mode:pss -keyopt rsa_pss_saltlen:20 -keyopt rsa_mgf1_md:sha1` (default parameters, encoded as an empty SEQUENCE) |
| `rsa-keyid.der` | `-keyid` (sid is the subjectKeyIdentifier) |
| `rsa-ber-stream.der` | `-stream` (BER, indefinite lengths) |
| `ed25519.der` | Ed25519 key, `-md sha512` |
| `two-signers.der` | two `-signer`/`-inkey` pairs |

Signers are throwaway self-signed certificates; only signature verification is tested with them.
