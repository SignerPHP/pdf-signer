# Encrypted PDF fixtures

One-page PDF with object streams (`text-1-page--object-streams.pdf` from the conformance corpus),
encrypted with qpdf 12.2.0. The owner password is always `owner-pw`; where there is a user password it is `user-pw`.

| File | qpdf options | Handler |
|---|---|---|
| `aes256-r6-object-streams.pdf` | `--user-password=user-pw --owner-password=owner-pw --bits=256` | V5 R6 AESV3 |
| `aes128-r4-object-streams.pdf` | `--user-password= --owner-password=owner-pw --bits=128 --use-aes=y` | V4 R4 AESV2 |
| `aes128-r4-clear-metadata.pdf` | as above, plus `--cleartext-metadata` | V4 R4 AESV2, `/EncryptMetadata false` |
| `rc4-128-r3.pdf` | `--allow-weak-crypto --user-password=user-pw --owner-password=owner-pw --bits=128 --use-aes=n` | V2 R3 RC4 |
| `rc4-128-v4-crypt-filter.pdf` | `--allow-weak-crypto --user-password= --owner-password=owner-pw --bits=128 --use-aes=n --force-V4` | V4 R4, crypt filter V2 (RC4) |
| `rc4-40-r2.pdf` | `--allow-weak-crypto --user-password= --owner-password=owner-pw --bits=40` | V1 R2 RC4 |
