# File-system encryption

This page explains which encryption modes file systems and disk layers use, why they use them, and where the MKV modes would fit. Read it before designing file or disk encryption on this library.

## Two shapes

File systems that own their block pointers store a nonce and an authentication tag in the metadata next to each block. That leaves room for an AEAD mode such as GCM or CCM, so each block is authenticated.

Sector-layer encryption has no room for extra bytes. Each sector or data unit is encrypted in place with XTS, using the sector number as the tweak. Nothing authenticates the data. This shape covers dm-crypt, BitLocker, APFS, VeraCrypt and the file contents mode of fscrypt.

## Systems

| System | File data | Keys and metadata | Authenticated | Source |
| --- | --- | --- | --- | --- |
| OpenZFS | AES-GCM with `encryption=on`; CCM is an option | 96-bit IV; 128-bit MAC stored in the block pointer; per-block 64-bit salt is an HKDF input with the master key; dedup blocks take their salt and IV from an HMAC of the plaintext; no associated data for normal file data | Yes, the GCM or CCM tag | [zfsprops](https://openzfs.github.io/openzfs-docs/man/master/7/zfsprops.7.html), [zio_crypt.c](https://github.com/openzfs/zfs/blob/master/module/zfs/zio_crypt.c) |
| fscrypt (ext4, F2FS, UBIFS, CephFS) | AES-256-XTS for contents; names use AES-256-CBC-CTS or AES-256-HCTR2; Adiantum for both | Little-endian data-unit index as the tweak; per-file keys derived with HKDF-SHA512 under v2 policies; inline encryption hardware can replace the CPU path on ext4 and f2fs with the `inlinecrypt` mount option | No. The doc says authenticated modes are not supported and does not guarantee authenticity | [fscrypt](https://docs.kernel.org/filesystems/fscrypt.html) |
| dm-crypt | `aes-xts-plain64` in the doc's example | Sector number as the IV; optional dm-integrity adds per-sector integrity metadata | No by default | [dm-crypt](https://docs.kernel.org/admin-guide/device-mapper/dm-crypt.html) |
| BitLocker | XTS-AES; AES-CBC is also listed | Not covered by the cited page | Not stated on the cited page | [BitLocker configure](https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/configure) |
| APFS | AES-XTS | Per-file key wrapped with the NIST AES key wrap algorithm, then wrapped with one of several class keys | Not stated on the cited page | [Data protection](https://support.apple.com/guide/security/data-protection-overview-secf6276da8a/web), [key wrap](https://support.apple.com/guide/security/data-protection-sece8608431d/web) |
| VeraCrypt | XTS | Not covered by the cited page | Not stated on the cited page | [Modes of operation](https://veracrypt.io/en/Modes%20of%20Operation.html) |
| bcachefs | ChaCha20/Poly1305 | Not covered by the cited page | Yes, Poly1305 | [Encryption](https://bcachefs.org/Encryption/) |

## Why each mode

- GCM and CCM need a 128-bit block cipher ([SP 800-38D](https://csrc.nist.gov/pubs/sp/800/38/d/final), [SP 800-38C](https://csrc.nist.gov/pubs/sp/800/38/c/upd1/final)). MKV-256 has no GCM or CCM.
- XTS is length-preserving: a sector encrypts to the same size, so it has no room for a tag. IEEE 1619 defines XTS. [SP 800-38E](https://csrc.nist.gov/pubs/sp/800/38/e/final) approves XTS only with AES; XTS over MKV-128 is an inference, as for GCM.
- CTS keeps names length-preserving: ciphertext stealing encrypts the final partial block without padding ([SP 800-38A addendum](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a-add.pdf)).
- Key wrap protects per-file keys stored in metadata. The wrapping key also checks integrity on unwrap ([SP 800-38F](https://csrc.nist.gov/pubs/sp/800/38/f/final)). KW and KWP need a 128-bit block cipher.
- Limits: GCM with random 96-bit IVs allows at most 2^32 invocations per key ([SP 800-38D](https://csrc.nist.gov/pubs/sp/800/38/d/final)). Truncated GCM tags are for restricted uses only ([SP 800-38D](https://csrc.nist.gov/pubs/sp/800/38/d/final)). CCM tags are 4 to 16 bytes ([SP 800-38C](https://csrc.nist.gov/pubs/sp/800/38/c/upd1/final)). An XTS data unit is at most 2^20 blocks ([SP 800-38E](https://csrc.nist.gov/pubs/sp/800/38/e/final)).

## MKV in a ZFS-style design

This section is inferred from publicly available reference material and publicly announced information. MKV-128 with a 256-bit key can replace AES unchanged inside GCM, keeping the 96-bit nonce, the 16-byte tag, the per-block salt and the dedup framing. CCM is an optional alternative with the same block size. MKV-256 has no standard GCM or XTS, so a ZFS-style design uses MKV-128 only.

## MKV in a sector-layer design

XTS over MKV-128, with the sector number as the tweak. The XTS data-unit limit applies. Like the other sector-layer systems, this design has no authentication. A design that must detect tampering needs an integrity layer outside the mode, such as dm-integrity.

## Role to library API

| Role | Library API |
| --- | --- |
| CBC | `MkvCipher.EncryptCbc`, `MkvCipher.DecryptCbc` |
| CBC without padding (ESSIV-style sector data) | `MkvCipher.EncryptCbc`, `MkvCipher.DecryptCbc` with `PaddingMode.None` |
| CBC-CTS: file names, fscrypt-style | `MkvCipher.EncryptCbcCts`, `MkvCipher.DecryptCbcCts` |
| CTR | `MkvCipher.TransformCtr` |
| CTR then HMAC-SHA256 with associated data | `MkvCtrHmac.Encrypt`, `MkvCtrHmac.Decrypt` |
| Key wrap: per-file or per-dataset keys | `MkvCipher.EncryptKeyWrap`, `MkvCipher.DecryptKeyWrap` (KW, multiple of 8 bytes); `MkvCipher.EncryptKeyWrapPadded`, `MkvCipher.DecryptKeyWrapPadded` (KWP, any length). `Mkv128` only |
