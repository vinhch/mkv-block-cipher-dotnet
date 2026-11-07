# Security

Security design, key handling, mode rules and limits for this library. Read it before you use the library to protect data: the library has not been independently audited.

## Constant-time design

`MkvEngine.ConstantTime` is the default. It is designed so that no branch and no memory index depends on secret data: keys, round keys or block state. Each part keeps that rule in its own way.

- S-box on x64 without GFNI, with SSSE3, and in the batch kernels when AVX is absent: each table row is a 16-entry byte shuffle. Every row is read for every byte, and a compare keeps the row that the high nibble selects.
- S-box on ARM64: AdvSimd table lookups over tables held in registers, so no load address depends on the data.
- S-box in the scalar fallback: all 256 entries are read for every byte, and a mask keeps the matching entry.
- S-box on x64 with GFNI: the single-block path, and the batch kernels when AVX is present, run the subfield evaluation in `algorithm.md` as GFNI affine and multiply instructions, so no load address depends on the data. Zero cases select between two results instead of branching. The branches test the CPU flag and the layer direction, never the data.
- Mix on x64 with GFNI: one affine instruction per constant. Without GFNI: two nibble shuffles and an XOR. On ARM64: nibble lookups. In the scalar fallback: shifts and XORs. The only branch tests the public matrix constant, never the data.
- AVX-512 engine (`X64Avx512Engine`, 64 blocks per batch in 512-bit vectors): the S-box is a VPERMI2B table lookup when the CPU has AVX-512 VBMI, and the GFNI S-box at 512 bits otherwise. Mix is one 512-bit affine instruction per constant. Neither path branches or indexes memory by data.
- CBC padding check: every byte of the last block is read, and the result is built from masks.
- Key wrap unwrap (`DecryptKeyWrapPadded`): every byte of the padded output is read into one mask, and the length and prefix checks run before the one decision. The MLI is compared through a sign mask, not a branch. KW checks the initial value with `FixedTimeEquals`.
- Tag check in `MkvCtrHmac`: `CryptographicOperations.FixedTimeEquals`.

The test suite has no timing test, so this is a design property, not a measured one.

The AVX-512 engine needs `Vector512.IsHardwareAccelerated`, AVX-512BW and GFNI at 512 bits. The first follows .NET's default: where .NET does not use 512-bit vectors by default, the 256-bit engines run. `DOTNET_PreferredVectorBitWidth=256` is the opt-out. The engine has not been run: no AVX-512 hardware and no Intel SDE run have been done for it, so its correctness and constant-time behavior are unverified. It is not measured on real hardware.

Vector registers are not cleared after use, zmm registers included, as with the ymm registers today. Only the stack copies of a batch are cleared.

`MkvEngine.VariableTime` is variable time by design. Its table lookups index memory by data bytes, so timing depends on the key and the input. Use it only for offline or batch work on a host with no untrusted co-resident code. Do not use it on multi-tenant servers, on cloud VMs, or anywhere an attacker can measure timing.

## Key handling

- The constructor expands the key once into round keys and keeps no copy of the key.
- Round keys sit in a pinned array, so the GC cannot compact the array and leave an unzeroed copy behind.
- `Dispose` zeroes the round keys. Every method then throws `ObjectDisposedException`. A second `Dispose` does nothing.
- `MkvCtrHmac` takes a 32-byte key and derives two keys with HKDF-SHA256 and an empty salt: one for the cipher and one for the MAC. Each info string names its purpose, block size and revision. The derived keys are zeroed after construction. The MAC state keeps its own copy of the MAC key until `Dispose`.
- The library does not zero the buffers you pass in, with one exception: the destination of a failed decrypt is zeroed. Zero your own keys, plaintext and temporary buffers when you finish with them.

## Mode rules

- `EncryptBlock` and `DecryptBlock` process one block with no chaining. For messages, use a mode. Equal plaintext blocks give equal ciphertext blocks under the single-block call.
- CBC (`EncryptCbc`, `DecryptCbc`) is unauthenticated. A changed ciphertext bit garbles its block and flips one bit in the next block. A padding failure raises one generic `CryptographicException`, but success and failure remain observable. If an attacker can see that outcome for ciphertexts they choose, CBC is open to padding-oracle attacks.
- CBC with `PaddingMode.None` takes whole blocks and adds no padding. Under one IV, the same plaintext prefix gives the same ciphertext prefix, and nothing detects a change. Use it only where the IV is unique per sector or message and the length is fixed by the caller.
- CBC ciphertext stealing (`EncryptCbcCts`, `DecryptCbcCts`) is unauthenticated and length-preserving: the output is the input length, with no padding and no tag. A changed ciphertext bit is not detected. Under one IV, the same plaintext prefix gives the same ciphertext prefix, up to the last two blocks, which are swapped. The length is visible. Use it where the format needs deterministic output of the same length, such as file names. Elsewhere use `EncryptCbc` with a random IV, or `MkvCtrHmac`.
- CTR (`TransformCtr`) is unauthenticated. Encrypting and decrypting are the same call. A reused initial counter under one key reveals the XOR of the two plaintexts.
- XTS (`MkvXts`) is unauthenticated and length-preserving. A changed ciphertext block garbles its own 16-byte block, or the last two blocks when the data unit has a partial tail, and nothing detects it. Use it for sector-layer storage where the format has no room for a tag. Data that crosses a trust boundary needs `MkvCtrHmac`.
- `MkvCtrHmac` is encrypt-then-MAC: CTR with the block cipher, then HMAC-SHA256 over the associated data, the nonce, the ciphertext, and both lengths as 64-bit values. Use it for data that crosses a trust boundary. Decrypt verifies the tag before it decrypts anything. A tag mismatch zeroes the destination and throws one generic `CryptographicException`.
- Key wrap (`EncryptKeyWrap`, `EncryptKeyWrapPadded` and their decrypt methods) wraps key data under a key-encryption key, for example per-file keys stored in metadata. It is deterministic: the same key-encryption key and key data give the same output. It needs a 128-bit block, so `Mkv256` throws `InvalidOperationException`.
- Key wrap detects a changed wrapped key on unwrap: KW checks a 64-bit initial value, and KWP checks a 32-bit prefix, a length field and zero padding. A failed check zeroes the destination and throws one generic `CryptographicException`.
- Key wrap has no associated data: it does not bind a wrapped key to a file, dataset or other context. Keep that binding in the metadata.
- Key wrap reveals the key length. KW output is the key length plus 8 bytes. KWP output reveals the key length only up to a multiple of 8.
- Use a key-encryption key only for key wrap, not for `EncryptBlock`, CBC or CTR.

## Nonces, IVs and counters

- CBC IV: one block, random for each message, never reused under one key. The exception is CBC ciphertext stealing for file names, which is deterministic by design: its IV is fixed per key and context, as file-name encryption does. The IV is not secret, but the same key and IV must not protect data other than file names.
- CTR initial counter: never reuse a counter range under one key. A random initial counter per message is safe only while the total blocks under one key stay far below 2^64 for `Mkv128` and 2^128 for `Mkv256`, the birthday bound on the block size.
- XTS data unit number: with the key, it selects the tweak. Use each number once per key. Reusing one under one key makes equal plaintext blocks at the same positions encrypt to equal ciphertext blocks, which reveals which blocks changed.
- `MkvCtrHmac` nonce: `BlockSizeBytes - 4` bytes, which is 12 bytes for `Mkv128` and 28 bytes for `Mkv256`. Never reuse a nonce under one key. With 96-bit random nonces, the chance of a repeat reaches about 2^-33 at 2^32 messages under one key, so keep each key well below that count.

## Limits

| Limit | Value | Past the limit |
| --- | --- | --- |
| `MkvCtrHmac` message | 2^32 - 1 blocks: 2^36 - 16 bytes (about 64 GiB) for `Mkv128`, 2^37 - 32 bytes (about 128 GiB) for `Mkv256` | `ArgumentException`, no output |
| CTR counter | The block count must not carry the counter past all-ones | `ArgumentException`, no output |
| `MkvCtrHmac` tag | Exactly 32 bytes. Truncation is not supported. | `ArgumentException` |
| Key wrap length | KW: a multiple of 8 bytes, at least 16 for wrap and at least 24 for unwrap. KWP: at least 1 byte to wrap, at least 16 to unwrap. `Mkv128` only. | `ArgumentException`, or `InvalidOperationException` on `Mkv256` |
| Key wrap output | An output that does not fit in an `int`: `GetKeyWrapPaddedLength` throws | `ArgumentOutOfRangeException` |
| XTS data unit | 16 bytes to 2^20 blocks (16 MiB) | `ArgumentException`, no output |
| Key length | `Mkv128`: 16, 24 or 32 bytes. `Mkv256`: 32, 48 or 64 bytes. `MkvCtrHmac`: 32 bytes. `MkvXts`: 32 or 64 bytes, with two different halves. | `ArgumentException` |

The unwrap destination must hold at least `ciphertext.Length - 8` bytes. `TryDecryptKeyWrapPadded` returns `false` for a shorter destination; the other overloads throw `ArgumentException`.

## Concurrency

- `MkvCipher` block, CBC, CTR and key-wrap methods are safe to call concurrently after construction. `Dispose` must not overlap them.
- `MkvXts` methods are safe to call concurrently after construction. `Dispose` must not overlap them.
- `MkvCtrHmac` is not thread-safe. Calls must not overlap. Use one instance per thread, or lock around it.

## Audit status

The library has not been independently audited. Get an independent review before you rely on it for data you cannot afford to expose.
