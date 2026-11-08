# MkvBlockCipher

MkvBlockCipher is a .NET library for the MKV block cipher, with 128-bit and 256-bit blocks, CBC (padded, unpadded or ciphertext stealing) and CTR modes, an authenticated mode (CTR with HMAC-SHA256), GCM (SP 800-38D authenticated encryption, 128-bit blocks only), CCM (SP 800-38C authenticated encryption, 128-bit blocks only), MKV key wrap (KW and KWP, 128-bit blocks only), and XTS (IEEE 1619 sector encryption, 128-bit blocks only).

This is an unofficial implementation and has not been audited. Read [DISCLAIMER.md](DISCLAIMER.md) and [docs/security.md](docs/security.md) before you protect data with it.

## Installation

The library targets `net10.0`. It is not published to nuget.org. Reference the project directly, or pack it and install the local package:

```bash
dotnet pack src/MkvBlockCipher/MkvBlockCipher.csproj -c Release
```

The `.nupkg` and `.snupkg` land in `src/MkvBlockCipher/bin/Release/`.

## Quick start

```csharp
using System.Security.Cryptography;
using MkvBlockCipher;

byte[] key = RandomNumberGenerator.GetBytes(32);   // valid for both block sizes
byte[] message = "hello"u8.ToArray();

using (var cipher = new MkvCipher(MkvBlockSize.Mkv128, key))
{
    // One block, no mode. Both spans must be BlockSizeBytes long.
    byte[] block = RandomNumberGenerator.GetBytes(cipher.BlockSizeBytes);
    byte[] encryptedBlock = new byte[cipher.BlockSizeBytes];
    cipher.EncryptBlock(block, encryptedBlock);

    // CBC with PKCS#7 padding. A new random IV for every message.
    byte[] iv = RandomNumberGenerator.GetBytes(cipher.BlockSizeBytes);
    byte[] ciphertext = cipher.EncryptCbc(message, iv);
    byte[] plaintext = cipher.DecryptCbc(ciphertext, iv);

    // CTR. A new random initial counter for every message. Unauthenticated.
    byte[] counter = RandomNumberGenerator.GetBytes(cipher.BlockSizeBytes);
    byte[] stream = cipher.TransformCtr(counter, message);
}

// Authenticated: CTR plus HMAC-SHA256. A nonce must never repeat under one key.
using var aead = new MkvCtrHmac(MkvBlockSize.Mkv256, key);
byte[] nonce = RandomNumberGenerator.GetBytes(aead.NonceSizeBytes);
byte[] encrypted = new byte[message.Length];
byte[] tag = new byte[MkvCtrHmac.TagSizeBytes];
aead.Encrypt(nonce, message, encrypted, tag);

byte[] decrypted = new byte[encrypted.Length];
aead.Decrypt(nonce, encrypted, tag, decrypted);
```

Use `MkvCtrHmac`, `MkvGcm` or `MkvCcm` for data from untrusted sources. Limits and key handling are in [docs/security.md](docs/security.md).

## API reference

Namespace `MkvBlockCipher`. Every type and member has XML documentation; this section lists the surface.

### Enums

| Type | Values |
| --- | --- |
| `MkvBlockSize` | `Mkv128` (16-byte block), `Mkv256` (32-byte block) |
| `MkvRevision` | `Rev2024`, `Rev2025` (default). See [Revisions](#revisions) |
| `MkvEngine` | `ConstantTime` (default), `VariableTime`. See [Engines](#engines) |

Key lengths are 16, 24 or 32 bytes for `Mkv128`, and 32, 48 or 64 bytes for `Mkv256`.

### MkvCipher

Block cipher and modes under one key. Implements `IDisposable`.

| Member | Notes |
| --- | --- |
| `MkvCipher(MkvBlockSize, ReadOnlySpan<byte> key, MkvRevision = Rev2025, MkvEngine = ConstantTime)` | Runs the key schedule once. The key is not kept |
| `int BlockSizeBytes` | 16 or 32 |
| `void EncryptBlock(source, destination)`, `void DecryptBlock(source, destination)` | One block, no mode |
| `int GetCiphertextLengthCbc(int plaintextLength, PaddingMode paddingMode = PKCS7)` | CBC output size. PKCS#7 always adds between 1 and `BlockSizeBytes` bytes. `PaddingMode.None` returns the input length and rejects a partial block |
| `byte[] EncryptCbc(plaintext, iv, paddingMode = PKCS7)`, `int EncryptCbc(plaintext, iv, destination, paddingMode = PKCS7)`, `bool TryEncryptCbc(plaintext, iv, destination, out bytesWritten, paddingMode = PKCS7)` | CBC with PKCS#7 padding, or with `PaddingMode.None` for whole blocks only. Other modes throw `ArgumentOutOfRangeException` |
| `byte[] DecryptCbc(ciphertext, iv, paddingMode = PKCS7)`, `int DecryptCbc(ciphertext, iv, destination, paddingMode = PKCS7)`, `bool TryDecryptCbc(ciphertext, iv, destination, out bytesWritten, paddingMode = PKCS7)` | CBC with padding removed. Bad padding throws `CryptographicException`. `PaddingMode.None` returns the ciphertext length and does not check padding |
| `byte[] EncryptCbcCts(plaintext, iv)`, `void EncryptCbcCts(plaintext, iv, destination)`, `byte[] DecryptCbcCts(ciphertext, iv)`, `void DecryptCbcCts(ciphertext, iv, destination)` | CBC ciphertext stealing (CS3): the output is the input length and no padding is added. Input is at least `BlockSizeBytes`; the destination must match the input length. One-block input is plain CBC. Unauthenticated |
| `void TransformCtr(initialCounter, source, destination)`, `byte[] TransformCtr(initialCounter, source)` | CTR keystream XOR. Encryption and decryption are the same call |
| `byte[] EncryptKeyWrap(plaintext)`, `void EncryptKeyWrap(plaintext, destination)` | MKV key wrap (the RFC 3394 construction, SP 800-38F). Input is a multiple of 8 bytes, at least 16. Output is 8 bytes longer. `Mkv128` only: `Mkv256` throws `InvalidOperationException` |
| `byte[] DecryptKeyWrap(ciphertext)`, `int DecryptKeyWrap(ciphertext, destination)` | Unwraps MKV key wrap. A failed integrity check zeroes the destination and throws `CryptographicException` |
| `byte[] EncryptKeyWrapPadded(plaintext)`, `void EncryptKeyWrapPadded(plaintext, destination)`, `int GetKeyWrapPaddedLength(plaintextLength)` (static) | MKV key wrap with padding (the RFC 5649 construction). Any non-empty input. The output is the input rounded up to 8 bytes, plus 8 bytes. `Mkv128` only |
| `byte[] DecryptKeyWrapPadded(ciphertext)`, `int DecryptKeyWrapPadded(ciphertext, destination)`, `bool TryDecryptKeyWrapPadded(ciphertext, destination, out bytesWritten)` | Unwraps MKV key wrap with padding. The key length comes from the wrapped value. A failed check throws `CryptographicException`. `TryDecrypt` returns `false` when the destination is shorter than `ciphertext.Length - 8` |
| `void Dispose()` | Zeroes the round keys. Later calls throw `ObjectDisposedException` |

### MkvCtrHmac

Authenticated mode: CTR, then HMAC-SHA256 over the associated data, the nonce and the ciphertext. Implements `IDisposable`.

| Member | Notes |
| --- | --- |
| `MkvCtrHmac(MkvBlockSize, ReadOnlySpan<byte> key, MkvRevision = Rev2025, MkvEngine = ConstantTime)` | The key must be exactly 32 bytes. Sub-keys are derived with HKDF |
| `int NonceSizeBytes` | `BlockSizeBytes - 4`: 12 or 28 |
| `const int TagSizeBytes` | 32 |
| `void Encrypt(nonce, plaintext, ciphertext, tag, associatedData = default)` | `ciphertext` has the length of `plaintext` |
| `void Decrypt(nonce, ciphertext, tag, plaintext, associatedData = default)` | Verifies the tag before decrypting. On failure zeroes `plaintext` and throws |
| `void Dispose()` | As for `MkvCipher` |

### MkvXts

IEEE 1619 XTS for sector-layer encryption: one data unit per call, length-preserving, no authentication. Implements `IDisposable`.

| Member | Notes |
| --- | --- |
| `MkvXts(ReadOnlySpan<byte> key, MkvRevision = Rev2025, MkvEngine = ConstantTime)` | The key is 32 or 64 bytes. The first half is the data key, the second the tweak key. The halves must differ. `Mkv128` only |
| `void Encrypt(ulong dataUnitNumber, plaintext, ciphertext)` | Data unit of 16 bytes to 2^20 blocks. The output has the input length. May be in place |
| `void Decrypt(ulong dataUnitNumber, ciphertext, plaintext)` | As `Encrypt`. Does not authenticate: a changed ciphertext decrypts without an error |
| `void Dispose()` | Zeroes both round-key sets. Later calls throw `ObjectDisposedException` |

### MkvGcm

GCM (SP 800-38D) with MKV-128 as the block cipher: authenticated encryption with a 12-byte nonce. Implements `IDisposable`.

| Member | Notes |
| --- | --- |
| `MkvGcm(ReadOnlySpan<byte> key, int tagSizeInBytes, MkvRevision = Rev2025, MkvEngine = ConstantTime)` | The key is 16, 24 or 32 bytes. The tag is 12 to 16 bytes. `Mkv128` only |
| `static KeySizes NonceByteSizes`, `static KeySizes TagByteSizes` | Nonce: exactly 12 bytes. Tag: 12 to 16 bytes |
| `int TagSizeInBytes` | Fixed at construction |
| `void Encrypt(nonce, plaintext, ciphertext, tag, associatedData = default)` | `ciphertext` has the length of `plaintext`. May be in place |
| `void Decrypt(nonce, ciphertext, tag, plaintext, associatedData = default)` | Verifies the tag before decrypting. On failure zeroes `plaintext` and throws |
| `void Dispose()` | As for `MkvCipher` |

### MkvCcm

CCM (SP 800-38C) with MKV-128 as the block cipher: authenticated encryption with a 7 to 13-byte nonce. The tag length comes from the `tag` span. Implements `IDisposable`.

| Member | Notes |
| --- | --- |
| `MkvCcm(ReadOnlySpan<byte> key, MkvRevision = Rev2025, MkvEngine = ConstantTime)` | The key is 16, 24 or 32 bytes. `Mkv128` only |
| `static KeySizes NonceByteSizes`, `static KeySizes TagByteSizes` | Nonce: 7 to 13 bytes. Tag: 4 to 16 bytes, an even length |
| `void Encrypt(nonce, plaintext, ciphertext, tag, associatedData = default)` | `ciphertext` has the length of `plaintext`. May be in place. The payload limit depends on the nonce length: see [docs/security.md](docs/security.md#limits) |
| `void Decrypt(nonce, ciphertext, tag, plaintext, associatedData = default)` | Decrypts, then verifies the tag. On failure zeroes `plaintext` and throws |
| `void Dispose()` | As for `MkvCipher` |

### Errors

| Exception | When |
| --- | --- |
| `ArgumentException` | A length is wrong, or two buffers partially overlap. `ParamName` names the argument |
| `CryptographicException` | Bad padding, a bad tag or a failed key-wrap integrity check. The message is always "The data could not be decrypted." |
| `InvalidOperationException` | Key wrap methods on an `Mkv256` instance |
| `ObjectDisposedException` | A method is called after `Dispose` |

## Advanced usage

- **Allocation.** The span overloads allocate nothing per call, except that `MkvCtrHmac` allocates when concurrent calls grow its pool. The `byte[]` overloads allocate the result. Create one cipher per key and reuse it.
- **Output sizes.** Use `BlockSizeBytes` for one block, `GetCiphertextLengthCbc` for CBC, `GetKeyWrapPaddedLength` for KWP, and the input length for CBC ciphertext stealing. The `Try` methods return `false` and write nothing when the destination is too short. The other overloads throw `ArgumentException`.
- **In-place.** The same start for source and destination is allowed in every mode. Partial overlap throws.
- **Counters.** `TransformCtr` takes an initial counter of one block. A call whose counter would wrap past all-ones throws before it writes anything.
- **Associated data.** `MkvCtrHmac`, `MkvGcm` and `MkvCcm` authenticate the associated data without encrypting it. Pass the same bytes to `Decrypt`.
- **Concurrency.** `MkvCipher` block, CBC, CTR and key-wrap calls may run concurrently on one instance, but `Dispose` must not overlap them. `MkvCtrHmac`, `MkvXts`, `MkvGcm` and `MkvCcm` calls may run concurrently, and `Dispose` must not overlap them.
- **Limits.** Message length limits and nonce rules are in [docs/security.md](docs/security.md#limits).

## Revisions

Two revisions, `Rev2024` and `Rev2025` (default), share the S-box, the mix matrices and the round structure. `Rev2025` uses one more round, rotates each word in MixWords and adds round constants to the key schedule. The round count for each block size and key length is in [docs/algorithm.md](docs/algorithm.md#revisions).

## Engines

- `MkvEngine.ConstantTime` (default) is designed so that no branch or memory index depends on secret data. It uses an AVX-512 engine with 64 blocks per batch where the CPU and .NET allow 512-bit vectors, x64 SSSE3 kernels (with AVX2 and GFNI where the CPU has them), ARM64 AdvSimd kernels, or a scalar fallback.
- The AVX-512 engine has run on AVX-512 hardware in CI, first on an Intel Xeon Platinum 8370C, and runs there whenever the runner supports it, meaning AVX-512F, BW, CD, DQ, VL and GFNI. AVX-512 is not selectable on GitHub-hosted runners, so that coverage is opportunistic: the `default` Ubuntu leg probes the CPU, runs the AVX-512 guard tests when the engine is eligible, and records the CPU model and the verdict in its job summary. The engine has not been run under Intel SDE and is not measured. `DOTNET_PreferredVectorBitWidth=256` turns it off.
- `MkvEngine.VariableTime` is faster and variable time by design. Use it only for offline or batch work on a host with no untrusted co-resident code. Do not use it on multi-tenant servers, on cloud VMs, or anywhere an attacker can measure timing.
- On x64 Windows with a CPU that has GFNI, a default Native AOT publish ran `X64Engine` with AVX2 off and GFNI on (`scripts/aot-smoke.ps1`). A publish limited to `x86-64-v2` reported the same flags, so GFNI does not come from the baseline ISA. A CPU without GFNI has not been tested. `-p:IlcInstructionSet=native` turns AVX2 on.

## Security notes

- The library has not been independently audited.
- Use `MkvCtrHmac`, `MkvGcm` or `MkvCcm` for untrusted data. CBC, CBC ciphertext stealing, CTR and XTS alone are unauthenticated.
- CBC IVs must be random, except that CBC ciphertext stealing for file names is deterministic by design. `MkvCtrHmac`, `MkvGcm` and `MkvCcm` nonces must be unique per key.
- Never reuse a nonce, a CTR counter range or an XTS data unit number under one key.
- Key wrap protects key data under a key-encryption key. Use a key-encryption key only for key wrap, and see the key wrap rules in [docs/security.md](docs/security.md#mode-rules).
- `Dispose` zeroes the round keys. Details and limits are in [docs/security.md](docs/security.md).

## Benchmarks

Throughput in MB/s (10^6 bytes per second) on a 1 MiB payload, with `ConstantTime`, `Rev2025` and the BenchmarkDotNet Default job (no kernel toggles, so the CPU's preferred kernel path runs). Measured on one Intel Core i7-12700H machine running Windows 11.

| Operation | Mkv128 | Mkv256 |
| --- | ---: | ---: |
| CBC encrypt | 27.16 | 18.48 |
| CBC decrypt | 93.21 | 100.30 |
| CTR encrypt | 90.59 | 97.99 |
| CtrHmac encrypt | 83.03 | 80.13 |
| GCM encrypt | 185.09 | n/a |
| XTS encrypt | 273.21 | n/a |

The GCM and XTS rows are from a `--quick` run with a wide Error; see docs/benchmarks.md. They come from a later quick run on the current kernels, so they are not directly comparable with the other rows, which predate them.

The full tables, the kernel-path rows and the VariableTime gate are in [docs/benchmarks.md](docs/benchmarks.md).

## Development

Requirements: the .NET SDK pinned in `global.json`, 10.0.100 or a later 10.0 feature band. Everything else comes from NuGet.

| Script | Does |
| --- | --- |
| `scripts/build.sh [Debug\|Release]` | Builds the solution. Default `Debug` |
| `scripts/test.sh [Debug\|Release] [args]` | Runs the tests. Default `Debug`. Extra arguments go to `dotnet test`; CI adds `--report-github` |
| `scripts/coverage.sh [Debug\|Release]` | Runs the tests with coverage and writes an HTML report to `artifacts/coverage/report/`. Default `Release` |
| `scripts/lint.sh` | `dotnet format --verify-no-changes` |
| `scripts/bench.sh [args]` | Runs the BenchmarkDotNet suite. See [docs/benchmarks.md](docs/benchmarks.md) |

Each script has a `.ps1` twin.

```text
src/MkvBlockCipher/           the library: public API, Modes/, Primitives/, Kernels/ (engines)
tests/MkvBlockCipher.Tests/   xUnit v3 on Microsoft.Testing.Platform; published test vectors in TestData/
benchmarks/                   BenchmarkDotNet project
docs/                         algorithm, security and benchmark notes
```

CI runs in `.github/workflows`. Build runs on Ubuntu, Windows and macOS. Test runs on Ubuntu with the default kernels and with the scalar, GFNI-off, AVX2-off and AVX2-and-GFNI-off paths, plus an ARM64 macOS leg that fails if its ARM64 tests do not run. The `default` Ubuntu leg also probes its runner for the AVX-512 flags the engine needs and records the result in the job summary; the AVX-512 guard tests run only when the engine is eligible. Coverage, lint and the native AOT smoke publish run as their own jobs. All of these run on pushes and pull requests to `main`. Pushing a tag `vX.Y.Z`, optionally with a `-suffix`, packs the library and creates a GitHub Release without the `.nupkg` attached. No package is published anywhere.

## About this implementation

This repository is an independent, unofficial interpretation of the MKV block cipher, based only on publicly available reference material. It is not affiliated with or endorsed by any standards body or the algorithm's designers; see [DISCLAIMER.md](DISCLAIMER.md).

## License

The repository is published for viewing only. Use requires prior written permission from the author. See [LICENSE](LICENSE).
