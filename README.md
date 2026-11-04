# MkvBlockCipher

MkvBlockCipher is a .NET library for the MKV block cipher, with 128-bit and 256-bit blocks, CBC and CTR modes, and an authenticated mode (CTR with HMAC-SHA256).

This is an unofficial implementation and has not been audited. Read [docs/security.md](docs/security.md) before you protect data with it.

## Build

The library targets `net10.0`. The SDK version is pinned in `global.json`.

```bash
bash scripts/build.sh Release
bash scripts/test.sh
bash scripts/lint.sh
dotnet pack src/MkvBlockCipher/MkvBlockCipher.csproj -c Release
```

`dotnet pack` writes the `.nupkg` and `.snupkg` to `src/MkvBlockCipher/bin/Release/`. The package is not published to nuget.org. Use a project reference, or install the local package.

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

Use `MkvCtrHmac` for data from untrusted sources. Limits and key handling are in [docs/security.md](docs/security.md).

## Revisions

Two revisions, `Rev2024` and `Rev2026` (default), share one algorithm and differ in round count, which is 6 to 9. The round count for each block size and key length is in [docs/algorithm.md](docs/algorithm.md#revisions).

## Engines

- `MkvEngine.ConstantTime` (default) is designed so that no branch or memory index depends on secret data. It uses x64 SSSE3 kernels (with AVX2 and GFNI where the CPU has them), ARM64 AdvSimd kernels, or a scalar fallback.
- `MkvEngine.VariableTime` is faster and variable time by design. Use it only for offline or batch work on a host with no untrusted co-resident code. Do not use it on multi-tenant servers, on cloud VMs, or anywhere an attacker can measure timing.

## Security notes

- The library has not been independently audited.
- Use `MkvCtrHmac` for untrusted data. CBC and CTR alone are unauthenticated.
- CBC IVs must be random. `MkvCtrHmac` nonces must be unique per key.
- Never reuse a nonce or a CTR counter range under one key.
- `Dispose` zeroes the round keys. Details and limits are in [docs/security.md](docs/security.md).

## Benchmarks

Throughput in MB/s (10^6 bytes per second) on a 1 MiB payload, with `ConstantTime`, `Rev2026` and the BenchmarkDotNet Default job (no kernel toggles, so the CPU's preferred kernel path runs). Measured on one Intel Core i7-12700H machine running Windows 11.

| Operation | Mkv128 | Mkv256 |
| --- | ---: | ---: |
| CBC encrypt | 26.65 | 18.91 |
| CBC decrypt | 91.66 | 108.65 |
| CTR encrypt | 89.39 | 104.07 |
| CtrHmac encrypt | 86.25 | 81.06 |

The full tables, the kernel-path rows and the VariableTime gate are in [docs/benchmarks.md](docs/benchmarks.md).

## About this implementation

MKV was publicly announced as a proposed Vietnamese national standard block cipher. This repository is an independent interpretation and implementation of MKV, built solely from publicly announced information. It does not reference, reproduce, or link to any external document. It is not affiliated with or endorsed by any standards body or the algorithm's designers, and it has not been independently audited.

## License

The repository is published for viewing only. Use requires prior written permission from the author. See [LICENSE](LICENSE).
