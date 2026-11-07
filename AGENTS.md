# Agent guide

MkvBlockCipher is a .NET library (`net10.0`) for the MKV block cipher: `Mkv128` and `Mkv256` blocks, with block, CBC (including ciphertext stealing), CTR and CTR-then-HMAC modes, GCM (`Mkv128` only), CCM (`Mkv128` only), AES key wrap (KW and KWP, `Mkv128` only), and XTS (`Mkv128` only). Correctness is the bar: a change is right when every engine still produces the reference outputs, and the default engine stays constant-time. The repository is licensed for viewing only (`LICENSE`): never describe it as open source.

Public types, all in `src/MkvBlockCipher/`:

| Type | Role |
| --- | --- |
| `MkvCipher` | Block, CBC (PKCS#7, unpadded or ciphertext stealing), CTR and key wrap (KW, KWP) operations for one key |
| `MkvCtrHmac` | CTR then HMAC-SHA256 with associated data, 32-byte key and tag |
| `MkvXts` | IEEE 1619 XTS over one data unit, 32- or 64-byte key (data half and tweak half), `Mkv128` only |
| `MkvGcm` | GCM (SP 800-38D) over MKV-128: 16, 24 or 32-byte key, 12-byte nonce, 12 to 16-byte tag, `Mkv128` only |
| `MkvCcm` | CCM (SP 800-38C) over MKV-128: 16, 24 or 32-byte key, 7 to 13-byte nonce, 4 to 16-byte even tag, `Mkv128` only |
| `MkvBlockSize` | `Mkv128` (16-byte block) or `Mkv256` (32-byte block) |
| `MkvRevision` | `Rev2024` (earlier draft) or `Rev2025` (default) |
| `MkvEngine` | `ConstantTime` (default) or `VariableTime` (table lookups, timing depends on data) |

## Documents

| Document | Read it when | Update it when |
| --- | --- | --- |
| `docs/algorithm.md` | before touching anything in `Primitives/` or a round kernel: the algorithm, tables and test vectors | the algorithm, a table or a test vector changes |
| `docs/security.md` | before touching an engine, a mode or key handling: constant-time design, mode rules, limits | an engine or S-box path changes, or its verification status changes |
| `docs/benchmarks.md` | before a performance change: how to run and read the numbers | benchmark numbers change |
| `docs/file-systems.md` | before designing file or disk encryption on this library | a mode is added or a cited system changes |
| `README.md` | for the public API, engines and the script list | the public API, scripts or CI change |

Some facts are copied across files and must change together:

- Benchmark numbers: `docs/benchmarks.md` and the README Benchmarks section. Only `docs/benchmarks.md` notes that the numbers predate the current kernels.
- AVX-512 engine status (unverified): README Engines and `docs/security.md`.
- Rev2025 vectors: `docs/algorithm.md`, `Rev2025Vectors.cs`, `samples/MkvBlockCipher.AotSmoke/Program.cs`.

## Correctness rules

- `docs/algorithm.md` is the reference for the algorithm and describes it as implemented. An algorithm change updates it in the same commit; code and doc disagreeing is a bug.
- Expected values that come from reference material never change to make a test pass: the Rev2025 ciphertexts, RK[1] prefixes and the one sourced last round key, and all Rev2024 data. Values this project computed (the other Rev2025 last round keys, the CTR-HMAC frozen vector) may change, with the reason in the commit.
- A new engine goes into both `EngineFactory.Create` and `EngineFactory.AllSupported`. Parity against `ScalarEngine` (`EngineParityTests`) is what covers every engine class. Known-answer tests reach `ScalarEngine`, `TableEngine` and the `ConstantTime` engine that `Create` picks on the host; other SIMD engines rely on parity.
- Tests skip engines the host cannot run (AVX-512, ARM64), so a green local run proves nothing for them. The AVX-512 engine is unverified: `scripts/test-sde` runs the tests under Intel SDE, and CI does not run it. CI fails the ARM64 leg if its ARM64 tests do not run.
- Official AES vectors from NIST, IEEE 1619 and RFCs never change to make a test pass. Frozen MKV mode vectors are project-computed and may change with the reason in the commit.

## Constant-time and performance rules

- `ConstantTime` paths, engines and modes never branch on or index memory by secret data: keys, round keys, H, tweaks, block state, tags and unwrapped key bytes. Branches test CPU flags or public values (lengths, block counts, revision, layer direction). `TableEngine` is the only variable-time engine; it backs `MkvEngine.VariableTime` and nothing else.
- No heap allocation in round loops or span paths: scratch is `stackalloc` per call; tables are `static ReadOnlySpan<byte>` properties over constant data, or `static readonly` fields built once. The `byte[]` overloads allocate their result, and `DecryptCbc` also a scratch buffer of the ciphertext length, and `DecryptKeyWrapPadded` a scratch buffer of the ciphertext length minus 8, because the integrity check runs after unwrap. `MkvCtrHmac` is the one exception to the span-path rule: a call rents a pooled `IncrementalHash`, and the pool allocates only when concurrent calls outgrow it, so a warm single-threaded call allocates nothing.
- In encryption and decryption, virtual dispatch through `BlockEngine` happens at most once per block or batch, never per round; engine classes are sealed. The key schedule is the exception: it calls `engine.Round` 4R times, once per key.
- Nothing enforces these rules but review: no analyzer or test checks allocation, dispatch or timing.
- Measure before and after a performance change (`scripts/bench`); the benchmark project refuses non-optimized builds.

## Legal wording

- For MKV reference material: describe sources only in general terms: "publicly available reference material" or "publicly announced information".
- For MKV reference material: never point at a specific existing document: no document number, title, URL or file name, in code, comments, tests, docs or commits. A bare generic abbreviation such as TCVN is fine.
- For MKV reference material: never commit reference documents.
- Public standards may be named and linked: NIST SPs, RFCs, IEEE 1619. Links go only to primary sources, plus Wikipedia as the one allowed secondary source: NIST CSRC and nvlpubs, RFC Editor, kernel.org, OpenZFS, cryptsetup, Microsoft Learn, Apple Platform Security, VeraCrypt, bcachefs.org, Wikipedia.

## Layout

- `src/MkvBlockCipher/`: public types at the root; `Kernels/` holds the engines (`ScalarEngine`, `TableEngine`, `X64/` with SSSE3, GFNI and AVX-512 paths, `Arm64/` with AdvSimd); `Modes/` holds CBC, CTR, CCM, GCM and GHASH, key wrap, XTS, padding and CTR-HMAC key derivation; `Primitives/` holds tables, parameters and the key schedule.
- `tests/MkvBlockCipher.Tests/`: xUnit v3 on Microsoft.Testing.Platform, mirroring the source folders; reference values in `TestData/`.
- `benchmarks/MkvBlockCipher.Benchmarks/`: BenchmarkDotNet, Release only.
- `samples/MkvBlockCipher.AotSmoke/`: native AOT publish check.

## Commands

The SDK is pinned in `global.json`. Warnings are errors in every project (`Directory.Build.props`), and `.editorconfig` style is enforced in the build.

| Task | Command |
| --- | --- |
| Build | `scripts/build.sh [Debug\|Release]` |
| Test | `scripts/test.sh [Debug\|Release] [args]` |
| Lint | `scripts/lint.sh` (`dotnet format --verify-no-changes`) |
| Coverage | `scripts/coverage.sh [Debug\|Release]`, writes an HTML report under artifacts |
| Benchmarks | `scripts/bench.sh [--quick\|--cold\|--precise]` |
| Native AOT smoke | `scripts/aot-smoke.sh` |
| Tests under Intel SDE | `scripts/test-sde.sh` with `SDE_PATH` set |

Scripts come in `.sh` and `.ps1` pairs with the same arguments; change both together. Two known differences: `coverage.ps1` does not forward extra arguments, and `aot-smoke` publishes for linux-x64 in `.sh` and win-<arch> in `.ps1`.

CI in `.github/workflows/`: `build.yml` (Ubuntu, Windows, macOS), `test.yml` (test legs for default, scalar, GFNI-off, AVX2-off and AVX2-and-GFNI-off kernels plus ARM64 macOS, then coverage and AOT smoke jobs), `lint.yml`, and `release.yml` (packs on a `v*` tag).

## Commits

Conventional commits (`feat:`, `fix:`, `perf:`, `docs:`, `test:`, `build:`, `ci:`, `chore:`), optional scope (`perf(arm64):`). English for code, comments, docs and commit messages. A performance change states its measured numbers in the body.
