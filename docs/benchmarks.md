# Benchmarks

Baseline MB/s of the span APIs for the block cipher, CBC, CTR and CtrHmac, measured on one machine.

Machine: Intel Core i7-12700H, 20 logical processors, Windows 11 Pro 10.0.26200, .NET 10.0.14.

Setup: the default revision Rev2026 and engine ConstantTime, with a 32-byte key for both block sizes. Under Rev2026 that key length gives 9 rounds for Mkv128 and 7 rounds for Mkv256.

Rows are kernel paths. Default sets no toggle, so it uses every kernel branch the CPU supports. NoHwIntrinsic (`DOTNET_EnableHWIntrinsic=0`) is the only toggle that changes the engine class: it runs the scalar engine. NoGfni (`DOTNET_EnableGFNI=0`) and NoAvx2 (`DOTNET_EnableAVX2=0`) keep the SIMD engine and switch one kernel branch each. NoGfni leaves AVX2 on, and NoAvx2 leaves GFNI on. No row runs the SSSE3-only path with both AVX2 and GFNI off.

All four rows use BenchmarkDotNet's Default job. Each row is its own process with its environment toggle set. MB/s is 10^6 payload bytes per second: the Size column for the mode rows, and the block size for EncryptBlock.

## Run

Full matrix: `bash scripts/bench.sh --filter "*"`. It has 272 rows: two engines, four jobs. The ConstantTime-only matrix of 136 rows took 60 minutes in the recorded run, so expect about twice that. Narrow it with a filter: `bash scripts/bench.sh --filter "*CbcEncrypt*"` for one case, `bash scripts/bench.sh --filter "*CbcEncrypt(BlockSize: Mkv128*"` for one case and block size, or `--filter "*VariableTime*"` for the VariableTime rows. `scripts/bench.ps1` takes the same arguments. `--job Short` adds a fifth job next to the four rows; it does not replace them.

## EncryptBlock

Jobs: all four, see the intro. One block per call, so the table has no size column.

| Job | Block | MB/s |
| --- | --- | ---: |
| Default | Mkv128 | 27.24 |
| Default | Mkv256 | 19.24 |
| NoGfni | Mkv128 | 23.00 |
| NoGfni | Mkv256 | 13.69 |
| NoAvx2 | Mkv128 | 26.41 |
| NoAvx2 | Mkv256 | 18.80 |
| NoHwIntrinsic | Mkv128 | 0.28 |
| NoHwIntrinsic | Mkv256 | 0.34 |

## CbcEncrypt

Jobs: all four, see the intro.

| Job | Block | 16 B | 1 KiB | 64 KiB | 1 MiB |
| --- | --- | ---: | ---: | ---: | ---: |
| Default | Mkv128 | 13.40 | 26.22 | 26.43 | 26.65 |
| Default | Mkv256 | 9.26 | 18.37 | 19.04 | 18.91 |
| NoGfni | Mkv128 | 11.32 | 22.25 | 22.59 | 23.03 |
| NoGfni | Mkv256 | 6.73 | 13.30 | 13.67 | 13.81 |
| NoAvx2 | Mkv128 | 12.91 | 25.36 | 25.75 | 26.10 |
| NoAvx2 | Mkv256 | 9.02 | 18.06 | 18.62 | 18.58 |
| NoHwIntrinsic | Mkv128 | 0.15 | 0.29 | 0.29 | 0.29 |
| NoHwIntrinsic | Mkv256 | 0.17 | 0.34 | 0.35 | 0.35 |

## CbcDecrypt

Jobs: all four, see the intro.

| Job | Block | 16 B | 1 KiB | 64 KiB | 1 MiB |
| --- | --- | ---: | ---: | ---: | ---: |
| Default | Mkv128 | 13.02 | 85.30 | 90.95 | 91.66 |
| Default | Mkv256 | 9.15 | 90.84 | 104.40 | 108.65 |
| NoGfni | Mkv128 | 11.00 | 77.50 | 84.60 | 82.84 |
| NoGfni | Mkv256 | 6.61 | 73.96 | 93.82 | 91.16 |
| NoAvx2 | Mkv128 | 12.61 | 49.99 | 52.47 | 52.72 |
| NoAvx2 | Mkv256 | 9.00 | 57.26 | 64.05 | 62.66 |
| NoHwIntrinsic | Mkv128 | 0.15 | 0.29 | 0.30 | 0.29 |
| NoHwIntrinsic | Mkv256 | 0.17 | 0.32 | 0.35 | 0.35 |

## CtrEncrypt

Jobs: all four, see the intro.

| Job | Block | 16 B | 1 KiB | 64 KiB | 1 MiB |
| --- | --- | ---: | ---: | ---: | ---: |
| Default | Mkv128 | 25.72 | 88.36 | 88.22 | 89.39 |
| Default | Mkv256 | 9.18 | 104.42 | 105.01 | 104.07 |
| NoGfni | Mkv128 | 22.14 | 83.63 | 82.38 | 81.24 |
| NoGfni | Mkv256 | 6.56 | 88.35 | 90.98 | 90.02 |
| NoAvx2 | Mkv128 | 24.48 | 52.12 | 51.39 | 51.57 |
| NoAvx2 | Mkv256 | 8.84 | 62.13 | 62.36 | 62.45 |
| NoHwIntrinsic | Mkv128 | 0.30 | 0.29 | 0.29 | 0.30 |
| NoHwIntrinsic | Mkv256 | 0.17 | 0.35 | 0.35 | 0.34 |

## CtrHmacEncrypt

Jobs: all four, see the intro. Associated data is empty.

| Job | Block | 16 B | 1 KiB | 64 KiB | 1 MiB |
| --- | --- | ---: | ---: | ---: | ---: |
| Default | Mkv128 | 18.09 | 82.26 | 85.89 | 86.25 |
| Default | Mkv256 | 6.42 | 81.47 | 82.50 | 81.06 |
| NoGfni | Mkv128 | 15.76 | 76.95 | 79.27 | 80.32 |
| NoGfni | Mkv256 | 4.76 | 70.05 | 70.21 | 69.85 |
| NoAvx2 | Mkv128 | 17.25 | 50.40 | 50.54 | 50.33 |
| NoAvx2 | Mkv256 | 6.18 | 48.38 | 49.29 | 48.25 |
| NoHwIntrinsic | Mkv128 | 0.30 | 0.30 | 0.29 | 0.29 |
| NoHwIntrinsic | Mkv256 | 0.13 | 0.26 | 0.27 | 0.27 |

## Allocation

In the full run, every span row shows `-` (0 B) except CbcDecrypt, Default, Mkv256, 1 MiB, which showed 5 B per call. A filtered re-run of that row showed `-` (0 B) for the Default row.

## Reading the numbers

Ratios below divide printed cells. Default over NoHwIntrinsic at 1 MiB is 297 to 316 for CtrEncrypt, CtrHmacEncrypt and CbcDecrypt, and 54 to 92 for CbcEncrypt; EncryptBlock is 57 to 97. NoGfni is 7 to 29 percent below Default on the 1 MiB rows and EncryptBlock. NoAvx2 is 40 to 43 percent below Default on the 1 MiB CbcDecrypt, CtrEncrypt and CtrHmacEncrypt rows, and 2 to 3 percent below on EncryptBlock and CbcEncrypt. At Default, Mkv256 is 16 to 19 percent faster than Mkv128 on 1 MiB CtrEncrypt and CbcDecrypt, 6 percent slower on 1 MiB CtrHmacEncrypt, and 29 percent slower on EncryptBlock and 1 MiB CbcEncrypt.

## VariableTime

`MkvEngine.VariableTime` is variable time by design: its table lookups index memory by state bytes, so timing depends on the key and the input. Use it only for offline or batch work on a host with no untrusted co-resident code. Do not use it on multi-tenant servers, cloud VMs, or anywhere an attacker can measure timing.

The speed gate is at least 1.5 times faster than ConstantTime on the Default job, for EncryptBlock or CBC encrypt at 1 KiB or 64 KiB. All six cases below clear it, so the engine is kept.

| Case | Block | ConstantTime | VariableTime | Ratio |
| --- | --- | ---: | ---: | ---: |
| EncryptBlock | Mkv128 | 591.7 ns | 381.2 ns | 1.55 |
| EncryptBlock | Mkv256 | 1,675.9 ns | 604.9 ns | 2.77 |
| CbcEncrypt, 1 KiB | Mkv128 | 39.00 us | 19.53 us | 2.00 |
| CbcEncrypt, 1 KiB | Mkv256 | 55.81 us | 18.19 us | 3.07 |
| CbcEncrypt, 64 KiB | Mkv128 | 2.429 ms | 1.232 ms | 1.97 |
| CbcEncrypt, 64 KiB | Mkv256 | 3.485 ms | 1.117 ms | 3.12 |

Ratio is the ConstantTime mean divided by the VariableTime mean, both from the Default job. In the gate runs, the three toggle jobs stay within 10 percent of the Default row for VariableTime, since the engine uses no SIMD, and every gate row allocates 0 B per call.
