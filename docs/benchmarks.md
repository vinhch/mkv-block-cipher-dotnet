# Benchmarks

The numbers in the sections before GcmEncrypt predate the current kernels, including the GFNI S-box and the AVX-512 engine; the ARM64 kernels and the AVX-512 engine are not measured on real hardware.

Baseline MB/s of the span APIs for the block cipher, CBC, CTR, CtrHmac, GCM and XTS, measured on one machine.

Machine: Intel Core i7-12700H, 20 logical processors, Windows 11 Pro 10.0.26200, .NET 10.0.14.

Setup: the default revision Rev2025 and engine ConstantTime, with a 32-byte key for both block sizes. Under Rev2025 that key length gives 9 rounds for Mkv128 and 7 rounds for Mkv256. Measured on 2026-11-04.

Rows are kernel paths. Default sets no toggle, so it uses the best kernel branch the CPU supports. NoHwIntrinsic (`DOTNET_EnableHWIntrinsic=0`) is the only toggle that changes the engine class: it runs the scalar engine. NoGfni (`DOTNET_EnableGFNI=0`) and NoAvx2 (`DOTNET_EnableAVX2=0`) keep the SIMD engine and switch one kernel branch each. NoGfni leaves AVX2 on, and NoAvx2 leaves GFNI on. No row runs the SSSE3-only path with both AVX2 and GFNI off.

All four jobs use BenchmarkDotNet's Default job. Each job is its own process with its environment toggle set. MB/s is 10^6 payload bytes per second: the Size column for the mode rows, and the block size for EncryptBlock.

## Run

Full matrix: `bash scripts/bench.sh --filter "*"`. It has 336 rows: two engines, four jobs. The ConstantTime-only matrix of 136 rows took 60 minutes in the recorded run. The 272-row matrix from before GcmEncrypt and XtsEncrypt were added took 1 hour 49 minutes on 2026-11-04. Narrow it with a filter: `bash scripts/bench.sh --filter "*CbcEncrypt*"` for one case, `bash scripts/bench.sh --filter "*CbcEncrypt(BlockSize: Mkv128*"` for one case and block size, or `--filter "*VariableTime*"` for the VariableTime rows. `scripts/bench.ps1` takes the same arguments. `--job Short` adds a fifth job next to the four rows; it does not replace them.

## EncryptBlock

Jobs: all four, see the intro. One block per call, so the table has no size column.

| Job | Block | MB/s |
| --- | --- | ---: |
| Default | Mkv128 | 27.32 |
| Default | Mkv256 | 19.80 |
| NoGfni | Mkv128 | 22.70 |
| NoGfni | Mkv256 | 13.28 |
| NoAvx2 | Mkv128 | 26.50 |
| NoAvx2 | Mkv256 | 19.44 |
| NoHwIntrinsic | Mkv128 | 0.29 |
| NoHwIntrinsic | Mkv256 | 0.34 |

## CbcEncrypt

Jobs: all four, see the intro.

| Job | Block | 16 B | 1 KiB | 64 KiB | 1 MiB |
| --- | --- | ---: | ---: | ---: | ---: |
| Default | Mkv128 | 13.44 | 26.64 | 27.30 | 27.16 |
| Default | Mkv256 | 9.43 | 18.19 | 19.12 | 18.48 |
| NoGfni | Mkv128 | 11.09 | 21.99 | 22.52 | 21.48 |
| NoGfni | Mkv256 | 6.35 | 12.61 | 12.85 | 13.12 |
| NoAvx2 | Mkv128 | 13.17 | 26.41 | 26.53 | 25.55 |
| NoAvx2 | Mkv256 | 9.46 | 18.22 | 18.99 | 19.12 |
| NoHwIntrinsic | Mkv128 | 0.15 | 0.29 | 0.29 | 0.29 |
| NoHwIntrinsic | Mkv256 | 0.17 | 0.34 | 0.34 | 0.35 |

## CbcDecrypt

Jobs: all four, see the intro.

| Job | Block | 16 B | 1 KiB | 64 KiB | 1 MiB |
| --- | --- | ---: | ---: | ---: | ---: |
| Default | Mkv128 | 12.77 | 85.91 | 91.48 | 93.21 |
| Default | Mkv256 | 9.08 | 91.24 | 106.51 | 100.30 |
| NoGfni | Mkv128 | 10.55 | 79.28 | 84.75 | 81.58 |
| NoGfni | Mkv256 | 6.32 | 73.52 | 91.64 | 90.98 |
| NoAvx2 | Mkv128 | 12.62 | 51.20 | 53.27 | 52.35 |
| NoAvx2 | Mkv256 | 9.18 | 57.65 | 63.61 | 63.61 |
| NoHwIntrinsic | Mkv128 | 0.15 | 0.29 | 0.29 | 0.28 |
| NoHwIntrinsic | Mkv256 | 0.17 | 0.34 | 0.34 | 0.34 |

## CtrEncrypt

Jobs: all four, see the intro.

| Job | Block | 16 B | 1 KiB | 64 KiB | 1 MiB |
| --- | --- | ---: | ---: | ---: | ---: |
| Default | Mkv128 | 26.46 | 91.24 | 89.54 | 90.59 |
| Default | Mkv256 | 9.39 | 104.65 | 104.16 | 97.99 |
| NoGfni | Mkv128 | 21.77 | 83.53 | 82.24 | 82.65 |
| NoGfni | Mkv256 | 6.26 | 87.89 | 90.85 | 92.62 |
| NoAvx2 | Mkv128 | 25.22 | 51.87 | 52.53 | 51.27 |
| NoAvx2 | Mkv256 | 9.38 | 61.52 | 63.31 | 62.55 |
| NoHwIntrinsic | Mkv128 | 0.30 | 0.30 | 0.29 | 0.29 |
| NoHwIntrinsic | Mkv256 | 0.18 | 0.34 | 0.34 | 0.33 |

## CtrHmacEncrypt

Jobs: all four, see the intro. Associated data is empty.

| Job | Block | 16 B | 1 KiB | 64 KiB | 1 MiB |
| --- | --- | ---: | ---: | ---: | ---: |
| Default | Mkv128 | 18.13 | 85.06 | 85.82 | 83.03 |
| Default | Mkv256 | 6.43 | 80.88 | 80.38 | 80.13 |
| NoGfni | Mkv128 | 16.02 | 78.27 | 78.88 | 78.87 |
| NoGfni | Mkv256 | 4.52 | 66.69 | 69.58 | 71.24 |
| NoAvx2 | Mkv128 | 17.92 | 50.34 | 51.29 | 48.01 |
| NoAvx2 | Mkv256 | 6.42 | 48.55 | 49.28 | 49.50 |
| NoHwIntrinsic | Mkv128 | 0.30 | 0.30 | 0.29 | 0.29 |
| NoHwIntrinsic | Mkv256 | 0.13 | 0.27 | 0.25 | 0.26 |

## GcmEncrypt

Jobs: Default, NoGfni and NoAvx2 from the `--quick` run, which has no NoHwIntrinsic row. MKV-128 only, so there is no Mkv256 row. 16-byte tag, 12-byte nonce, empty associated data, ConstantTime engine. Measured on 2026-11-07 with `bash scripts/bench.sh --quick --filter "*"` on the machine described in the intro, so the host is the same. The quick profile runs 3 iterations, and its Error column is wide: at 1 MiB Default the Error is 145 percent of the mean, so treat that figure as a rough reading and rerun without `--quick` before relying on it.

| Job | Block | 16 B | 1 KiB | 1040 B | 1 MiB |
| --- | --- | ---: | ---: | ---: | ---: |
| Default | Mkv128 | 15.92 | 176.56 | 175.76 | 185.09 |
| NoGfni | Mkv128 | 11.32 | 93.17 | 87.91 | 100.34 |
| NoAvx2 | Mkv128 | 15.43 | 162.88 | 133.41 | 179.92 |

## XtsEncrypt

Jobs: Default, NoGfni and NoAvx2 from the `--quick` run, which has no NoHwIntrinsic row. MKV-128 only, so there is no Mkv256 row. One data unit per call with data unit number 0, 32-byte key, ConstantTime engine. Every size is a multiple of 16, so no call takes the ciphertext stealing path. Same run and host as GcmEncrypt above, with the same wide quick-profile Error.

| Job | Block | 16 B | 1 KiB | 1040 B | 1 MiB |
| --- | --- | ---: | ---: | ---: | ---: |
| Default | Mkv128 | 20.01 | 242.64 | 218.29 | 273.21 |
| NoGfni | Mkv128 | 14.80 | 123.12 | 111.72 | 130.41 |
| NoAvx2 | Mkv128 | 19.60 | 223.81 | 196.81 | 228.16 |

## Allocation

In the full run, every span row shows `-` (0 B) except three VariableTime rows at 1 MiB, which show 1 B per call: CtrHmacEncrypt Default Mkv128, CtrEncrypt NoAvx2 Mkv128, and CbcEncrypt NoAvx2 Mkv256. The quick run of GcmEncrypt and XtsEncrypt shows `-` (0 B) on every row; their full-run rows, including VariableTime, are not measured yet.

## Reading the numbers

Ratios below divide printed cells. Default over NoHwIntrinsic at 1 MiB is 286 to 333 for CtrEncrypt, CtrHmacEncrypt and CbcDecrypt, and 53 to 94 for CbcEncrypt; EncryptBlock is 58 to 94. NoGfni is 5 to 33 percent below Default on the 1 MiB rows and EncryptBlock. NoAvx2 is 36 to 44 percent below Default on the 1 MiB CbcDecrypt, CtrEncrypt and CtrHmacEncrypt rows, and 2 to 3 percent below on EncryptBlock. On 1 MiB CbcEncrypt it is 6 percent below at Mkv128 and 3.5 percent above at Mkv256; at 16 B, Mkv128 CbcEncrypt is 2.0 percent below. At Default, Mkv256 is 8 percent faster than Mkv128 on 1 MiB CtrEncrypt and CbcDecrypt, 3.5 percent slower on 1 MiB CtrHmacEncrypt, and 27.5 percent slower on EncryptBlock and 32 percent slower on 1 MiB CbcEncrypt.

## VariableTime

`MkvEngine.VariableTime` is variable time by design: its table lookups index memory by state bytes, so timing depends on the key and the input. Use it only for offline or batch work on a host with no untrusted co-resident code. Do not use it on multi-tenant servers, cloud VMs, or anywhere an attacker can measure timing.

The speed gate is at least 1.5 times faster than ConstantTime on the Default job, for EncryptBlock or CBC encrypt at 1 KiB or 64 KiB. Five of the six cases below clear it. EncryptBlock Mkv128 is 1.498 in this run, just under the gate; an EncryptBlock-only run on the same day gave 1.454 for that case.

| Case | Block | ConstantTime | VariableTime | Ratio |
| --- | --- | ---: | ---: | ---: |
| EncryptBlock | Mkv128 | 585.6 ns | 390.9 ns | 1.498 |
| EncryptBlock | Mkv256 | 1,616.3 ns | 601.6 ns | 2.69 |
| CbcEncrypt, 1 KiB | Mkv128 | 38.44 us | 19.98 us | 1.92 |
| CbcEncrypt, 1 KiB | Mkv256 | 56.30 us | 17.78 us | 3.17 |
| CbcEncrypt, 64 KiB | Mkv128 | 2.401 ms | 1.324 ms | 1.81 |
| CbcEncrypt, 64 KiB | Mkv256 | 3.427 ms | 1.176 ms | 2.92 |

Ratio is the ConstantTime mean divided by the VariableTime mean, both from the Default job. Each ratio comes from one benchmark run on this machine, and the ConstantTime side depends on AVX2 and GFNI. In the gate runs, the three toggle jobs stay within 10 percent of the Default row for VariableTime, since the engine uses no SIMD, and every gate row allocates 0 B per call.
