# Benchmarks

Baseline MB/s of the span APIs for the block cipher, CBC, CTR and CtrHmac, on each engine path of one machine.

Machine: Intel Core i7-12700H, 20 logical processors, Windows 11 Pro 10.0.26200, .NET 10.0.14.

Rows are engine paths. Default leaves every instruction set the CPU reports on. NoGfni, NoAvx2 and NoHwIntrinsic set `DOTNET_EnableGFNI=0`, `DOTNET_EnableAVX2=0` and `DOTNET_EnableHWIntrinsic=0`. NoHwIntrinsic runs the scalar engine. MB/s is 10^6 payload bytes per second: the Size column for the mode rows, the block size for EncryptBlock.

## EncryptBlock

Job: Default. One block per call, so the table has no size column.

| Job | Block | MB/s |
| --- | --- | ---: |
| Default | Mkv128 | 27.2 |
| Default | Mkv256 | 19.2 |
| NoGfni | Mkv128 | 23.0 |
| NoGfni | Mkv256 | 13.7 |
| NoAvx2 | Mkv128 | 26.4 |
| NoAvx2 | Mkv256 | 18.8 |
| NoHwIntrinsic | Mkv128 | 0.3 |
| NoHwIntrinsic | Mkv256 | 0.3 |

## CbcEncrypt

Job: Default.

| Job | Block | 16 B | 1 KiB | 64 KiB | 1 MiB |
| --- | --- | ---: | ---: | ---: | ---: |
| Default | Mkv128 | 13.4 | 26.2 | 26.4 | 26.7 |
| Default | Mkv256 | 9.3 | 18.4 | 19.0 | 18.9 |
| NoGfni | Mkv128 | 11.3 | 22.2 | 22.6 | 23.0 |
| NoGfni | Mkv256 | 6.7 | 13.3 | 13.7 | 13.8 |
| NoAvx2 | Mkv128 | 12.9 | 25.4 | 25.7 | 26.1 |
| NoAvx2 | Mkv256 | 9.0 | 18.1 | 18.6 | 18.6 |
| NoHwIntrinsic | Mkv128 | 0.1 | 0.3 | 0.3 | 0.3 |
| NoHwIntrinsic | Mkv256 | 0.2 | 0.3 | 0.4 | 0.3 |

## CbcDecrypt

Job: Default.

| Job | Block | 16 B | 1 KiB | 64 KiB | 1 MiB |
| --- | --- | ---: | ---: | ---: | ---: |
| Default | Mkv128 | 13.0 | 85.3 | 90.9 | 91.7 |
| Default | Mkv256 | 9.2 | 90.8 | 104.4 | 108.6 |
| NoGfni | Mkv128 | 11.0 | 77.5 | 84.6 | 82.8 |
| NoGfni | Mkv256 | 6.6 | 74.0 | 93.8 | 91.2 |
| NoAvx2 | Mkv128 | 12.6 | 50.0 | 52.5 | 52.7 |
| NoAvx2 | Mkv256 | 9.0 | 57.3 | 64.1 | 62.7 |
| NoHwIntrinsic | Mkv128 | 0.1 | 0.3 | 0.3 | 0.3 |
| NoHwIntrinsic | Mkv256 | 0.2 | 0.3 | 0.3 | 0.3 |

Allocated is 0 B on every row of every table except one: CbcDecrypt, Default, Mkv256, 1 MiB, which shows 5 B per call from a one-time allocation that repeated calls do not make (they measured 0 B).

## CtrEncrypt

Job: Default.

| Job | Block | 16 B | 1 KiB | 64 KiB | 1 MiB |
| --- | --- | ---: | ---: | ---: | ---: |
| Default | Mkv128 | 25.7 | 88.4 | 88.2 | 89.4 |
| Default | Mkv256 | 9.2 | 104.4 | 105.0 | 104.1 |
| NoGfni | Mkv128 | 22.1 | 83.6 | 82.4 | 81.2 |
| NoGfni | Mkv256 | 6.6 | 88.4 | 91.0 | 90.0 |
| NoAvx2 | Mkv128 | 24.5 | 52.1 | 51.4 | 51.6 |
| NoAvx2 | Mkv256 | 8.8 | 62.1 | 62.4 | 62.4 |
| NoHwIntrinsic | Mkv128 | 0.3 | 0.3 | 0.3 | 0.3 |
| NoHwIntrinsic | Mkv256 | 0.2 | 0.4 | 0.3 | 0.3 |

## CtrHmacEncrypt

Job: Default. Empty associated data.

| Job | Block | 16 B | 1 KiB | 64 KiB | 1 MiB |
| --- | --- | ---: | ---: | ---: | ---: |
| Default | Mkv128 | 18.1 | 82.3 | 85.9 | 86.3 |
| Default | Mkv256 | 6.4 | 81.5 | 82.5 | 81.1 |
| NoGfni | Mkv128 | 15.8 | 77.0 | 79.3 | 80.3 |
| NoGfni | Mkv256 | 4.8 | 70.0 | 70.2 | 69.8 |
| NoAvx2 | Mkv128 | 17.3 | 50.4 | 50.5 | 50.3 |
| NoAvx2 | Mkv256 | 6.2 | 48.4 | 49.3 | 48.3 |
| NoHwIntrinsic | Mkv128 | 0.3 | 0.3 | 0.3 | 0.3 |
| NoHwIntrinsic | Mkv256 | 0.1 | 0.3 | 0.3 | 0.3 |

The SIMD engine runs single-block calls 56 to 96 times faster than the scalar engine, and 1 MiB bulk rows about 300 times faster. GFNI off costs 7 to 29 percent at 1 MiB and on single blocks. AVX2 off costs about 40 percent on bulk CBC decrypt, CTR and CtrHmac, and 2 to 3 percent on single-block rows. Mkv256 runs fewer rounds at the 32-byte key used here (7 against 9 for Mkv128), so it moves 16 to 18 percent more bytes per second on bulk CTR and CBC decrypt. Each Mkv256 block call takes about 2.8 times as long as a Mkv128 call, so EncryptBlock and CBC encrypt lose about 30 percent MB/s.
