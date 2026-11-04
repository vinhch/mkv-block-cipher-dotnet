# Algorithm

How this library computes the MKV block cipher: the notation, the block layout, the round function, the key schedule, and the revisions. It describes this implementation only.

## Notation

| Symbol | Meaning |
| --- | --- |
| `B` | Block length in bytes: 16 for `Mkv128`, 32 for `Mkv256` |
| `t` | Word length in bytes: `B / 4`, so 4 or 8 |
| `X` | A block of four words |
| `^` | Bitwise XOR |
| `S`, `SI` | The S-box and its inverse, applied to each byte |
| `Mix`, `Mix^-1` | For each word, a fixed `t x t` matrix over GF(2^8) and its inverse, applied to the word as a column of bytes |
| `XWords` | Replace each word with the XOR of the other three words |
| `R` | Round count, from the revision, block size and key length (see Revisions) |
| `RK[0..2R]` | Round keys, each `B` bytes long |
| `ctr(c)` | A block whose last byte is `c` and whose other bytes are zero. `c` is at most `2R`, so one byte is enough |
| `complement(w)` | Bitwise NOT of word `w` |

## State

A block is four words of `t` bytes. Word `i` is bytes `i*t` to `i*t + t - 1`. Bytes keep their plain order. No endianness conversion happens anywhere.

Arithmetic runs in GF(2^8), reduced by x^8 + x^5 + x^3 + x + 1 (0x12B). The S-box, its inverse and the mix matrices are fixed tables in `src/MkvBlockCipher/Primitives/`.

## Round function

A round takes two round keys, K0 and K1, and a block X:

    F(K0, K1, X) = XWords(S(Mix(S(X ^ K0)) ^ K1))

The steps, in order:

1. XOR K0 into X.
2. Apply S to every byte.
3. Apply Mix to each word.
4. XOR K1 into the block.
5. Apply S to every byte.
6. Apply XWords.

XWords is its own inverse. The inverse round runs the steps in reverse: XWords, SI, XOR K1, Mix^-1, SI, XOR K0.

## Encryption and decryption

Encryption:

1. For r = 0 to R-1, apply F with keys (RK[2r], RK[2r+1]).
2. XOR RK[2R] into the block. The result is the ciphertext.

Decryption:

1. XOR RK[2R] into the ciphertext block.
2. For r = R-1 down to 0, apply the inverse round with keys (RK[2r], RK[2r+1]).

## Key schedule

The key fills eight words, k0 to k7, of `t` bytes each. A key of eight words fills all of them. A shorter key fills k0 onward, and each missing word is the complement of the word four places before it:

    k(w) = complement(k(w-4))    for each missing word w >= 4

So a 4-word key (16 bytes for `Mkv128`, 32 bytes for `Mkv256`) gives k4 to k7 as complements of k0 to k3. A 6-word key (24 or 48 bytes) gives k6 and k7 as complements of k2 and k3.

Split the key into two halves: P0 = k0 to k3 and Q0 = k4 to k7. Define:

- G(c, X) = F(ctr(c), 0, X)
- G0(X) = F(0, 0, X), the round with zero keys

For i = 1 to R:

    P_i = G0(G(2i, Q_(i-1)))
    Q_i = P_i ^ G0(G(2i-1, P_(i-1)))
    RK[2i-1] = P_i
    RK[2i] = Q_i

RK[0] = P0. The schedule uses the same round function as encryption. It costs 4R round evaluations, about four block encryptions, so create one cipher per key and reuse it.

## Revisions

The two revisions use the same algorithm. They differ only in the round count R, which depends on the block size and the key length. `Rev2026` is the default.

| Block | Key bytes (bits) | Rev2024 R | Rev2026 R |
| --- | ---: | ---: | ---: |
| `Mkv128` | 16 (128) | 6 | 7 |
| `Mkv128` | 24 (192) | 7 | 8 |
| `Mkv128` | 32 (256) | 8 | 9 |
| `Mkv256` | 32 (256) | 6 | 7 |
| `Mkv256` | 48 (384) | 7 | 8 |
| `Mkv256` | 64 (512) | 8 | 9 |

The revision names are this project's labels. Neither revision is claimed to be official.

## Verification

The tests check the round keys and the per-round intermediate values against published traces, for both block sizes. They check the block output against published test vectors. One vector, `Mkv128` with `Rev2026`, is computed by this project and is not published.
