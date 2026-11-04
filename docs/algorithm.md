# Algorithm

How this library computes the MKV block cipher: the block layout, the round function, the key schedule, and the two revisions. It describes this implementation only.

## State

A block is four words of equal size. A word is `t` bytes, where `t` is 4 for `Mkv128` and 8 for `Mkv256`. Word `i` is bytes `i * t` to `i * t + t - 1`. Bytes keep their plain order: no endianness conversion happens anywhere.

Arithmetic runs in GF(2^8), reduced by x^8 + x^5 + x^3 + x + 1 (0x12B). The S-box and its inverse are fixed 256-entry byte tables. The constants live in `src/MkvBlockCipher/Primitives/`.

## Round function

A round takes two round keys, K0 and K1, and a block X:

    F(K0, K1, X) = XWords(S(Mix(S(X ^ K0)) ^ K1))

The steps, in order:

1. XOR K0 into the block.
2. Apply the S-box to every byte.
3. Mix: multiply each word, read as a column of bytes, by a fixed invertible matrix over GF(2^8). The matrix is 4 x 4 for `Mkv128` and 8 x 8 for `Mkv256`.
4. XOR K1 into the block.
5. Apply the S-box to every byte again.
6. XWords: replace each word with the XOR of the other three words.

XWords is its own inverse. The inverse round undoes the steps in reverse order: XWords, the inverse S-box, XOR K1, the inverse Mix matrix, the inverse S-box, then XOR K0.

## Encryption and decryption

The round keys are RK[0] to RK[2R], where R is the round count for the block size, key length and revision (see Revisions).

Encryption:

1. Apply F with keys (RK[2r], RK[2r+1]) for r = 0 to R-1.
2. XOR RK[2R] into the block. The result is the ciphertext.

Decryption:

1. XOR RK[2R] into the ciphertext block.
2. For r = R-1 down to 0, apply the inverse round with keys (RK[2r], RK[2r+1]).

## Key schedule

The key fills eight words, k0 to k7, of `t` bytes each. Words k0 to k3 form the left half L, and words k4 to k7 form the right half R.

A key shorter than eight words leaves the upper words unfilled. Each unfilled word k_w is the bitwise complement of word k_(w-4):

- A 4-word key (16 bytes for `Mkv128`, 32 bytes for `Mkv256`) fills k0 to k3. The rest are complements of k0 to k3.
- A 6-word key (24 bytes, or 48 bytes) fills k0 to k5. k6 and k7 are complements of k2 and k3.
- An 8-word key fills all eight words.

The schedule starts with RK[0] = L. Define G(c, X) = F(ctr(c), 0, X), where ctr(c) is the integer c written big-endian across the full block. Define G0(X) = F(0, 0, X), the round with zero keys. For each round i from 1 to R:

    L_i = G0(G(2i, R_(i-1)))
    R_i = L_i XOR G0(G(2i-1, L_(i-1)))
    RK[2i-1] = L_i
    RK[2i] = R_i

The schedule uses the same round function as encryption. Its cost is 4R round evaluations, about four block encryptions, so create one instance per key and reuse it.

## Revisions

Rev2024 and Rev2026 use the same algorithm. They differ only in R: Rev2026 adds one round at every key length. Rev2026 is the library default.

| Revision | Mkv128 with 128, 192, 256-bit keys | Mkv256 with 256, 384, 512-bit keys |
| --- | ---: | ---: |
| Rev2024 | 6, 7, 8 | 6, 7, 8 |
| Rev2026 (default) | 7, 8, 9 | 7, 8, 9 |

Neither revision is claimed to be official.

## Verification

The test suite checks the implementation against published test vectors. It also checks the round keys and the per-round intermediate values for both block sizes.
