# Algorithm

How this library computes the MKV block cipher: the notation, the block layout, the round function, the key schedule, the revisions, and the constructions behind the fixed tables. It describes this implementation only.

## Notation

| Symbol | Meaning |
| --- | --- |
| `B` | Block length in bytes: 16 for `Mkv128`, 32 for `Mkv256` |
| `t` | Word length in bytes: `B / 4`, so 4 or 8 |
| `X` | A block of four words |
| `^` | Bitwise XOR |
| `S`, `SI` | The S-box and its inverse, applied to each byte |
| `Mix`, `Mix^-1` | For each word, a fixed `t x t` matrix over GF(2^8) and its inverse, applied to the word as a column of bytes |
| `RotL(w, n)`, `RotR(w, n)` | Rotate word `w` left or right by `n` bytes. Rev2025 applies them in MixWords, see [Round function](#round-function) |
| `XWords` | Replace each word with the XOR of the other three words |
| `R` | Round count, from the revision, block size and key length (see Revisions) |
| `RK[0..2R]` | Round keys, each `B` bytes long |
| `ctr(c)` | A block whose last byte is `c` and whose other bytes are zero. `c` is at most `2R`, so one byte is enough |
| `complement(w)` | Bitwise NOT of word `w` |

## State

A block is four words of `t` bytes. Word `i` is bytes `i*t` to `i*t + t - 1`. Bytes keep their plain order. No endianness conversion happens anywhere.

Arithmetic runs in GF(2^8), reduced by x^8 + x^5 + x^3 + x + 1 (0x12B). The S-box, its inverse and the mix matrices are fixed tables in `src/MkvBlockCipher/Primitives/`.

## Round function

The round function F is the unit that encryption, decryption and the key schedule repeat. A round takes two round keys, K0 and K1, and a block X:

    F(K0, K1, X) = XWords(S(Mix(S(X ^ K0)) ^ K1))

The steps, in order:

1. XOR K0 into X.
2. Apply S to every byte.
3. Apply Mix to each word.
4. XOR K1 into the block.
5. Apply S to every byte.
6. Apply XWords.

Mix on word i, counting words from 0, where `M` is the `t x t` matrix for the word size:

- Rev2024: `y = M · x`.
- Rev2025: `y = M · RotL(x, i·t/4)`. Word i rotates left by `i·t/4` bytes first: `i` bytes for `Mkv128`, `2i` bytes for `Mkv256`.

Mix^-1 is the inverse, word by word. For Rev2025 it is `x = RotR(M^-1 · y, i·t/4)`.

XWords is its own inverse. The inverse round runs the steps in reverse: XWords, SI, XOR K1, Mix^-1, SI, XOR K0.

## Encryption and decryption

Encryption:

1. For r = 0 to R-1, apply F with keys (RK[2r], RK[2r+1]).
2. XOR RK[2R] into the block. The result is the ciphertext.

Decryption:

1. XOR RK[2R] into the ciphertext block.
2. For r = R-1 down to 0, apply the inverse round with keys (RK[2r], RK[2r+1]).

## Key schedule

The key schedule expands the key into the round keys RK[0..2R], and every step runs the round function.

The key fills eight words, k0 to k7, of `t` bytes each. A key of eight words fills all of them. A shorter key fills k0 onward, and each missing word is the complement of the word four places before it:

    k(w) = complement(k(w-4))    for each missing word w >= 4

So a 4-word key (16 bytes for `Mkv128`, 32 bytes for `Mkv256`) gives k4 to k7 as complements of k0 to k3. A 6-word key (24 or 48 bytes) gives k6 and k7 as complements of k2 and k3.

Split the key into two halves: P0 = k0 to k3 and Q0 = k4 to k7. Define:

- G(c, X) = F(K(c), 0, X), where K(c) is the counter block for c
- G0(X) = F(0, 0, X), the round with zero keys

The counter block is `ctr(c)` in Rev2024. Rev2025 XORs a constant into it: K(c) = C0 ^ ctr(c) for odd c, and K(c) = C1 ^ ctr(c) for even c.

For i = 1 to R:

    P_i = G0(G(2i, Q_(i-1)))
    Q_i = P_i ^ G0(G(2i-1, P_(i-1)))
    RK[2i-1] = P_i
    RK[2i] = Q_i

RK[0] = P0. The schedule costs 4R round evaluations, about four block encryptions, so create one cipher per key and reuse it.

Rev2025 constants, as hex in block byte order:

| Constant | `Mkv128` (16 bytes) | `Mkv256` (32 bytes) |
| --- | --- | --- |
| C0 | `9302ee911a2ad98cad13e7948ad8b3b2` | `9302ee911a2ad98cad13e7948ad8b3b2d4da00f33f11fd8822166bb9cd187c55` |
| C1 | `d4da00f33f11fd8822166bb9cd187c55` | `43c853a3f90f70ae8d72ad0e7aac0c71afad739c17a14bd656c9436300def1e5` |

## Revisions

This section lists the parts that differ between the two revisions. The rest of the algorithm is shared.

`Rev2024` follows the earlier draft. `Rev2025` follows the specification in publicly available reference material, and it is the default. The revision names are this project's labels. Neither revision is claimed to be official.

| Part | Rev2024 | Rev2025 |
| --- | --- | --- |
| Round count R, 4-word key (`Mkv128` 16 bytes, `Mkv256` 32 bytes) | 6 | 7 |
| Round count R, 6-word key (`Mkv128` 24 bytes, `Mkv256` 48 bytes) | 7 | 8 |
| Round count R, 8-word key (`Mkv128` 32 bytes, `Mkv256` 64 bytes) | 8 | 9 |
| MixWords rotation | None | Per word, see [Round function](#round-function) |
| Key-schedule constants | None: K(c) = ctr(c) | C0 and C1, see [Key schedule](#key-schedule) |

## Where the tables come from

This section gives the constructions behind the fixed S-box, its inverse and the mix matrices. The tables in `src/MkvBlockCipher/Primitives/` match these constructions exactly.

S-box. Split the byte x into nibbles: xl is the high nibble and xr the low nibble. Work in GF(2^4) modulo x^4 + x + 1, with inv(0) = 0:

    yr = inv(xl)^4 * xr    if xr != 0, else inv(xl)
    yl = inv(xr * yr)^2    if yr != 0, else inv(xr)
    S(x) = (yl << 4 | yr) ^ 0x01

The inverse S-box is the inverse permutation of S.

Mix matrices. M4 = A4^4 and M8 = A8^8, with the powers taken over GF(2^8). A4 is the companion matrix of the coefficients 01 02 01 03, and A8 is the companion matrix of 01 04 DB 0C 14 0C DB 04. A companion matrix has ones on the superdiagonal and the coefficients in the last row. M4^-1 and M8^-1 are the matrix inverses of M4 and M8.

## Verification

This section lists what the tests check and where each expected value comes from.

- Rev2025: the six reference vectors, on both `MkvEngine` values and on the scalar fallback. The six ciphertexts, the first 8 bytes of RK[1] for each block size and key length, and the last round key for `Mkv256` with a 32-byte key come from publicly available reference material. The other five last round keys are computed by this project and serve as regression values.
- Rev2024: the full round key sets, the per-round intermediate values for both block sizes, and the block outputs. The values come from the earlier draft.
- Implementation paths: every path the machine supports, including the table path, matches the scalar fallback under both revisions, for blocks and rounds, out of place and in place.
- Tables: the S-box matches its construction, and the inverse S-box round-trips it. The mix matrices match their constructions, and each inverse multiplies its matrix to the identity.
- Modes: the mode tests run under Rev2025. The CTR-HMAC frozen vector is computed by this project and is not published. It is a regression value, not an independent known answer.
