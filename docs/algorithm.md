# Algorithm

The MKV block cipher as this library computes it: notation, block layout, round function, key schedule, revisions, the fixed tables with their constructions, and test vectors. Everything needed to implement and check the cipher is on this page.

## How the parts fit

The sections below describe one flow: a key and a block of data go in, a block of ciphertext comes out. The flow has two tiers. The set-up tier runs once for each key and produces the round keys. The per-block tier runs once for each block and uses them.

    Set up once per key

      parameters
        in:  block size, key length, revision
        out: B, t, R, the MixWords rotation step, and whether the
             key schedule uses round constants
             |
             v
      key schedule
        in:  key, parameters, S, SI, M, inverse(M)
        out: RK[0..2R], each B bytes

The caller picks the block size, the key length and the revision, and everything else follows from them, including `R`; the key length must be 4, 6 or 8 words for the block size, listed in bytes and bits under [Revisions](#revisions). The tables are fixed constants that no key or data changes: S and SI are the same for every parameter set, and M is M4 or M8 according to `t`. The key schedule is the only stage that reads key bytes. It completes a short key to eight words, then runs F `4R` times to produce `RK[0..2R]`. The key is not stored on its own, but it is not erased either: `RK[0]` is the first half of the completed key, which is the whole key for a 4-word key.

The two tiers meet at one secret value: `RK[0..2R]` is the set-up tier's whole output and the per-block tier's whole key input. The per-block tier also needs `t`, `R` and the MixWords rotation step from the parameters, since the round function cannot choose between M4 and M8 or between the two revisions without them. The tables cross over too, but they are constants rather than state, so nothing has to carry them across.

    Run once per block

      in:  plaintext block, RK[0..2R], t, R, the rotation step
             |
             v
      round (F), repeated R times
        in:  block X, round keys K0 and K1
        out: block X, in place
             |
             v
      final key addition
        in:  block, RK[2R]
        out: ciphertext block

Encryption runs the rounds in order, then the final key addition. Decryption runs the per-block tier backwards.

The tiers divide the work. The set-up tier never sees plaintext or ciphertext; the per-block tier never reads the key as such, only the round keys. A caller who encrypts many blocks under one key pays for the set-up tier once and the per-block tier per block.

Modes call the block step and build on its output; they add nothing to the cipher itself. They belong to the public API, not to this page.

## Notation

| Symbol | Meaning |
| --- | --- |
| `B` | Block length in bytes: 16 for `Mkv128`, 32 for `Mkv256` |
| `t` | Word length in bytes: `B / 4`, so 4 or 8 |
| `X` | A block of four words |
| `^` | Bitwise XOR, always written with spaces: `a ^ b` |
| `·` | Multiplication in GF(2^8). Between a `t x t` matrix and a word, the matrix-vector product over GF(2^8) |
| `*` | Multiplication in GF(2^4), used only in the S-box construction |
| `pow(a, n)` | The product of `n` copies of `a`, in the field or matrix ring at hand |
| `×`, `/`, `mod` | Integer multiplication, division and remainder on indices and counts |
| `inv(a)` | Multiplicative inverse in GF(2^4), with `inv(0) = 0` |
| `inverse(M)` | Matrix inverse over GF(2^8) |
| `<<`, `\|` | Shift left by bits, bitwise OR |
| `S`, `SI` | The S-box and its inverse, applied to each byte |
| `MixWords`, `InvMixWords` | The word mix and its inverse, see [Round function](#round-function) |
| `RotL(w, n)`, `RotR(w, n)` | Rotate word `w` left or right by `n` bytes: byte `j` of `RotL(w, n)` is byte `(j + n) mod t` of `w` |
| `XWords` | Replace each word with the XOR of the other three words |
| `R` | Round count, from the revision, block size and key length (see [Revisions](#revisions)) |
| `RK[0..2R]` | Round keys, each `B` bytes long |
| `ctr(c)` | A block whose last byte is `c` and whose other bytes are zero. `c` is at most `2R`, so one byte is enough |
| `complement(w)` | Bitwise NOT of word `w` |

## State

A block is four words of `t` bytes. Word `i` is bytes `i×t` to `i×t + t - 1`. Bytes keep their plain order. No endianness conversion happens anywhere.

Arithmetic runs in [GF(2^8)](https://en.wikipedia.org/wiki/Finite_field_arithmetic): a byte is a polynomial over GF(2) with bit 0 as the constant term, and products are reduced by x^8 + x^5 + x^3 + x + 1 (0x12B). The S-box and the mix matrices are fixed; [Where the tables come from](#where-the-tables-come-from) gives each one in full and its construction.

## Round function

The round function F is the unit that encryption, decryption and the key schedule repeat. A round takes two round keys, K0 and K1, and a block X:

    F(K0, K1, X) = XWords(S(MixWords(S(X ^ K0)) ^ K1))

The steps, in order:

1. XOR K0 into X.
2. Apply S to every byte.
3. Apply MixWords.
4. XOR K1 into the block.
5. Apply S to every byte.
6. Apply XWords.

MixWords works on each word i, counting words from 0. `M` is the matrix for the word size (M4 when `t` is 4, M8 when `t` is 8), and the word is a column vector whose element `j` is byte `j` of the word, so output byte `r` is the XOR over `c` of `M[r][c] · x[c]`:

- Rev2024: `y = M · x`.
- Rev2025: `y = M · RotL(x, i×t/4)`. Word i rotates left by `i×t/4` bytes first: `i` bytes for `Mkv128`, `2i` bytes for `Mkv256`.

InvMixWords is the inverse, word by word: `x = inverse(M) · y` for Rev2024, and `x = RotR(inverse(M) · y, i×t/4)` for Rev2025.

XWords is its own inverse. The inverse round runs the steps in reverse: XWords, SI, XOR K1, InvMixWords, SI, XOR K0.

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

So a 4-word key (16 bytes or 128 bits for `Mkv128`, 32 bytes or 256 bits for `Mkv256`) gives k4 to k7 as complements of k0 to k3. A 6-word key (24 bytes or 192 bits, 48 bytes or 384 bits) gives k6 and k7 as complements of k2 and k3.

Split the key into two halves: P0 = k0 to k3 and Q0 = k4 to k7. Define:

- G(c, X) = F(K(c), 0, X), where K(c) is the counter block for c
- G0(X) = F(0, 0, X), the round with zero keys

The counter block is `ctr(c)` in Rev2024. Rev2025 XORs a constant into it: K(c) = C0 ^ ctr(c) for odd c, and K(c) = C1 ^ ctr(c) for even c.

For i = 1 to R:

    P_i = G0(G(2i, Q_(i-1)))
    Q_i = P_i ^ G0(G(2i-1, P_(i-1)))
    RK[2i-1] = P_i
    RK[2i] = Q_i

RK[0] = P0. The schedule costs 4R round evaluations, about four block encryptions.

Rev2025 constants, as hex in block byte order:

| Constant | `Mkv128` (16 bytes) | `Mkv256` (32 bytes) |
| --- | --- | --- |
| C0 | `9302ee911a2ad98cad13e7948ad8b3b2` | `9302ee911a2ad98cad13e7948ad8b3b2d4da00f33f11fd8822166bb9cd187c55` |
| C1 | `d4da00f33f11fd8822166bb9cd187c55` | `43c853a3f90f70ae8d72ad0e7aac0c71afad739c17a14bd656c9436300def1e5` |

## Revisions

This section lists the parts that differ between the two revisions. The rest of the algorithm is shared.

`Rev2024` follows the earlier draft. `Rev2025` follows this project's interpretation of publicly available reference material, and it is the default. The revision names are this project's labels. Neither revision is claimed to be official.

| Part | Rev2024 | Rev2025 |
| --- | --- | --- |
| Round count R, 4-word key (`Mkv128` 16 bytes or 128 bits, `Mkv256` 32 bytes or 256 bits) | 6 | 7 |
| Round count R, 6-word key (`Mkv128` 24 bytes or 192 bits, `Mkv256` 48 bytes or 384 bits) | 7 | 8 |
| Round count R, 8-word key (`Mkv128` 32 bytes or 256 bits, `Mkv256` 64 bytes or 512 bits) | 8 | 9 |
| MixWords rotation | None | Per word, see [Round function](#round-function) |
| Key-schedule constants | None: K(c) = ctr(c) | C0 and C1, see [Key schedule](#key-schedule) |

## Where the tables come from

This section gives the S-box and the mix matrices in full, with the constructions they come from.

S-box. Split the byte x into nibbles: xl is the high nibble and xr the low nibble. Work in GF(2^4) modulo x^4 + x + 1 (0x13):

    yr = pow(inv(xl), 4) * xr    if xr != 0, else inv(xl)
    yl = pow(inv(xr * yr), 2)    if yr != 0, else inv(xr)
    S(x) = (yl << 4 | yr) ^ 0x01

The resulting S-box, with the high nibble of x as the row and the low nibble as the column:

| Row | x0 | x1 | x2 | x3 | x4 | x5 | x6 | x7 | x8 | x9 | xA | xB | xC | xD | xE | xF |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 0x | 01 | 11 | 91 | E1 | D1 | B1 | 71 | 61 | F1 | 21 | C1 | 51 | A1 | 41 | 31 | 81 |
| 1x | 00 | 10 | E3 | 92 | B5 | D4 | 77 | 66 | 89 | 38 | AB | 4A | CD | 5C | 2F | FE |
| 2x | 08 | 5F | 3E | B0 | 1C | C2 | 83 | DD | E8 | F6 | 47 | 79 | 95 | 2B | AA | 64 |
| 3x | 0F | 48 | D0 | 29 | A3 | 1A | F2 | BB | 65 | CC | E4 | 3D | 57 | 7E | 86 | 9F |
| 4x | 0C | 2A | F4 | 1F | 5B | 90 | EE | C5 | 36 | 6D | 73 | 88 | BC | A7 | 49 | D2 |
| 5x | 0A | 3C | 18 | 85 | E0 | 4D | 99 | A4 | B3 | 5E | DA | C7 | 72 | FF | 6B | 26 |
| 6x | 06 | 76 | CF | A8 | 4E | 59 | 60 | 17 | DC | 9B | 32 | F5 | 23 | 84 | ED | BA |
| 7x | 07 | 67 | 2D | 3B | FA | 8C | 16 | 70 | 54 | A2 | 98 | BE | EF | D9 | C3 | 45 |
| 8x | 0E | A9 | 62 | 5A | 27 | BF | 34 | 9C | FD | D5 | 8E | E6 | 1B | 43 | 78 | C0 |
| 9x | 03 | B2 | 87 | C4 | 9D | 6E | 4B | F8 | 7A | E9 | 2C | AF | D6 | 15 | 50 | 33 |
| Ax | 0D | FB | 56 | EC | 3F | 75 | B8 | 42 | 1E | 24 | C9 | 93 | 80 | 6A | D7 | AD |
| Bx | 04 | E5 | B9 | 7D | 82 | A6 | CA | 2E | 97 | 13 | 6F | DB | 44 | 30 | FC | 58 |
| Cx | 0B | 8D | 9A | 46 | 74 | 28 | DF | 53 | CB | B7 | F0 | 6C | AE | E2 | 35 | 19 |
| Dx | 05 | 94 | 7B | DE | C6 | F3 | AC | 39 | 4F | 8A | 55 | 20 | 68 | BD | 12 | E7 |
| Ex | 02 | D3 | A5 | F7 | 69 | EB | 5D | 8F | 22 | 40 | B6 | 14 | 3A | C8 | 9E | 7C |
| Fx | 09 | CE | 4C | 63 | D8 | 37 | 25 | EA | A0 | 7F | 1D | 52 | F9 | 96 | B4 | 8B |

The inverse S-box SI is the inverse permutation of S.

Mix matrices. M4 = pow(A4, 4) and M8 = pow(A8, 8), with the products taken over GF(2^8). A4 is the [companion matrix](https://en.wikipedia.org/wiki/Companion_matrix) of the coefficients 01 02 01 03, and A8 is the companion matrix of 01 04 DB 0C 14 0C DB 04. Here a companion matrix has ones on the superdiagonal, the coefficients in the last row, and zeros elsewhere. Rows are listed top to bottom, element `M[r][c]` at row `r`, column `c`:

    M4 =
    01 02 01 03
    03 07 01 04
    04 0B 03 0D
    0D 1E 06 14

    M8 =
    01 04 DB 0C 14 0C DB 04
    04 11 15 EB 5C 24 1D CB
    CB 55 38 E6 D5 AF 0D 4C
    4C D0 5D 15 91 F8 A7 16
    16 14 18 B5 06 79 30 FF
    FF 97 E0 B0 66 AE 8D B1
    B1 6D F6 7D 3C FB CF 1F
    1F CD 5C 72 DA B8 CA B3

InvMixWords uses inverse(M4) and inverse(M8).

## Test vectors

Each vector lists the key, the plaintext and the ciphertext as hex in byte order. Rev2025 vectors also list the first 8 bytes of RK[1] and the last round key RK[2R].

Rev2025. The six ciphertexts, the six RK[1] prefixes and the last round key for `Mkv256` with a 32-byte key come from publicly available reference material. The other five last round keys are computed by this project and serve as regression values.

    Rev2025, Mkv128, 16-byte (128-bit) key
    Key         000102030405060708090A0B0C0D0E0F
    Plaintext   FFEEDDCCBBAA99887766554433221100
    Ciphertext  F2795ECBA8F4D887F539EE8D8DF1141D
    RK[1] first 8 bytes D55F9779EFA06276
    RK[14]      AA89FB1AFDE0CBECDDB03D41CE3E5F00

    Rev2025, Mkv128, 24-byte (192-bit) key
    Key         000102030405060708090A0B0C0D0E0F1011121314151617
    Plaintext   FFEEDDCCBBAA99887766554433221100
    Ciphertext  D8E0A9A2994B4622D837676B7A54BFE2
    RK[1] first 8 bytes 1974492A8DE8FEE7
    RK[16]      8B2AA5F3A9E1C2573284E4AA4115A620

    Rev2025, Mkv128, 32-byte (256-bit) key
    Key         000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F
    Plaintext   FFEEDDCCBBAA99887766554433221100
    Ciphertext  893F15625E29414002725C12781A7A34
    RK[1] first 8 bytes 0245745DDFEA1357
    RK[18]      F1C80EAEF2DD216FD182F2002C83A271

    Rev2025, Mkv256, 32-byte (256-bit) key
    Key         000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F
    Plaintext   FFEEDDCCBBAA99887766554433221100FFEEDDCCBBAA99887766554433221100
    Ciphertext  24EB2357EABAE02C8E2C9E497125DE8AF0B43EF000BF15FF20E091B0DE08893D
    RK[1] first 8 bytes D511DC576D930D91
    RK[14]      1C90E6439CA60AA2A6E40143A00447F9D8FDB7AFB118ED613ACD720BD59467DF

    Rev2025, Mkv256, 48-byte (384-bit) key
    Key         000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F
    Plaintext   FFEEDDCCBBAA99887766554433221100FFEEDDCCBBAA99887766554433221100
    Ciphertext  C2B27F34B9E38857D1E1C345817D04047677335009526ABCC9212CB9BBF26374
    RK[1] first 8 bytes A5C8F69EB97064DE
    RK[16]      BBC4A411CECC2B583B07A8E5113FD30D248D41412A9EA47D5120C5F25120177C

    Rev2025, Mkv256, 64-byte (512-bit) key
    Key         000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F
    Plaintext   FFEEDDCCBBAA99887766554433221100FFEEDDCCBBAA99887766554433221100
    Ciphertext  3DAD4F9B1330C6111CED631DDDF6E3EEA0678D10DD7B75A06B5BA602FCCA28AB
    RK[1] first 8 bytes 809A8447DC898BD3
    RK[18]      FE951B1A6DFA1AEEE63DD42533180340685410E644080CB4FFB765A396731F20

Rev2024. The six vectors come from the earlier draft. The same source also gives the full round key sets and the intermediate values after each round step for both block sizes; this project keeps them as further known-answer data.

    Rev2024, Mkv128, 16-byte (128-bit) key
    Key         0102030405060708090A0B0C0D0E0F11
    Plaintext   112233445566778899AABBCCDDEEFF00
    Ciphertext  B331228334C3F81A37206591498756A1

    Rev2024, Mkv128, 24-byte (192-bit) key
    Key         0102030405060708090A0B0C0D0E0F111213141516171819
    Plaintext   112233445566778899AABBCCDDEEFF00
    Ciphertext  4A9FC1350AAFCCAE7CB5B12AE4B24F91

    Rev2024, Mkv128, 32-byte (256-bit) key
    Key         0102030405060708090A0B0C0D0E0F1112131415161718191A1B1C1D1E1F2223
    Plaintext   112233445566778899AABBCCDDEEFF00
    Ciphertext  5F16D17C48E40146559D602F50D6307E

    Rev2024, Mkv256, 32-byte (256-bit) key
    Key         0102030405060708090A0B0C0D0E0F1112131415161718191A1B1C1D1E1F2223
    Plaintext   112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00
    Ciphertext  CF2F2C1008186A578FE5B45DBD154473940C2BEC5682CDF83A3564A72DB0161B

    Rev2024, Mkv256, 48-byte (384-bit) key
    Key         0102030405060708090A0B0C0D0E0F1112131415161718191A1B1C1D1E1F22230102030405060708090A0B0C0D0E0F11
    Plaintext   112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00
    Ciphertext  731E244B25D8F7489D2E4BDEC8EAEE1796F55A26904EEDB22D96C2C17452739D

    Rev2024, Mkv256, 64-byte (512-bit) key
    Key         0102030405060708090A0B0C0D0E0F1112131415161718191A1B1C1D1E1F22230102030405060708090A0B0C0D0E0F1112131415161718191A1B1C1D1E1F2223
    Plaintext   112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00
    Ciphertext  93B442FB88D257FBE71256BE511AAB9B1F71A4DD524635A61019A12ACB262C85
