using System.Security.Cryptography;
using MkvBlockCipher.Kernels;

namespace MkvBlockCipher.Modes;

// GCM over one block cipher with a 96-bit nonce, as SP 800-38D defines it. J0 = nonce || 0x00000001 masks the tag, and
// the keystream starts at nonce || 0x00000002. Callers check lengths and overlap first.
internal static class Gcm
{
    private const int BlockBytes = 16;
    private const int NonceBytes = 12;
    private const byte TagMaskCounter = 1;
    private const byte FirstKeystreamCounter = 2;

    // H = E_K(0^128). Computed once per key; the caller keeps it in a pinned array.
    internal static void ComputeH(BlockEngine engine, ReadOnlySpan<byte> roundKeys, Span<byte> h)
    {
        Span<byte> zero = stackalloc byte[BlockBytes];
        zero.Clear();
        engine.EncryptBlocks(roundKeys, zero, h);
    }

    internal static void Encrypt(
        BlockEngine engine,
        ReadOnlySpan<byte> roundKeys,
        ReadOnlySpan<byte> h,
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> plaintext,
        Span<byte> ciphertext,
        Span<byte> tag,
        ReadOnlySpan<byte> associatedData)
    {
        Span<byte> j0 = stackalloc byte[BlockBytes];
        Span<byte> counter = stackalloc byte[BlockBytes];
        InitialCounter(nonce, TagMaskCounter, j0);
        InitialCounter(nonce, FirstKeystreamCounter, counter);

        // Whole-block increment equals inc32: an int-length span is at most 2^27 blocks, so the low 32 bits never carry.
        Ctr.Transform(engine, roundKeys, counter, plaintext, ciphertext);
        ComputeTag(engine, roundKeys, h, j0, associatedData, ciphertext, tag);
    }

    // Verifies the tag before any plaintext is written. Returns false, with plaintext untouched, when the tag differs.
    internal static bool Decrypt(
        BlockEngine engine,
        ReadOnlySpan<byte> roundKeys,
        ReadOnlySpan<byte> h,
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> ciphertext,
        ReadOnlySpan<byte> tag,
        Span<byte> plaintext,
        ReadOnlySpan<byte> associatedData)
    {
        Span<byte> j0 = stackalloc byte[BlockBytes];
        Span<byte> counter = stackalloc byte[BlockBytes];
        InitialCounter(nonce, TagMaskCounter, j0);
        InitialCounter(nonce, FirstKeystreamCounter, counter);

        Span<byte> expectedTag = stackalloc byte[BlockBytes];
        ComputeTag(engine, roundKeys, h, j0, associatedData, ciphertext, expectedTag.Slice(0, tag.Length));
        bool tagMatches = CryptographicOperations.FixedTimeEquals(expectedTag.Slice(0, tag.Length), tag);
        CryptographicOperations.ZeroMemory(expectedTag);
        if (!tagMatches)
        {
            return false;
        }

        Ctr.Transform(engine, roundKeys, counter, ciphertext, plaintext);
        return true;
    }

    // Tag = MSB(tag.Length) of E_K(J0) XOR GHASH_H(A, C).
    private static void ComputeTag(
        BlockEngine engine,
        ReadOnlySpan<byte> roundKeys,
        ReadOnlySpan<byte> h,
        ReadOnlySpan<byte> j0,
        ReadOnlySpan<byte> associatedData,
        ReadOnlySpan<byte> ciphertext,
        Span<byte> tag)
    {
        Span<byte> ghash = stackalloc byte[BlockBytes];
        Span<byte> mask = stackalloc byte[BlockBytes];
        Ghash.Compute(h, associatedData, ciphertext, ghash);
        engine.EncryptBlocks(roundKeys, j0, mask);
        ByteXor.Xor(ghash, mask, ghash);
        ghash.Slice(0, tag.Length).CopyTo(tag);
        CryptographicOperations.ZeroMemory(ghash);
        CryptographicOperations.ZeroMemory(mask);
    }

    // The nonce, then 31 zero bits and the 32-bit counter in the last four bytes.
    private static void InitialCounter(ReadOnlySpan<byte> nonce, byte lastByte, Span<byte> counter)
    {
        nonce.CopyTo(counter);
        counter.Slice(NonceBytes).Clear();
        counter[BlockBytes - 1] = lastByte;
    }
}
