using System.Security.Cryptography;
using MkvBlockCipher.Kernels;

namespace MkvBlockCipher.Modes;

// CS3 as in RFC 3962 section 5 and the SP 800-38A addendum: the last two blocks are swapped, and a short final block
// is the truncated penultimate ciphertext. The output is the input length. Callers check lengths and overlap first.
internal static class CbcCts
{
    internal static void Encrypt(
        BlockEngine engine,
        ReadOnlySpan<byte> roundKeys,
        ReadOnlySpan<byte> plaintext,
        ReadOnlySpan<byte> iv,
        Span<byte> destination)
    {
        int blockBytes = engine.Parameters.BlockBytes;
        if (plaintext.Length == blockBytes)
        {
            Cbc.Encrypt(engine, roundKeys, plaintext, iv, destination, PaddingMode.None);
            return;
        }

        int tailLength = TailLength(plaintext.Length, blockBytes);
        int penultimateOffset = plaintext.Length - blockBytes - tailLength;
        int chainedLength = penultimateOffset + blockBytes;

        // CBC through the penultimate block. Its ciphertext Y is left in its destination slot.
        Cbc.Encrypt(engine, roundKeys, plaintext.Slice(0, chainedLength), iv, destination.Slice(0, chainedLength), PaddingMode.None);

        Span<byte> penultimate = stackalloc byte[blockBytes];
        Span<byte> last = stackalloc byte[blockBytes];
        destination.Slice(penultimateOffset, blockBytes).CopyTo(penultimate);

        // The final partial block is zero-padded, then encrypted with Y as its chaining value. The input tail is
        // read before the writes below overwrite it.
        last.Clear();
        plaintext.Slice(chainedLength, tailLength).CopyTo(last);
        ByteXor.Xor(last, penultimate, last);
        engine.EncryptBlocks(roundKeys, last, destination.Slice(penultimateOffset, blockBytes));
        penultimate.Slice(0, tailLength).CopyTo(destination.Slice(chainedLength, tailLength));

        CryptographicOperations.ZeroMemory(penultimate);
        CryptographicOperations.ZeroMemory(last);
    }

    internal static void Decrypt(
        BlockEngine engine,
        ReadOnlySpan<byte> roundKeys,
        ReadOnlySpan<byte> ciphertext,
        ReadOnlySpan<byte> iv,
        Span<byte> destination)
    {
        int blockBytes = engine.Parameters.BlockBytes;
        if (ciphertext.Length == blockBytes)
        {
            Cbc.Decrypt(engine, roundKeys, ciphertext, iv, destination, PaddingMode.None);
            return;
        }

        int tailLength = TailLength(ciphertext.Length, blockBytes);
        int penultimateOffset = ciphertext.Length - blockBytes - tailLength;
        int chainedLength = penultimateOffset + blockBytes;

        // Z = E(P* ^ Y) with P* zero past the tail, so D(Z) and Y agree past the tail: the stored tail plus the rest
        // of D(Z) gives Y, and D(Z) ^ Y gives P*. Every ciphertext read happens before dest is written.
        Span<byte> swapped = stackalloc byte[blockBytes];
        Span<byte> penultimate = stackalloc byte[blockBytes];
        Span<byte> last = stackalloc byte[blockBytes];
        engine.DecryptBlocks(roundKeys, ciphertext.Slice(penultimateOffset, blockBytes), swapped);
        swapped.CopyTo(penultimate);
        ciphertext.Slice(chainedLength, tailLength).CopyTo(penultimate);
        ByteXor.Xor(swapped, penultimate, last);

        // The prefix and Y go to dest so Cbc.Decrypt can chain in place. For in-place use the first copy is a no-op.
        ciphertext.Slice(0, chainedLength).CopyTo(destination);
        penultimate.CopyTo(destination.Slice(penultimateOffset, blockBytes));
        Cbc.Decrypt(engine, roundKeys, destination.Slice(0, chainedLength), iv, destination.Slice(0, chainedLength), PaddingMode.None);
        last.Slice(0, tailLength).CopyTo(destination.Slice(chainedLength, tailLength));

        CryptographicOperations.ZeroMemory(swapped);
        CryptographicOperations.ZeroMemory(penultimate);
        CryptographicOperations.ZeroMemory(last);
    }

    // Final block length, 1 to blockBytes. A whole final block is a full block, which makes the swap a plain swap.
    private static int TailLength(int length, int blockBytes) => (length - 1) % blockBytes + 1;
}
