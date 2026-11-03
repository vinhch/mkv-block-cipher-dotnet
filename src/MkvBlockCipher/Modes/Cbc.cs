using System.Security.Cryptography;
using MkvBlockCipher.Kernels;

namespace MkvBlockCipher.Modes;

// The stack copies are cleared; register values are not.
internal static class Cbc
{
    private const string DecryptFailedMessage = "The data could not be decrypted.";

    // Serial by nature: each block needs the ciphertext of the block before it.
    internal static void Encrypt(
        BlockEngine engine,
        ReadOnlySpan<byte> roundKeys,
        ReadOnlySpan<byte> plaintext,
        ReadOnlySpan<byte> iv,
        Span<byte> destination)
    {
        int blockBytes = engine.Parameters.BlockBytes;
        int fullBytes = plaintext.Length - plaintext.Length % blockBytes;
        Span<byte> block = stackalloc byte[blockBytes];
        ReadOnlySpan<byte> previous = iv;
        for (int offset = 0; offset < fullBytes; offset += blockBytes)
        {
            plaintext.Slice(offset, blockBytes).CopyTo(block);
            XorInPlace(block, previous);
            engine.EncryptBlocks(roundKeys, block, destination.Slice(offset, blockBytes));
            previous = destination.Slice(offset, blockBytes);
        }

        Pkcs7.Pad(plaintext.Slice(fullBytes), block);
        XorInPlace(block, previous);
        engine.EncryptBlocks(roundKeys, block, destination.Slice(fullBytes, blockBytes));
        CryptographicOperations.ZeroMemory(block);
    }

    // Returns the plaintext length. Destination must hold the whole ciphertext, which may be the same span.
    internal static int Decrypt(
        BlockEngine engine,
        ReadOnlySpan<byte> roundKeys,
        ReadOnlySpan<byte> ciphertext,
        ReadOnlySpan<byte> iv,
        Span<byte> destination)
    {
        int blockBytes = engine.Parameters.BlockBytes;
        int batchBytes = engine.BatchBlocks * blockBytes;
        Span<byte> batch = stackalloc byte[batchBytes];

        // The last ciphertext block before the current batch: the IV for the first batch.
        Span<byte> previous = stackalloc byte[blockBytes];
        iv.CopyTo(previous);
        for (int offset = 0; offset < ciphertext.Length; offset += batchBytes)
        {
            int length = Math.Min(batchBytes, ciphertext.Length - offset);
            // Copied before the write below: in-place use would otherwise overwrite ciphertext the XOR still needs.
            ciphertext.Slice(offset, length).CopyTo(batch);
            Span<byte> output = destination.Slice(offset, length);
            engine.DecryptBlocks(roundKeys, batch.Slice(0, length), output);
            for (int position = 0; position < length; position += blockBytes)
            {
                ReadOnlySpan<byte> prior = position == 0 ? previous : batch.Slice(position - blockBytes, blockBytes);
                XorInPlace(output.Slice(position, blockBytes), prior);
            }

            batch.Slice(length - blockBytes, blockBytes).CopyTo(previous);
        }

        CryptographicOperations.ZeroMemory(batch);
        CryptographicOperations.ZeroMemory(previous);

        int lastOffset = ciphertext.Length - blockBytes;
        int unpaddedLength = Pkcs7.GetUnpaddedLength(destination.Slice(lastOffset, blockBytes));
        if (unpaddedLength < 0)
        {
            CryptographicOperations.ZeroMemory(destination);
            throw new CryptographicException(DecryptFailedMessage);
        }

        int plaintextLength = lastOffset + unpaddedLength;
        CryptographicOperations.ZeroMemory(destination.Slice(plaintextLength, ciphertext.Length - plaintextLength));
        return plaintextLength;
    }

    private static void XorInPlace(Span<byte> target, ReadOnlySpan<byte> operand)
    {
        for (int i = 0; i < target.Length; i++)
        {
            target[i] ^= operand[i];
        }
    }
}
