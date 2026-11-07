using System.Diagnostics;
using System.Security.Cryptography;
using MkvBlockCipher.Kernels;

namespace MkvBlockCipher.Modes;

// The stack copies are cleared; register values are not.
internal static class Cbc
{
    // Serial by nature: each block needs the ciphertext of the block before it. With PaddingMode.None the plaintext
    // must be whole blocks; the public layer checks that before any output is written.
    internal static void Encrypt(
        BlockEngine engine,
        ReadOnlySpan<byte> roundKeys,
        ReadOnlySpan<byte> plaintext,
        ReadOnlySpan<byte> iv,
        Span<byte> destination,
        PaddingMode padding = PaddingMode.PKCS7)
    {
        int blockBytes = engine.Parameters.BlockBytes;
        Debug.Assert(padding != PaddingMode.None || plaintext.Length % blockBytes == 0, "PaddingMode.None needs whole blocks.");
        int fullBytes = plaintext.Length - plaintext.Length % blockBytes;
        Span<byte> block = stackalloc byte[blockBytes];
        ReadOnlySpan<byte> previous = iv;
        for (int offset = 0; offset < fullBytes; offset += blockBytes)
        {
            plaintext.Slice(offset, blockBytes).CopyTo(block);
            ByteXor.Xor(block, previous, block);
            engine.EncryptBlocks(roundKeys, block, destination.Slice(offset, blockBytes));
            previous = destination.Slice(offset, blockBytes);
        }

        if (padding == PaddingMode.PKCS7)
        {
            Pkcs7.Pad(plaintext.Slice(fullBytes), block);
            ByteXor.Xor(block, previous, block);
            engine.EncryptBlocks(roundKeys, block, destination.Slice(fullBytes, blockBytes));
        }

        CryptographicOperations.ZeroMemory(block);
    }

    // Returns the plaintext length. Destination must hold the whole ciphertext, which may be the same span.
    // With PaddingMode.None the plaintext length is the ciphertext length and no padding is checked.
    internal static int Decrypt(
        BlockEngine engine,
        ReadOnlySpan<byte> roundKeys,
        ReadOnlySpan<byte> ciphertext,
        ReadOnlySpan<byte> iv,
        Span<byte> destination,
        PaddingMode padding = PaddingMode.PKCS7)
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
                Span<byte> outputBlock = output.Slice(position, blockBytes);
                ByteXor.Xor(outputBlock, prior, outputBlock);
            }

            batch.Slice(length - blockBytes, blockBytes).CopyTo(previous);
        }

        CryptographicOperations.ZeroMemory(batch);
        CryptographicOperations.ZeroMemory(previous);

        if (padding == PaddingMode.None)
        {
            return ciphertext.Length;
        }

        int lastOffset = ciphertext.Length - blockBytes;
        int unpaddedLength = Pkcs7.GetUnpaddedLength(destination.Slice(lastOffset, blockBytes));
        if (unpaddedLength < 0)
        {
            CryptographicOperations.ZeroMemory(destination);
            throw new CryptographicException(DecryptFailure.Message);
        }

        int plaintextLength = lastOffset + unpaddedLength;
        CryptographicOperations.ZeroMemory(destination.Slice(plaintextLength, ciphertext.Length - plaintextLength));
        return plaintextLength;
    }
}
