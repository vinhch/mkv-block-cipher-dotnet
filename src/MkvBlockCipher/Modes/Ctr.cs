using System.Security.Cryptography;
using MkvBlockCipher.Kernels;

namespace MkvBlockCipher.Modes;

// The stack copies are cleared; register values are not.
internal static class Ctr
{
    // Counters and keystream share one scratch buffer. Each batch overwrites the part it uses,
    // so one clear at the end covers all of it.
    internal static void Transform(
        BlockEngine engine,
        ReadOnlySpan<byte> roundKeys,
        ReadOnlySpan<byte> initialCounter,
        ReadOnlySpan<byte> source,
        Span<byte> destination)
    {
        int blockBytes = engine.Parameters.BlockBytes;
        long blockCount = ((long)source.Length + blockBytes - 1) / blockBytes;
        CounterBlock.ThrowIfWouldWrap(initialCounter, blockCount, nameof(source));

        Span<byte> scratch = stackalloc byte[engine.BatchBlocks * blockBytes];
        int offset = 0;
        long firstBlock = 0;
        while (offset < source.Length)
        {
            int batchBlocks = (int)Math.Min(engine.BatchBlocks, blockCount - firstBlock);
            Span<byte> keystream = scratch.Slice(0, batchBlocks * blockBytes);
            CounterBlock.Fill(keystream, initialCounter, firstBlock);
            engine.EncryptBlocks(roundKeys, keystream, keystream);

            int length = Math.Min(keystream.Length, source.Length - offset);
            XorInto(source.Slice(offset, length), keystream, destination.Slice(offset, length));
            offset += length;
            firstBlock += batchBlocks;
        }

        CryptographicOperations.ZeroMemory(scratch);
    }

    // Source and destination may be the same span: each byte is read before its own slot is written.
    private static void XorInto(ReadOnlySpan<byte> source, ReadOnlySpan<byte> keystream, Span<byte> destination)
    {
        for (int i = 0; i < source.Length; i++)
        {
            destination[i] = (byte)(source[i] ^ keystream[i]);
        }
    }
}
