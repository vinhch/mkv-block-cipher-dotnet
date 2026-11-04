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
            ByteXor.Xor(source.Slice(offset, length), keystream.Slice(0, length), destination.Slice(offset, length));
            offset += length;
            firstBlock += batchBlocks;
        }

        CryptographicOperations.ZeroMemory(scratch);
    }
}
