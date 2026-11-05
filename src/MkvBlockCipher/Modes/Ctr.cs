using System.Security.Cryptography;
using MkvBlockCipher.Kernels;

namespace MkvBlockCipher.Modes;

// The stack copies are cleared; register values are not.
internal static class Ctr
{
    // Counters and keystream share one scratch buffer. Each batch overwrites the part it uses,
    // so one clear at the end covers all of it.
    // firstBlock is the index of source's first block in the whole message, so a chunk continues the keystream.
    internal static void Transform(
        BlockEngine engine,
        ReadOnlySpan<byte> roundKeys,
        ReadOnlySpan<byte> initialCounter,
        ReadOnlySpan<byte> source,
        Span<byte> destination,
        long firstBlock = 0)
    {
        int blockBytes = engine.Parameters.BlockBytes;
        long blockCount = ((long)source.Length + blockBytes - 1) / blockBytes;
        // Counted from the initial counter, so the check covers firstBlock through the last block.
        long endBlock = firstBlock + blockCount;
        CounterBlock.ThrowIfWouldWrap(initialCounter, endBlock, nameof(source));

        Span<byte> scratch = stackalloc byte[engine.BatchBlocks * blockBytes];
        int offset = 0;
        long nextBlock = firstBlock;
        while (offset < source.Length)
        {
            int batchBlocks = (int)Math.Min(engine.BatchBlocks, endBlock - nextBlock);
            Span<byte> keystream = scratch.Slice(0, batchBlocks * blockBytes);
            CounterBlock.Fill(keystream, initialCounter, nextBlock);
            engine.EncryptBlocks(roundKeys, keystream, keystream);

            int length = Math.Min(keystream.Length, source.Length - offset);
            ByteXor.Xor(source.Slice(offset, length), keystream.Slice(0, length), destination.Slice(offset, length));
            offset += length;
            nextBlock += batchBlocks;
        }

        CryptographicOperations.ZeroMemory(scratch);
    }
}
