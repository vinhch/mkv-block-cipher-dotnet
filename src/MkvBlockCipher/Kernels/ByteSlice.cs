namespace MkvBlockCipher.Kernels;

// Converts between block-major bytes and byte-major lanes: byte p of block b sits at index p * lanes + b.
// Only public indices are used, so the copy never depends on the data.
internal static class ByteSlice
{
    internal static void Gather(ReadOnlySpan<byte> blocks, int blockBytes, Span<byte> sliced)
    {
        int lanes = blocks.Length / blockBytes;
        for (int lane = 0; lane < lanes; lane++)
        {
            for (int position = 0; position < blockBytes; position++)
            {
                sliced[position * lanes + lane] = blocks[lane * blockBytes + position];
            }
        }
    }

    internal static void Scatter(ReadOnlySpan<byte> sliced, int blockBytes, Span<byte> blocks)
    {
        int lanes = blocks.Length / blockBytes;
        for (int lane = 0; lane < lanes; lane++)
        {
            for (int position = 0; position < blockBytes; position++)
            {
                blocks[lane * blockBytes + position] = sliced[position * lanes + lane];
            }
        }
    }
}
