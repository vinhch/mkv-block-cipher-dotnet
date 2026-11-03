namespace MkvBlockCipher.Modes;

// Every byte of the block is read and the result is built from masks, so the time taken does not depend on
// where the padding starts or whether it is valid.
internal static class Pkcs7
{
    // The tail must be shorter than the block: the padding is at least one byte.
    internal static void Pad(ReadOnlySpan<byte> tail, Span<byte> lastBlock)
    {
        tail.CopyTo(lastBlock);
        lastBlock.Slice(tail.Length).Fill((byte)(lastBlock.Length - tail.Length));
    }

    // Returns the data length in the block, or -1 when the padding is not valid. The block must not be empty.
    internal static int GetUnpaddedLength(ReadOnlySpan<byte> lastBlock)
    {
        int blockBytes = lastBlock.Length;
        int padCount = lastBlock[blockBytes - 1];
        int padStart = blockBytes - padCount;

        // A count of 0 or above the block size fails here. Inside the block, every byte from padStart on must equal the count.
        int failed = SignMask(padCount - 1) | SignMask(padStart);
        for (int i = 0; i < blockBytes; i++)
        {
            int paddingMask = ~SignMask(i - padStart);
            failed |= (lastBlock[i] ^ padCount) & paddingMask;
        }

        // Any nonzero failure value becomes -1, so every invalid block returns the same value.
        return (blockBytes - padCount) | SignMask(failed | -failed);
    }

    // -1 when the value is negative, else 0.
    private static int SignMask(int value) => value >> 31;
}
