namespace MkvBlockCipher.Modes;

// The counter block is the whole block read as one big-endian integer. It never wraps: a call that would
// pass all-ones is refused before any output is written.
internal static class CounterBlock
{
    // Adds blockCount - 1 to the counter from the low byte up. A carry left past the top byte is a wrap.
    internal static void ThrowIfWouldWrap(ReadOnlySpan<byte> counter, long blockCount, string paramName)
    {
        ulong carry = (ulong)Math.Max(blockCount - 1, 0);
        for (int i = counter.Length - 1; i >= 0 && carry != 0; i--)
        {
            carry = (carry >> 8) + (((ulong)counter[i] + (carry & 0xFF)) >> 8);
        }

        if (carry != 0)
        {
            throw new ArgumentException("The counter would wrap past all-ones for this length.", paramName);
        }
    }

    // Block i of the span is initial plus firstIndex + i.
    internal static void Fill(Span<byte> counters, ReadOnlySpan<byte> initial, long firstIndex)
    {
        int blockBytes = initial.Length;
        for (int offset = 0; offset < counters.Length; offset += blockBytes)
        {
            Span<byte> counter = counters.Slice(offset, blockBytes);
            initial.CopyTo(counter);
            AddInPlace(counter, (ulong)(firstIndex + offset / blockBytes));
        }
    }

    // The carry out of the top byte is dropped: callers rule out a wrap with ThrowIfWouldWrap first.
    private static void AddInPlace(Span<byte> counter, ulong amount)
    {
        ulong carry = amount;
        for (int i = counter.Length - 1; i >= 0 && carry != 0; i--)
        {
            ulong sum = counter[i] + (carry & 0xFF);
            counter[i] = (byte)sum;
            carry = (carry >> 8) + (sum >> 8);
        }
    }
}
