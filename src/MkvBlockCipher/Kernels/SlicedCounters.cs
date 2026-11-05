using System.Buffers.Binary;

namespace MkvBlockCipher.Kernels;

// Counter blocks for one batch in byte-sliced form: byte p of lane b sits at index p * lanes + b. The result is
// CounterBlock.Fill followed by ByteSlice.Gather, without the block-major copy. sliced holds initial.Length * lanes
// bytes.
internal static class SlicedCounters
{
    private const int LowWordBytes = 8;

    // Bytes above the low word match in every lane unless a carry reaches them, so they are broadcast first. The
    // low word takes a 64-bit add per lane, and that add's carry ripples up through the higher bytes.
    internal static void Fill(ReadOnlySpan<byte> initial, long firstIndex, int lanes, Span<byte> sliced)
    {
        int highBytes = initial.Length - LowWordBytes;
        for (int position = 0; position < highBytes; position++)
        {
            sliced.Slice(position * lanes, lanes).Fill(initial[position]);
        }

        ulong low = BinaryPrimitives.ReadUInt64BigEndian(initial.Slice(highBytes));
        for (int lane = 0; lane < lanes; lane++)
        {
            ulong sum = low + (ulong)(firstIndex + lane);
            // Big-endian: k = 0 is the top byte of the low word.
            for (int k = 0; k < LowWordBytes; k++)
            {
                sliced[(highBytes + k) * lanes + lane] = (byte)(sum >> (56 - 8 * k));
            }

            // The add wrapped past 2^64 exactly when the sum fell below the initial low word.
            bool carry = sum < low;
            for (int position = highBytes - 1; position >= 0 && carry; position--)
            {
                byte next = (byte)(initial[position] + 1);
                sliced[position * lanes + lane] = next;
                carry = next == 0;
            }
        }
    }
}
