using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;

namespace MkvBlockCipher.Kernels.X64;

// Table lookup by shuffles. The high nibble picks one 16-entry row, the low nibble picks an entry from every row,
// and a compare keeps the row that matched. Every row is read for every byte, so no load depends on the data.
internal static class SBoxShuffle
{
    internal static Vector128<byte> Lookup(Vector128<byte> x, ReadOnlySpan<byte> table)
    {
        Vector128<byte> mask = Vector128.Create((byte)0x0F);
        Vector128<byte> lowNibble = x & mask;
        Vector128<byte> highNibble = Sse2.ShiftRightLogical(x.AsUInt16(), 4).AsByte() & mask;
        Vector128<byte> result = Vector128<byte>.Zero;
        for (int row = 0; row < 16; row++)
        {
            Vector128<byte> entries = Ssse3.Shuffle(Vector128.Create(table.Slice(16 * row, 16)), lowNibble);
            Vector128<byte> inRow = Sse2.CompareEqual(highNibble, Vector128.Create((byte)row));
            result |= entries & inRow;
        }

        return result;
    }

    internal static Vector256<byte> Lookup(Vector256<byte> x, ReadOnlySpan<byte> table)
    {
        Vector256<byte> mask = Vector256.Create((byte)0x0F);
        Vector256<byte> lowNibble = x & mask;
        Vector256<byte> highNibble = Vector256.ShiftRightLogical(x.AsUInt16(), 4).AsByte() & mask;
        Vector256<byte> result = Vector256<byte>.Zero;
        for (int row = 0; row < 16; row++)
        {
            Vector256<byte> entries = LaneShuffle.Shuffle(LaneShuffle.BroadcastRow(table.Slice(16 * row, 16)), lowNibble);
            Vector256<byte> inRow = Vector256.Equals(highNibble, Vector256.Create((byte)row));
            result |= entries & inRow;
        }

        return result;
    }
}
