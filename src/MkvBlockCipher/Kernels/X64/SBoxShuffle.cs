using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;
using MkvBlockCipher.Primitives;

namespace MkvBlockCipher.Kernels.X64;

// Table lookup by shuffles. The high nibble picks one 16-entry row, the low nibble picks an entry from every row,
// and a compare keeps the row that matched. Every row is read for every byte, so no load depends on the data.
internal static class SBoxShuffle
{
    private static readonly Vector128<byte>[] ForwardRows128 = BuildRows128(SBoxTables.Forward);
    private static readonly Vector128<byte>[] InverseRows128 = BuildRows128(SBoxTables.Inverse);
    private static readonly Vector256<byte>[] ForwardRows256 = BuildRows256(SBoxTables.Forward);
    private static readonly Vector256<byte>[] InverseRows256 = BuildRows256(SBoxTables.Inverse);

    internal static ReadOnlySpan<Vector128<byte>> Rows128(bool inverse) => inverse ? InverseRows128 : ForwardRows128;

    internal static ReadOnlySpan<Vector256<byte>> Rows256(bool inverse) => inverse ? InverseRows256 : ForwardRows256;

    internal static Vector128<byte> Lookup(Vector128<byte> x, ReadOnlySpan<Vector128<byte>> rows)
    {
        Vector128<byte> mask = Vector128.Create((byte)0x0F);
        Vector128<byte> lowNibble = x & mask;
        Vector128<byte> highNibble = Sse2.ShiftRightLogical(x.AsUInt16(), 4).AsByte() & mask;
        Vector128<byte> result = Vector128<byte>.Zero;
        for (int row = 0; row < 16; row++)
        {
            Vector128<byte> entries = Ssse3.Shuffle(rows[row], lowNibble);
            Vector128<byte> inRow = Sse2.CompareEqual(highNibble, Vector128.Create((byte)row));
            result |= entries & inRow;
        }

        return result;
    }

    internal static Vector256<byte> Lookup(Vector256<byte> x, ReadOnlySpan<Vector256<byte>> rows)
    {
        Vector256<byte> mask = Vector256.Create((byte)0x0F);
        Vector256<byte> lowNibble = x & mask;
        Vector256<byte> highNibble = Vector256.ShiftRightLogical(x.AsUInt16(), 4).AsByte() & mask;
        Vector256<byte> result = Vector256<byte>.Zero;
        for (int row = 0; row < 16; row++)
        {
            Vector256<byte> entries = LaneShuffle.Shuffle(rows[row], lowNibble);
            Vector256<byte> inRow = Vector256.Equals(highNibble, Vector256.Create((byte)row));
            result |= entries & inRow;
        }

        return result;
    }

    private static Vector128<byte>[] BuildRows128(ReadOnlySpan<byte> table)
    {
        Vector128<byte>[] rows = new Vector128<byte>[16];
        for (int row = 0; row < 16; row++)
        {
            rows[row] = Vector128.Create(table.Slice(16 * row, 16));
        }

        return rows;
    }

    private static Vector256<byte>[] BuildRows256(ReadOnlySpan<byte> table)
    {
        Vector256<byte>[] rows = new Vector256<byte>[16];
        for (int row = 0; row < 16; row++)
        {
            rows[row] = LaneShuffle.BroadcastRow(table.Slice(16 * row, 16));
        }

        return rows;
    }
}
