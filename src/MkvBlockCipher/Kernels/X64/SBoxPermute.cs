using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;
using MkvBlockCipher.Primitives;

namespace MkvBlockCipher.Kernels.X64;

// Table lookup by VPERMI2B. One instruction reads 128 bytes with a 7-bit index, so the 256 entries take two lookups.
// Tables holds four 64-byte blocks: entries 0-63, 64-127, 128-191 and 192-255. The first lookup reads blocks 0 and 1,
// the second reads blocks 2 and 3. Callers check Avx512Vbmi.IsSupported.
internal static class SBoxPermute
{
    private static readonly Vector512<byte>[] ForwardTables = BuildTables(SBoxTables.Forward);
    private static readonly Vector512<byte>[] InverseTables = BuildTables(SBoxTables.Inverse);

    internal static ReadOnlySpan<Vector512<byte>> Tables(bool inverse) => inverse ? InverseTables : ForwardTables;

    internal static Vector512<byte> Lookup(Vector512<byte> x, ReadOnlySpan<Vector512<byte>> tables)
    {
        // Bit 7 selects the result below, so the 7-bit index drops it.
        Vector512<byte> index = x & Vector512.Create((byte)0x7F);
        Vector512<byte> lowHalf = Avx512Vbmi.PermuteVar64x8x2(tables[0], index, tables[1]);
        Vector512<byte> highHalf = Avx512Vbmi.PermuteVar64x8x2(tables[2], index, tables[3]);
        Vector512<byte> isHighHalf = Vector512.LessThan(x.AsSByte(), Vector512<sbyte>.Zero).AsByte();
        return Vector512.ConditionalSelect(isHighHalf, highHalf, lowHalf);
    }

    private static Vector512<byte>[] BuildTables(ReadOnlySpan<byte> table)
    {
        Vector512<byte>[] tables = new Vector512<byte>[4];
        for (int block = 0; block < 4; block++)
        {
            tables[block] = Vector512.Create(table.Slice(64 * block, 64));
        }

        return tables;
    }
}
