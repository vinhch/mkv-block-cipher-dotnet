using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.Arm;
using MkvBlockCipher.Primitives;

namespace MkvBlockCipher.Kernels.Arm64;

// 256 entries are more than the 64 bytes one four-register lookup reaches. The first lookup writes zero for an index
// past its table, and each extension keeps the destination lane it does not match, so every byte takes the one block
// that holds it. Each block indexes from its own start, so the index drops by 64 per block.
internal static class SBoxTableLookup
{
    private static readonly Vector128<byte>[] ForwardEntries = BuildEntries(SBoxTables.Forward);
    private static readonly Vector128<byte>[] InverseEntries = BuildEntries(SBoxTables.Inverse);

    internal static ReadOnlySpan<Vector128<byte>> Entries(bool inverse) => inverse ? InverseEntries : ForwardEntries;

    internal static Vector128<byte> Lookup(Vector128<byte> x, ReadOnlySpan<Vector128<byte>> entries)
    {
        Vector128<byte> result = AdvSimd.Arm64.VectorTableLookup(Entries64(entries, 0), x);
        Vector128<byte> index = x;
        for (int first = 64; first < 256; first += 64)
        {
            index -= Vector128.Create((byte)64);
            result = AdvSimd.Arm64.VectorTableLookupExtension(result, Entries64(entries, first), index);
        }

        return result;
    }

    // Entries first to first + 63 held in four registers, in the order the table instructions index them.
    private static (Vector128<byte>, Vector128<byte>, Vector128<byte>, Vector128<byte>) Entries64(
        ReadOnlySpan<Vector128<byte>> entries, int first)
    {
        int firstVector = first / 16;
        return (
            entries[firstVector],
            entries[firstVector + 1],
            entries[firstVector + 2],
            entries[firstVector + 3]);
    }

    private static Vector128<byte>[] BuildEntries(ReadOnlySpan<byte> table)
    {
        Vector128<byte>[] entries = new Vector128<byte>[16];
        for (int vector = 0; vector < 16; vector++)
        {
            entries[vector] = Vector128.Create(table.Slice(16 * vector, 16));
        }

        return entries;
    }
}
