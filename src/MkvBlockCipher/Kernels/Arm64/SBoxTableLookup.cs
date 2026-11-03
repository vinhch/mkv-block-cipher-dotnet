using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.Arm;

namespace MkvBlockCipher.Kernels.Arm64;

// 256 entries are more than the 64 bytes one four-register lookup reaches. The first lookup writes zero for an index
// past its table, and each extension keeps the destination lane it does not match, so every byte takes the one block
// that holds it. Each block indexes from its own start, so the index drops by 64 per block.
internal static class SBoxTableLookup
{
    internal static Vector128<byte> Lookup(Vector128<byte> x, ReadOnlySpan<byte> table)
    {
        Vector128<byte> result = AdvSimd.Arm64.VectorTableLookup(Entries64(table, 0), x);
        Vector128<byte> index = x;
        for (int first = 64; first < 256; first += 64)
        {
            index -= Vector128.Create((byte)64);
            result = AdvSimd.Arm64.VectorTableLookupExtension(result, Entries64(table, first), index);
        }

        return result;
    }

    // Entries first to first + 63 held in four registers, in the order the table instructions index them.
    private static (Vector128<byte>, Vector128<byte>, Vector128<byte>, Vector128<byte>) Entries64(
        ReadOnlySpan<byte> table, int first)
    {
        return (
            Vector128.Create(table.Slice(first, 16)),
            Vector128.Create(table.Slice(first + 16, 16)),
            Vector128.Create(table.Slice(first + 32, 16)),
            Vector128.Create(table.Slice(first + 48, 16)));
    }
}
