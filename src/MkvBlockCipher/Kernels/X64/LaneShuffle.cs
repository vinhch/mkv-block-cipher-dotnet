using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;

namespace MkvBlockCipher.Kernels.X64;

// Byte shuffles that stay inside each 128-bit lane, as PSHUFB does. Indices must be 0 to 15.
internal static class LaneShuffle
{
    internal static Vector256<byte> Shuffle(Vector256<byte> table, Vector256<byte> indices) =>
        Avx2.IsSupported
            ? Avx2.Shuffle(table, indices)
            : Vector256.Create(
                Ssse3.Shuffle(table.GetLower(), indices.GetLower()),
                Ssse3.Shuffle(table.GetUpper(), indices.GetUpper()));

    // One 16-byte table in both lanes, so each lane shuffles against the same entries.
    internal static Vector256<byte> BroadcastRow(ReadOnlySpan<byte> row)
    {
        Vector128<byte> lane = Vector128.Create(row);
        return Vector256.Create(lane, lane);
    }
}
