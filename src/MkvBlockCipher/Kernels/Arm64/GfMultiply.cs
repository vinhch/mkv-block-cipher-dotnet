using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.Arm;

namespace MkvBlockCipher.Kernels.Arm64;

// Products by a public constant: one 16-entry lookup per nibble, then XOR. The constant picks the tables; the data
// only reaches lookup indices and bitwise arithmetic.
internal static class GfMultiply
{
    internal static Vector128<byte> Multiply(Vector128<byte> x, byte constant)
    {
        Vector128<byte> lowNibble = x & Vector128.Create((byte)0x0F);
        // Byte-wide shift: the result already fits in one nibble.
        Vector128<byte> highNibble = Vector128.ShiftRightLogical(x, 4);
        Vector128<byte> low = AdvSimd.Arm64.VectorTableLookup(Vector128.Create(GfNibbleTables.Low(constant)), lowNibble);
        Vector128<byte> high = AdvSimd.Arm64.VectorTableLookup(Vector128.Create(GfNibbleTables.High(constant)), highNibble);
        return low ^ high;
    }
}
