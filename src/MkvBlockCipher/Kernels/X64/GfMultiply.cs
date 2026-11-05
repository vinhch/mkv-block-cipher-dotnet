using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;
using MkvBlockCipher.Primitives;

namespace MkvBlockCipher.Kernels.X64;

// Products by a public constant. The constant picks a matrix or a nibble table; the data only reaches shuffles
// and bitwise arithmetic, never a branch or an index.
internal static class GfMultiply
{
    private static readonly ulong[] AffineMatrices = BuildAffineMatrices();

    internal static Vector128<byte> Multiply(Vector128<byte> x, byte constant) =>
        Gfni.IsSupported ? MultiplyGfni(x, constant) : MultiplyNibble(x, constant);

    internal static Vector256<byte> Multiply(Vector256<byte> x, byte constant) =>
        Gfni.V256.IsSupported ? MultiplyGfni(x, constant) : MultiplyNibble(x, constant);

    internal static Vector128<byte> MultiplyGfni(Vector128<byte> x, byte constant) =>
        Gfni.GaloisFieldAffineTransform(x, Vector128.Create(AffineMatrices[constant]).AsByte(), 0);

    internal static Vector256<byte> MultiplyGfni(Vector256<byte> x, byte constant) =>
        Gfni.V256.GaloisFieldAffineTransform(x, Vector256.Create(AffineMatrices[constant]).AsByte(), 0);

    internal static Vector512<byte> MultiplyGfni(Vector512<byte> x, byte constant) =>
        Gfni.V512.GaloisFieldAffineTransform(x, Vector512.Create(AffineMatrices[constant]).AsByte(), 0);

    internal static Vector128<byte> MultiplyNibble(Vector128<byte> x, byte constant)
    {
        Vector128<byte> mask = Vector128.Create((byte)0x0F);
        Vector128<byte> lowNibble = x & mask;
        Vector128<byte> highNibble = Sse2.ShiftRightLogical(x.AsUInt16(), 4).AsByte() & mask;
        Vector128<byte> low = Ssse3.Shuffle(Vector128.Create(GfNibbleTables.Low(constant)), lowNibble);
        Vector128<byte> high = Ssse3.Shuffle(Vector128.Create(GfNibbleTables.High(constant)), highNibble);
        return low ^ high;
    }

    internal static Vector256<byte> MultiplyNibble(Vector256<byte> x, byte constant)
    {
        Vector256<byte> mask = Vector256.Create((byte)0x0F);
        Vector256<byte> lowNibble = x & mask;
        Vector256<byte> highNibble = Vector256.ShiftRightLogical(x.AsUInt16(), 4).AsByte() & mask;
        Vector256<byte> low = LaneShuffle.Shuffle(LaneShuffle.BroadcastRow(GfNibbleTables.Low(constant)), lowNibble);
        Vector256<byte> high = LaneShuffle.Shuffle(LaneShuffle.BroadcastRow(GfNibbleTables.High(constant)), highNibble);
        return low ^ high;
    }

    // Column j of the matrix is constant times x^j.
    internal static ulong AffineMatrix(byte constant)
    {
        Span<byte> columns = stackalloc byte[8];
        for (int input = 0; input < 8; input++)
        {
            columns[input] = GaloisField.Multiply(constant, (byte)(1 << input));
        }

        return GfAffine.FromColumns(columns);
    }

    private static ulong[] BuildAffineMatrices()
    {
        ulong[] matrices = new ulong[256];
        for (int constant = 0; constant < 256; constant++)
        {
            matrices[constant] = AffineMatrix((byte)constant);
        }

        return matrices;
    }
}
