using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;
using MkvBlockCipher.Primitives;

namespace MkvBlockCipher.Kernels.X64;

// Products by a public constant. The constant picks a matrix or a nibble table; the data only reaches shuffles
// and bitwise arithmetic, never a branch or an index.
internal static class GfMultiply
{
    private static readonly Vector128<byte>[] AffineMatrices128 = BuildAffineMatrices128();
    private static readonly Vector256<byte>[] AffineMatrices256 = BuildAffineMatrices256();

    internal static Vector128<byte> Multiply(Vector128<byte> x, byte constant) =>
        Gfni.IsSupported ? MultiplyGfni(x, constant) : MultiplyNibble(x, constant);

    internal static Vector256<byte> Multiply(Vector256<byte> x, byte constant) =>
        Gfni.V256.IsSupported ? MultiplyGfni(x, constant) : MultiplyNibble(x, constant);

    internal static Vector128<byte> MultiplyGfni(Vector128<byte> x, byte constant) =>
        Gfni.GaloisFieldAffineTransform(x, AffineMatrices128[constant], 0);

    internal static Vector256<byte> MultiplyGfni(Vector256<byte> x, byte constant) =>
        Gfni.V256.GaloisFieldAffineTransform(x, AffineMatrices256[constant], 0);

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

    // Column j of the matrix is constant times x^j. The instruction reads row i from byte 7 - i of the qword,
    // and bit j of each row weights input bit j.
    internal static ulong AffineMatrix(byte constant)
    {
        ulong matrix = 0;
        for (int input = 0; input < 8; input++)
        {
            byte column = GaloisField.Multiply(constant, (byte)(1 << input));
            for (int row = 0; row < 8; row++)
            {
                if (((column >> row) & 1) != 0)
                {
                    matrix |= 1UL << (8 * (7 - row) + input);
                }
            }
        }

        return matrix;
    }

    private static Vector128<byte>[] BuildAffineMatrices128()
    {
        Vector128<byte>[] matrices = new Vector128<byte>[256];
        for (int constant = 0; constant < 256; constant++)
        {
            matrices[constant] = Vector128.Create(AffineMatrix((byte)constant)).AsByte();
        }

        return matrices;
    }

    private static Vector256<byte>[] BuildAffineMatrices256()
    {
        Vector256<byte>[] matrices = new Vector256<byte>[256];
        for (int constant = 0; constant < 256; constant++)
        {
            matrices[constant] = Vector256.Create(AffineMatrix((byte)constant)).AsByte();
        }

        return matrices;
    }
}
