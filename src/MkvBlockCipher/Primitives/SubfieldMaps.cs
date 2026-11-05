using System.Numerics;

namespace MkvBlockCipher.Primitives;

// GF(2^4) inside GF(2^8) mod 0x11B, the field GFNI computes in. Nibble n embeds as the sum of n_i * beta^i, with
// beta = 0x5C, a root of t^4 + t + 1. Every map here is GF(2)-linear, so each one is a single GfAffine matrix.
internal static class SubfieldMaps
{
    private const byte Beta = 0x5C;

    // x^8 + x^4 + x^3 + x + 1, the field of GF2P8MULB. GaloisField uses 0x12B for the mix matrices.
    private const int Polynomial = 0x11B;

    // Static fields initialize in textual order: the matrices below read Basis and Rows.
    private static readonly byte[] Basis = BuildBasis();
    private static readonly byte[] Rows = BuildRows();

    // Column j is the image of input bit j. Each embedding reads one nibble and ignores the other.
    internal static readonly ulong EmbedHigh =
        GfAffine.FromColumns([0, 0, 0, 0, Basis[0], Basis[1], Basis[2], Basis[3]]);
    internal static readonly ulong EmbedLow =
        GfAffine.FromColumns([Basis[0], Basis[1], Basis[2], Basis[3], 0, 0, 0, 0]);
    internal static readonly ulong Identity = GfAffine.FromColumns([0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80]);
    internal static readonly ulong Square = Frobenius(1);
    internal static readonly ulong Fourth = Frobenius(2);
    internal static readonly ulong Eighth = Frobenius(3);

    // Back-maps only see subfield elements, where they invert the embedding. Elsewhere they are a linear extension.
    internal static readonly ulong BackHigh = BackMap(4);
    internal static readonly ulong BackLow = BackMap(0);

    // Basis[i] = beta^i, the embedding of nibble 1 << i.
    private static byte[] BuildBasis()
    {
        byte[] basis = new byte[4];
        byte power = 1;
        for (int i = 0; i < 4; i++)
        {
            basis[i] = power;
            power = Multiply(power, Beta);
        }

        return basis;
    }

    // Rows[k] is a mask whose parity against Basis[i] is 1 exactly when i == k: it reads bit k
    // of an embedded nibble.
    private static byte[] BuildRows()
    {
        byte[] rows = new byte[4];
        for (int k = 0; k < 4; k++)
        {
            for (int mask = 1; mask < 256; mask++)
            {
                if (IsRow(mask, k))
                {
                    rows[k] = (byte)mask;
                    break;
                }
            }
        }

        return rows;
    }

    private static bool IsRow(int mask, int k)
    {
        for (int i = 0; i < 4; i++)
        {
            int parity = BitOperations.PopCount((uint)(mask & Basis[i])) & 1;
            if (parity != (i == k ? 1 : 0))
            {
                return false;
            }
        }

        return true;
    }

    // Column j of a back-map: input bit j sets output bit k, shifted to firstBit, when it is set in Rows[k].
    private static ulong BackMap(int firstBit)
    {
        Span<byte> columns = stackalloc byte[8];
        for (int input = 0; input < 8; input++)
        {
            int column = 0;
            for (int k = 0; k < 4; k++)
            {
                column |= ((Rows[k] >> input) & 1) << k;
            }

            columns[input] = (byte)(column << firstBit);
        }

        return GfAffine.FromColumns(columns);
    }

    // x -> x^(2^squarings): column j is the image of 1 << j.
    private static ulong Frobenius(int squarings)
    {
        Span<byte> columns = stackalloc byte[8];
        for (int input = 0; input < 8; input++)
        {
            byte image = (byte)(1 << input);
            for (int step = 0; step < squarings; step++)
            {
                image = Multiply(image, image);
            }

            columns[input] = image;
        }

        return GfAffine.FromColumns(columns);
    }

    // Product in GF(2^8) mod Polynomial. Runs at type init on public constants only.
    private static byte Multiply(byte a, byte b)
    {
        int product = 0;
        int shifted = a;
        for (int bit = 0; bit < 8; bit++)
        {
            if (((b >> bit) & 1) != 0)
            {
                product ^= shifted;
            }

            shifted <<= 1;
            if ((shifted & 0x100) != 0)
            {
                shifted ^= Polynomial;
            }
        }

        return (byte)product;
    }
}
