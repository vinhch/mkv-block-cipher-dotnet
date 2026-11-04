using MkvBlockCipher.Primitives;
using Xunit;

namespace MkvBlockCipher.Tests.Primitives;

public sealed class ConstantsTests
{
    [Fact]
    public void SBox_inverse_round_trips_all_bytes()
    {
        for (int x = 0; x < 256; x++)
        {
            Assert.Equal((byte)x, SBoxTables.Inverse[SBoxTables.Forward[x]]);
        }
    }

    [Fact]
    public void Spot_values()
    {
        Assert.Equal((byte)0x1C, SBoxTables.Forward[0x24]);
        Assert.Equal((byte)0xB4, SBoxTables.Inverse[0x82]);
        Assert.Equal((byte)0x14, SBoxTables.Forward[0xEB]);
    }

    [Theory]
    [InlineData(4)]
    [InlineData(8)]
    public void Matrix_times_inverse_is_identity(int size)
    {
        ReadOnlySpan<byte> matrix = size == 4 ? MixMatrices.M4 : MixMatrices.M8;
        ReadOnlySpan<byte> inverse = size == 4 ? MixMatrices.M4Inverse : MixMatrices.M8Inverse;

        for (int row = 0; row < size; row++)
        {
            for (int col = 0; col < size; col++)
            {
                byte sum = 0;
                for (int k = 0; k < size; k++)
                {
                    sum ^= GaloisField.Multiply(matrix[row * size + k], inverse[k * size + col]);
                }

                Assert.Equal((byte)(row == col ? 1 : 0), sum);
            }
        }
    }

    [Theory]
    [InlineData((byte)0x02, (byte)0x80, (byte)0x2B)]
    [InlineData((byte)0x03, (byte)0xFF, (byte)0x2A)]
    public void Multiply_matches_reference(byte constant, byte value, byte expected)
    {
        Assert.Equal(expected, GaloisField.Multiply(constant, value));
    }

    [Theory]
    [InlineData((byte)0x00, (byte)0xA7, (byte)0x00)]
    [InlineData((byte)0x01, (byte)0xA7, (byte)0xA7)]
    [InlineData((byte)0xFF, (byte)0x00, (byte)0x00)]
    public void Multiply_identity_and_zero_cases(byte constant, byte value, byte expected)
    {
        Assert.Equal(expected, GaloisField.Multiply(constant, value));
    }

    [Fact]
    public void SBox_matches_butterfly_construction()
    {
        byte[] expected = new byte[256];
        for (int x = 0; x < 256; x++)
        {
            expected[x] = (byte)(ButterflySBox(x) ^ 1);
        }

        Assert.Equal(expected, SBoxTables.Forward.ToArray());
    }

    [Fact]
    public void M4_is_fourth_power_of_companion()
    {
        byte[] companion = Companion(0x01, 0x02, 0x01, 0x03);

        Assert.Equal(MatrixPower(companion, 4, 4), MixMatrices.M4.ToArray());
    }

    [Fact]
    public void M8_is_eighth_power_of_companion()
    {
        byte[] companion = Companion(0x01, 0x04, 0xDB, 0x0C, 0x14, 0x0C, 0xDB, 0x04);

        Assert.Equal(MatrixPower(companion, 8, 8), MixMatrices.M8.ToArray());
    }

    // Butterfly construction over GF(2^4): xl and xr are the high and low nibbles. Here inv(0) = 0.
    private static int ButterflySBox(int x)
    {
        int xl = x >> 4;
        int xr = x & 0xF;
        int yr = xr != 0 ? Gf16Multiply(Gf16Power(Gf16Inverse(xl), 4), xr) : Gf16Inverse(xl);
        int yl = yr != 0 ? Gf16Power(Gf16Inverse(Gf16Multiply(xr, yr)), 2) : Gf16Inverse(xr);
        return (yl << 4) | yr;
    }

    // GF(2^4) modulo x^4 + x + 1.
    private static int Gf16Multiply(int a, int b)
    {
        int product = 0;
        for (int bit = 0; bit < 4; bit++)
        {
            if (((b >> bit) & 1) != 0)
            {
                product ^= a;
            }

            a <<= 1;
            if ((a & 0x10) != 0)
            {
                a ^= 0x13;
            }
        }

        return product;
    }

    private static int Gf16Power(int a, int exponent)
    {
        int result = 1;
        for (int i = 0; i < exponent; i++)
        {
            result = Gf16Multiply(result, a);
        }

        return result;
    }

    // Returns 0 for a = 0, because no nonzero b gives a product of 1.
    private static int Gf16Inverse(int a)
    {
        for (int b = 1; b < 16; b++)
        {
            if (Gf16Multiply(a, b) == 1)
            {
                return b;
            }
        }

        return 0;
    }

    // Ones on the superdiagonal, the coefficients in the last row.
    private static byte[] Companion(params byte[] coefficients)
    {
        int size = coefficients.Length;
        byte[] matrix = new byte[size * size];
        for (int row = 0; row < size - 1; row++)
        {
            matrix[row * size + row + 1] = 1;
        }

        coefficients.CopyTo(matrix, (size - 1) * size);
        return matrix;
    }

    private static byte[] MatrixPower(byte[] matrix, int size, int power)
    {
        byte[] result = new byte[size * size];
        for (int i = 0; i < size; i++)
        {
            result[i * size + i] = 1;
        }

        for (int p = 0; p < power; p++)
        {
            result = MatrixMultiply(result, matrix, size);
        }

        return result;
    }

    private static byte[] MatrixMultiply(byte[] left, byte[] right, int size)
    {
        byte[] product = new byte[size * size];
        for (int row = 0; row < size; row++)
        {
            for (int col = 0; col < size; col++)
            {
                byte sum = 0;
                for (int k = 0; k < size; k++)
                {
                    sum ^= GaloisField.Multiply(left[row * size + k], right[k * size + col]);
                }

                product[row * size + col] = sum;
            }
        }

        return product;
    }
}
