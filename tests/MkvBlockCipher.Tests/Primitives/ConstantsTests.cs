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
}
