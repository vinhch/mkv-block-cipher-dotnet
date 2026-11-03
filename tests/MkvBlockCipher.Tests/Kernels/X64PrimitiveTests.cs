using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;
using MkvBlockCipher.Kernels.X64;
using MkvBlockCipher.Primitives;
using Xunit;

namespace MkvBlockCipher.Tests.Kernels;

public sealed class X64PrimitiveTests
{
    private const string SkipReason = "Needs SSSE3, which this machine lacks.";

    public static bool X64Supported => X64Engine.IsSupported;

    [Theory(SkipUnless = nameof(X64Supported), Skip = SkipReason)]
    [InlineData(false)]
    [InlineData(true)]
    public void SBoxShuffle_matches_table_all_bytes(bool inverse)
    {
        ReadOnlySpan<byte> table = inverse ? SBoxTables.Inverse : SBoxTables.Forward;

        for (int start = 0; start < 256; start += 16)
        {
            ReadOnlySpan<byte> input = Values(start, 16);
            Vector128<byte> output = SBoxShuffle.Lookup(Vector128.Create(input), table);
            AssertLanes(Expected(table, input), output);
        }

        for (int start = 0; start < 256; start += 32)
        {
            ReadOnlySpan<byte> input = Values(start, 32);
            Vector256<byte> output = SBoxShuffle.Lookup(Vector256.Create(input), table);
            AssertLanes(Expected(table, input), output);
        }
    }

    [Fact(SkipUnless = nameof(X64Supported), Skip = SkipReason)]
    public void GfMultiply_matches_scalar()
    {
        foreach (byte constant in MatrixConstants())
        {
            for (int start = 0; start < 256; start += 16)
            {
                ReadOnlySpan<byte> values = Values(start, 16);
                byte[] expected = Expected(constant, values);
                Vector128<byte> input = Vector128.Create(values);

                AssertLanes(expected, GfMultiply.MultiplyNibble(input, constant));
                AssertLanes(expected, GfMultiply.Multiply(input, constant));
                if (Gfni.IsSupported)
                {
                    AssertLanes(expected, GfMultiply.MultiplyGfni(input, constant));
                }
            }

            for (int start = 0; start < 256; start += 32)
            {
                ReadOnlySpan<byte> values = Values(start, 32);
                byte[] expected = Expected(constant, values);
                Vector256<byte> input = Vector256.Create(values);

                AssertLanes(expected, GfMultiply.MultiplyNibble(input, constant));
                AssertLanes(expected, GfMultiply.Multiply(input, constant));
                if (Gfni.V256.IsSupported)
                {
                    AssertLanes(expected, GfMultiply.MultiplyGfni(input, constant));
                }
            }
        }
    }

    // Every entry of the four mixing matrices. Each entry is a multiplier the engine applies.
    private static HashSet<byte> MatrixConstants()
    {
        HashSet<byte> constants = [];
        foreach (byte[] matrix in new[]
        {
            MixMatrices.M4.ToArray(),
            MixMatrices.M4Inverse.ToArray(),
            MixMatrices.M8.ToArray(),
            MixMatrices.M8Inverse.ToArray(),
        })
        {
            constants.UnionWith(matrix);
        }

        return constants;
    }

    private static byte[] Values(int start, int count)
    {
        byte[] values = new byte[count];
        for (int i = 0; i < count; i++)
        {
            values[i] = (byte)(start + i);
        }

        return values;
    }

    private static byte[] Expected(ReadOnlySpan<byte> table, ReadOnlySpan<byte> input)
    {
        byte[] expected = new byte[input.Length];
        for (int i = 0; i < input.Length; i++)
        {
            expected[i] = table[input[i]];
        }

        return expected;
    }

    private static byte[] Expected(byte constant, ReadOnlySpan<byte> values)
    {
        byte[] expected = new byte[values.Length];
        for (int i = 0; i < values.Length; i++)
        {
            expected[i] = GaloisField.Multiply(constant, values[i]);
        }

        return expected;
    }

    private static void AssertLanes(byte[] expected, Vector128<byte> actual)
    {
        byte[] lanes = new byte[Vector128<byte>.Count];
        actual.CopyTo(lanes);
        Assert.Equal(expected, lanes);
    }

    private static void AssertLanes(byte[] expected, Vector256<byte> actual)
    {
        byte[] lanes = new byte[Vector256<byte>.Count];
        actual.CopyTo(lanes);
        Assert.Equal(expected, lanes);
    }
}
