using System.Numerics;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;
using MkvBlockCipher.Kernels.X64;
using MkvBlockCipher.Primitives;
using Xunit;

namespace MkvBlockCipher.Tests.Kernels;

public sealed class X64PrimitiveTests
{
    private const string SkipReason = "Needs SSSE3, which this machine lacks.";
    private const string GfniSkipReason = "Needs GFNI, which this machine lacks.";
    private const string Gfni512SkipReason = "Needs AVX-512 with GFNI, which this machine lacks.";
    private const string VbmiSkipReason = "Needs AVX-512 VBMI, which this machine lacks.";

    public static bool X64Supported => X64Engine.IsSupported;

    public static bool GfniSupported => Gfni.IsSupported;

    public static bool Gfni512Supported => Gfni.V512.IsSupported;

    public static bool VbmiSupported => Avx512Vbmi.IsSupported;

    [Theory(SkipUnless = nameof(X64Supported), Skip = SkipReason)]
    [InlineData(false)]
    [InlineData(true)]
    public void SBoxShuffle_matches_table_all_bytes(bool inverse)
    {
        ReadOnlySpan<byte> table = inverse ? SBoxTables.Inverse : SBoxTables.Forward;

        for (int start = 0; start < 256; start += 16)
        {
            ReadOnlySpan<byte> input = Values(start, 16);
            Vector128<byte> output = SBoxShuffle.Lookup(Vector128.Create(input), SBoxShuffle.Rows128(inverse));
            AssertLanes(Expected(table, input), output);
        }

        for (int start = 0; start < 256; start += 32)
        {
            ReadOnlySpan<byte> input = Values(start, 32);
            Vector256<byte> output = SBoxShuffle.Lookup(Vector256.Create(input), SBoxShuffle.Rows256(inverse));
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

    [Theory(SkipUnless = nameof(GfniSupported), Skip = GfniSkipReason)]
    [InlineData(false)]
    [InlineData(true)]
    public void SBoxGfni_matches_table_all_bytes(bool inverse)
    {
        ReadOnlySpan<byte> table = inverse ? SBoxTables.Inverse : SBoxTables.Forward;

        for (int start = 0; start < 256; start += 16)
        {
            ReadOnlySpan<byte> input = Values(start, 16);
            Vector128<byte> vector = Vector128.Create(input);
            Vector128<byte> output = inverse ? SBoxGfni.Inverse(vector) : SBoxGfni.Forward(vector);
            AssertLanes(Expected(table, input), output);
        }

        if (!Gfni.V256.IsSupported)
        {
            return;
        }

        for (int start = 0; start < 256; start += 32)
        {
            ReadOnlySpan<byte> input = Values(start, 32);
            Vector256<byte> vector = Vector256.Create(input);
            Vector256<byte> output = inverse ? SBoxGfni.Inverse(vector) : SBoxGfni.Forward(vector);
            AssertLanes(Expected(table, input), output);
        }
    }

    [Theory(SkipUnless = nameof(Gfni512Supported), Skip = Gfni512SkipReason)]
    [InlineData(false)]
    [InlineData(true)]
    public void SBoxGfni512_matches_table_all_bytes(bool inverse)
    {
        ReadOnlySpan<byte> table = inverse ? SBoxTables.Inverse : SBoxTables.Forward;

        for (int start = 0; start < 256; start += 64)
        {
            ReadOnlySpan<byte> input = Values(start, 64);
            Vector512<byte> vector = Vector512.Create(input);
            Vector512<byte> output = inverse ? SBoxGfni.Inverse(vector) : SBoxGfni.Forward(vector);
            AssertLanes(Expected(table, input), output);
        }
    }

    [Theory(SkipUnless = nameof(VbmiSupported), Skip = VbmiSkipReason)]
    [InlineData(false)]
    [InlineData(true)]
    public void SBoxPermute_matches_table_all_bytes(bool inverse)
    {
        ReadOnlySpan<byte> table = inverse ? SBoxTables.Inverse : SBoxTables.Forward;

        for (int start = 0; start < 256; start += 64)
        {
            ReadOnlySpan<byte> input = Values(start, 64);
            Vector512<byte> output = SBoxPermute.Lookup(Vector512.Create(input), SBoxPermute.Tables(inverse));
            AssertLanes(Expected(table, input), output);
        }
    }

    // Software model, so it runs on every host: every constant, every input byte.
    [Fact]
    public void GfAffine_FromColumns_matches_constant_multiply()
    {
        byte[] values = Values(0, 256);
        for (int constant = 0; constant < 256; constant++)
        {
            byte[] columns = new byte[8];
            for (int input = 0; input < 8; input++)
            {
                columns[input] = GaloisField.Multiply((byte)constant, (byte)(1 << input));
            }

            ulong matrix = GfAffine.FromColumns(columns);
            Assert.Equal(GfMultiply.AffineMatrix((byte)constant), matrix);
            Assert.Equal(Expected((byte)constant, values), ApplyAffine(matrix, values));
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

    // Output bit i is the parity of row i (byte 7 - i of the qword) and the input, with a zero constant.
    private static byte[] ApplyAffine(ulong matrix, ReadOnlySpan<byte> values)
    {
        byte[] outputs = new byte[values.Length];
        for (int i = 0; i < values.Length; i++)
        {
            int output = 0;
            for (int row = 0; row < 8; row++)
            {
                byte rowBits = (byte)(matrix >> (8 * (7 - row)));
                output |= (BitOperations.PopCount((uint)(rowBits & values[i])) & 1) << row;
            }

            outputs[i] = (byte)output;
        }

        return outputs;
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

    private static void AssertLanes(byte[] expected, Vector512<byte> actual)
    {
        byte[] lanes = new byte[Vector512<byte>.Count];
        actual.CopyTo(lanes);
        Assert.Equal(expected, lanes);
    }
}
