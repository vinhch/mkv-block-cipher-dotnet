using System.Buffers.Binary;
using System.Runtime.Intrinsics.X86;
using MkvBlockCipher.Modes;
using Xunit;

namespace MkvBlockCipher.Tests.Modes;

public sealed class GhashTests
{
    private const string PclmulSkipReason = "Needs PCLMULQDQ, which this machine lacks.";

    private static readonly byte[] DensePatterns = [0xFF, 0x11, 0x88, 0xAA];

    public static bool PclmulSupported => Pclmulqdq.IsSupported;

    // GCM specification test cases 2 to 4 (AES-128): H, A, C and GHASH copied from the source.
    public static TheoryData<string, string, string, string, string> GcmSpecCases()
    {
        return new TheoryData<string, string, string, string, string>
        {
            {
                "Test case 2",
                "66e94bd4ef8a2c3b884cfa59ca342b2e",
                "",
                "0388dace60b6a392f328c2b971b2fe78",
                "f38cbb1ad69223dcc3457ae5b6b0f885"
            },
            {
                "Test case 3",
                "b83b533708bf535d0aa6e52980d53b78",
                "",
                "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985",
                "7f1b32b81b820d02614f8895ac1d4eac"
            },
            {
                "Test case 4",
                "b83b533708bf535d0aa6e52980d53b78",
                "feedfacedeadbeeffeedfacedeadbeefabaddad2",
                "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091",
                "698e57f70e6ecc7fd9463b7260a9ae5f"
            },
        };
    }

    public static TheoryData<byte, byte, int, int> DenseCases()
    {
        TheoryData<byte, byte, int, int> cases = new();
        foreach (byte hPattern in DensePatterns)
        {
            foreach (byte blockPattern in DensePatterns)
            {
                for (int aadBlocks = 0; aadBlocks <= 3; aadBlocks++)
                {
                    for (int ciphertextBlocks = 0; ciphertextBlocks <= 3; ciphertextBlocks++)
                    {
                        cases.Add(hPattern, blockPattern, aadBlocks, ciphertextBlocks);
                    }
                }
            }
        }

        return cases;
    }

    public static TheoryData<int, int, string> WrongLengthCases()
    {
        return new TheoryData<int, int, string>
        {
            { 15, 16, "h" },
            { 17, 16, "h" },
            { 16, 15, "output" },
            { 16, 17, "output" },
        };
    }

    [Theory]
    [MemberData(nameof(GcmSpecCases))]
    public void Software_matches_gcm_spec_test_cases(string name, string h, string a, string c, string expected)
    {
        byte[] actual = new byte[16];
        Ghash.ComputeSoftware(Convert.FromHexString(h), Convert.FromHexString(a), Convert.FromHexString(c), actual);
        AssertGhash(name, expected, actual);
    }

    [Theory(SkipUnless = nameof(PclmulSupported), Skip = PclmulSkipReason)]
    [MemberData(nameof(GcmSpecCases))]
    public void Pclmul_matches_gcm_spec_test_cases(string name, string h, string a, string c, string expected)
    {
        byte[] actual = new byte[16];
        Ghash.ComputePclmul(Convert.FromHexString(h), Convert.FromHexString(a), Convert.FromHexString(c), actual);
        AssertGhash(name, expected, actual);
    }

    [Fact(SkipUnless = nameof(PclmulSupported), Skip = PclmulSkipReason)]
    public void Pclmul_matches_software_on_random_inputs()
    {
        Random random = new(1);
        for (int i = 0; i < 1000; i++)
        {
            byte[] h = RandomBytes(random, 16);
            byte[] a = RandomBytes(random, random.Next(0, 71));
            byte[] c = RandomBytes(random, random.Next(0, 301));
            byte[] software = new byte[16];
            byte[] pclmul = new byte[16];
            Ghash.ComputeSoftware(h, a, c, software);
            Ghash.ComputePclmul(h, a, c, pclmul);
            Assert.True(
                software.AsSpan().SequenceEqual(pclmul),
                $"Case {i}: software {Convert.ToHexString(software)}, PCLMUL {Convert.ToHexString(pclmul)}");
        }
    }

    // With A and C empty, the only block is the zero length block, and H times zero is zero.
    [Fact]
    public void Empty_inputs_give_the_zero_block()
    {
        byte[] h = Filled(0x5C, 16);
        byte[] viaCompute = Filled(0xFF, 16);
        byte[] viaSoftware = Filled(0xFF, 16);
        Ghash.Compute(h, ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty, viaCompute);
        Ghash.ComputeSoftware(h, ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty, viaSoftware);
        Assert.Equal(new byte[16], viaCompute);
        Assert.Equal(new byte[16], viaSoftware);
    }

    [Theory]
    [MemberData(nameof(DenseCases))]
    public void Dense_patterns_match_bitwise_reference(byte hPattern, byte blockPattern, int aadBlocks, int ciphertextBlocks)
    {
        byte[] h = Filled(hPattern, 16);
        byte[] a = Filled(blockPattern, aadBlocks * 16);
        byte[] c = Filled(blockPattern, ciphertextBlocks * 16);
        byte[] actual = new byte[16];
        Ghash.ComputeSoftware(h, a, c, actual);
        Assert.Equal(ReferenceGhash(h, a, c), actual);
    }

    [Theory(SkipUnless = nameof(PclmulSupported), Skip = PclmulSkipReason)]
    [MemberData(nameof(DenseCases))]
    public void Pclmul_dense_patterns_match_bitwise_reference(byte hPattern, byte blockPattern, int aadBlocks, int ciphertextBlocks)
    {
        byte[] h = Filled(hPattern, 16);
        byte[] a = Filled(blockPattern, aadBlocks * 16);
        byte[] c = Filled(blockPattern, ciphertextBlocks * 16);
        byte[] actual = new byte[16];
        Ghash.ComputePclmul(h, a, c, actual);
        Assert.Equal(ReferenceGhash(h, a, c), actual);
    }

    [Theory]
    [MemberData(nameof(WrongLengthCases))]
    public void Rejects_wrong_lengths(int hLength, int outputLength, string paramName)
    {
        byte[] h = Filled(0x01, hLength);
        byte[] output = Filled(0xA5, outputLength);
        ArgumentException exception = Assert.Throws<ArgumentException>(
            () => Ghash.Compute(h, ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty, output));
        Assert.Equal(paramName, exception.ParamName);
        Assert.Equal(Filled(0xA5, outputLength), output);
    }

    // GHASH by its definition: each zero-padded block is XORed into the state, then the state is multiplied by H.
    private static byte[] ReferenceGhash(byte[] h, byte[] a, byte[] c)
    {
        byte[] paddedA = ZeroPad(a);
        byte[] paddedC = ZeroPad(c);
        byte[] input = new byte[paddedA.Length + paddedC.Length + 16];
        paddedA.CopyTo(input, 0);
        paddedC.CopyTo(input, paddedA.Length);
        BinaryPrimitives.WriteUInt64BigEndian(input.AsSpan(input.Length - 16), (ulong)a.Length * 8);
        BinaryPrimitives.WriteUInt64BigEndian(input.AsSpan(input.Length - 8), (ulong)c.Length * 8);

        byte[] y = new byte[16];
        for (int offset = 0; offset < input.Length; offset += 16)
        {
            for (int i = 0; i < 16; i++)
            {
                y[i] ^= input[offset + i];
            }

            y = BitwiseMultiply(y, h);
        }

        return y;
    }

    // SP 800-38D Algorithm 1, bit by bit. Bit i of an element is the i-th bit counted from the left of the first byte.
    private static byte[] BitwiseMultiply(byte[] x, byte[] y)
    {
        byte[] z = new byte[16];
        byte[] v = (byte[])y.Clone();
        for (int i = 0; i < 128; i++)
        {
            if (((x[i / 8] >> (7 - (i % 8))) & 1) != 0)
            {
                for (int b = 0; b < 16; b++)
                {
                    z[b] ^= v[b];
                }
            }

            bool shiftedOut = (v[15] & 1) != 0;
            for (int b = 15; b > 0; b--)
            {
                v[b] = (byte)((v[b] >> 1) | (v[b - 1] << 7));
            }

            v[0] >>= 1;
            if (shiftedOut)
            {
                v[0] ^= 0xE1;
            }
        }

        return z;
    }

    private static byte[] ZeroPad(byte[] data)
    {
        byte[] padded = new byte[(data.Length + 15) / 16 * 16];
        data.CopyTo(padded, 0);
        return padded;
    }

    private static void AssertGhash(string name, string expected, byte[] actual)
    {
        Assert.True(
            string.Equals(expected, Convert.ToHexString(actual), StringComparison.OrdinalIgnoreCase),
            $"{name}: expected {expected}, actual {Convert.ToHexString(actual)}");
    }

    private static byte[] Filled(byte value, int length)
    {
        byte[] bytes = new byte[length];
        Array.Fill(bytes, value);
        return bytes;
    }

    private static byte[] RandomBytes(Random random, int length)
    {
        byte[] bytes = new byte[length];
        random.NextBytes(bytes);
        return bytes;
    }
}
