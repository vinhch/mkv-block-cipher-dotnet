using System.Buffers.Binary;
using System.Numerics;
using System.Security.Cryptography;
using MkvBlockCipher.Modes;
using MkvBlockCipher.Tests.TestData;
using Xunit;
using static MkvBlockCipher.Tests.Modes.ModeTestSupport;

namespace MkvBlockCipher.Tests.Modes;

public sealed class XtsTests
{
    private const int BlockBytes = 16;

    [Theory]
    [MemberData(nameof(XtsVectors.Ieee1619), MemberType = typeof(XtsVectors))]
    public void Core_matches_IEEE1619_vectors(string keyHex, string dataUnitHex, string plaintextHex, string ciphertextHex)
    {
        byte[] key = Convert.FromHexString(keyHex);
        int half = key.Length / 2;
        ulong dataUnit = DataUnitNumber(dataUnitHex);
        byte[] plaintext = Convert.FromHexString(plaintextHex);
        byte[] ciphertext = new byte[plaintext.Length];

        Xts.Encrypt(new AesTestEngine(), key.AsSpan(0, half), key.AsSpan(half), dataUnit, plaintext, ciphertext);
        Assert.Equal(Convert.FromHexString(ciphertextHex), ciphertext);

        byte[] decrypted = new byte[plaintext.Length];
        Xts.Decrypt(new AesTestEngine(), key.AsSpan(0, half), key.AsSpan(half), dataUnit, ciphertext, decrypted);
        Assert.Equal(plaintext, decrypted);
    }

    [Fact]
    public void Batch_and_stealing_together_match_block_by_block_reference()
    {
        byte[] dataKey = SeededBytes(16, 1);
        byte[] tweakKey = SeededBytes(16, 2);
        byte[] plaintext = SeededBytes(5 * BlockBytes + 7, 3);
        const ulong dataUnit = 0x0123456789ABCDEF;

        byte[] ciphertext = new byte[plaintext.Length];
        Xts.Encrypt(new AesTestEngine(), dataKey, tweakKey, dataUnit, plaintext, ciphertext);
        Assert.Equal(ReferenceEncrypt(dataKey, tweakKey, dataUnit, plaintext), ciphertext);

        byte[] decrypted = new byte[plaintext.Length];
        Xts.Decrypt(new AesTestEngine(), dataKey, tweakKey, dataUnit, ciphertext, decrypted);
        Assert.Equal(plaintext, decrypted);
    }

    // Lengths around the block and batch boundaries; tails of 1, 7 and 15 bytes, and whole blocks.
    [Theory]
    [InlineData(16)]
    [InlineData(17)]
    [InlineData(31)]
    [InlineData(32)]
    [InlineData(33)]
    [InlineData(64)]
    [InlineData(87)]
    [InlineData(151)]
    public void Matches_block_by_block_reference(int length)
    {
        byte[] dataKey = SeededBytes(16, 4);
        byte[] tweakKey = SeededBytes(16, 5);
        byte[] plaintext = SeededBytes(length, 6);
        const ulong dataUnit = 0xFEDCBA9876543210;

        byte[] ciphertext = new byte[length];
        Xts.Encrypt(new AesTestEngine(), dataKey, tweakKey, dataUnit, plaintext, ciphertext);
        Assert.Equal(ReferenceEncrypt(dataKey, tweakKey, dataUnit, plaintext), ciphertext);
    }

    // The source prints the tweak as 16 little-endian bytes. The core takes a 64-bit unit number, so the upper eight
    // bytes must be zero for every vector.
    private static ulong DataUnitNumber(string tweakHex)
    {
        byte[] tweak = Convert.FromHexString(tweakHex);
        Assert.Equal(new byte[8], tweak.AsSpan(8).ToArray());
        return BinaryPrimitives.ReadUInt64LittleEndian(tweak);
    }

    // IEEE 1619 section 5, one block at a time with ciphertext stealing for a partial final block. E is AES-ECB under
    // the data key; the tweak is E under the tweak key, doubled per block. Written here so the core is not its own oracle.
    private static byte[] ReferenceEncrypt(byte[] dataKey, byte[] tweakKey, ulong dataUnit, byte[] plaintext)
    {
        int fullBlocks = plaintext.Length / BlockBytes;
        int tailLength = plaintext.Length % BlockBytes;
        byte[][] tweaks = Tweaks(tweakKey, dataUnit, fullBlocks + 1);
        byte[] output = new byte[plaintext.Length];

        int plainBlocks = tailLength == 0 ? fullBlocks : fullBlocks - 1;
        for (int i = 0; i < plainBlocks; i++)
        {
            byte[] encrypted = Xor(AesBlock(dataKey, Xor(BlockOf(plaintext, i), tweaks[i])), tweaks[i]);
            encrypted.CopyTo(output, i * BlockBytes);
        }

        if (tailLength == 0)
        {
            return output;
        }

        int penultimate = fullBlocks - 1;
        byte[] cc = Xor(AesBlock(dataKey, Xor(BlockOf(plaintext, penultimate), tweaks[penultimate])), tweaks[penultimate]);
        byte[] pp = new byte[BlockBytes];
        plaintext.AsSpan(fullBlocks * BlockBytes, tailLength).CopyTo(pp);
        cc.AsSpan(tailLength).CopyTo(pp.AsSpan(tailLength));
        byte[] cm = Xor(AesBlock(dataKey, Xor(pp, tweaks[fullBlocks])), tweaks[fullBlocks]);

        cm.CopyTo(output, penultimate * BlockBytes);
        cc.AsSpan(0, tailLength).CopyTo(output.AsSpan(fullBlocks * BlockBytes));
        return output;
    }

    private static byte[][] Tweaks(byte[] tweakKey, ulong dataUnit, int count)
    {
        byte[] unit = new byte[BlockBytes];
        BinaryPrimitives.WriteUInt64LittleEndian(unit, dataUnit);
        byte[][] tweaks = new byte[count][];
        tweaks[0] = AesBlock(tweakKey, unit);
        for (int i = 1; i < count; i++)
        {
            tweaks[i] = Multiply(tweaks[i - 1]);
        }

        return tweaks;
    }

    // Multiplication by x in GF(2^128), little-endian bytes, with the 0x87 reduction. BigInteger keeps it arithmetic.
    private static byte[] Multiply(byte[] tweak)
    {
        BigInteger value = new(tweak, isUnsigned: true, isBigEndian: false);
        value <<= 1;
        BigInteger overflow = BigInteger.One << 128;
        if (value >= overflow)
        {
            value = (value - overflow) ^ 0x87;
        }

        byte[] result = new byte[BlockBytes];
        value.TryWriteBytes(result, out _, isUnsigned: true, isBigEndian: false);
        return result;
    }

    private static byte[] AesBlock(byte[] key, byte[] block)
    {
        using Aes aes = Aes.Create();
        aes.Key = key;
        byte[] output = new byte[BlockBytes];
        aes.EncryptEcb(block, output, PaddingMode.None);
        return output;
    }

    private static byte[] BlockOf(byte[] data, int blockIndex) => data.AsSpan(blockIndex * BlockBytes, BlockBytes).ToArray();

    private static byte[] Xor(byte[] left, byte[] right)
    {
        byte[] result = new byte[left.Length];
        for (int i = 0; i < left.Length; i++)
        {
            result[i] = (byte)(left[i] ^ right[i]);
        }

        return result;
    }
}
