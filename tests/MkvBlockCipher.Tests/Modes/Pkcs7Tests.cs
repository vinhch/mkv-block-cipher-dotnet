using MkvBlockCipher.Modes;
using Xunit;

namespace MkvBlockCipher.Tests.Modes;

public sealed class Pkcs7Tests
{
    private const byte DataByte = 0xA5;

    public static TheoryData<int, int> ValidPaddingCases()
    {
        TheoryData<int, int> cases = new();
        foreach (int blockBytes in new[] { 16, 32 })
        {
            for (int count = 1; count <= blockBytes; count++)
            {
                cases.Add(blockBytes, count);
            }
        }

        return cases;
    }

    [Theory]
    [InlineData(16, 0)]
    [InlineData(16, 1)]
    [InlineData(16, 15)]
    [InlineData(32, 0)]
    [InlineData(32, 31)]
    public void Pad_writes_tail_then_count_bytes(int blockBytes, int tailLength)
    {
        byte[] tail = Enumerable.Range(1, tailLength).Select(i => (byte)i).ToArray();
        byte[] block = new byte[blockBytes];
        byte[] expected = Filled(blockBytes, (byte)(blockBytes - tailLength));
        tail.CopyTo(expected, 0);

        Pkcs7.Pad(tail, block);

        Assert.Equal(expected, block);
    }

    [Theory]
    [MemberData(nameof(ValidPaddingCases))]
    public void Valid_padding_returns_data_length(int blockBytes, int count)
    {
        byte[] block = Filled(blockBytes, DataByte);
        Array.Fill(block, (byte)count, blockBytes - count, count);

        Assert.Equal(blockBytes - count, Pkcs7.GetUnpaddedLength(block));
    }

    [Theory]
    [InlineData(16, 0)]
    [InlineData(16, 17)]
    [InlineData(16, 255)]
    [InlineData(32, 0)]
    [InlineData(32, 33)]
    [InlineData(32, 255)]
    public void Count_outside_block_returns_minus_one(int blockBytes, int count)
    {
        byte[] block = Filled(blockBytes, DataByte);
        block[^1] = (byte)count;

        Assert.Equal(-1, Pkcs7.GetUnpaddedLength(block));
    }

    [Theory]
    [InlineData(16, 0x00)]
    [InlineData(16, 0xFF)]
    [InlineData(32, 0x00)]
    [InlineData(32, 0xFF)]
    public void Uniform_block_returns_minus_one(int blockBytes, byte value)
    {
        Assert.Equal(-1, Pkcs7.GetUnpaddedLength(Filled(blockBytes, value)));
    }

    [Theory]
    [InlineData(16, 13)]
    [InlineData(16, 14)]
    [InlineData(32, 29)]
    [InlineData(32, 30)]
    public void Wrong_pad_byte_returns_minus_one(int blockBytes, int position)
    {
        byte[] block = Filled(blockBytes, DataByte);
        Array.Fill(block, (byte)3, blockBytes - 3, 3);
        block[position] ^= 0x01;

        Assert.Equal(-1, Pkcs7.GetUnpaddedLength(block));
    }

    private static byte[] Filled(int length, byte value) => Enumerable.Repeat(value, length).ToArray();
}
