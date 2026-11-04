using System.Security.Cryptography;
using Xunit;
using static MkvBlockCipher.Tests.Modes.ModeTestSupport;

namespace MkvBlockCipher.Tests.Modes;

public sealed class CbcPaddingTests
{
    private const string DecryptFailure = "The data could not be decrypted.";
    private const byte DataByte = 0xA5;

    public static TheoryData<MkvBlockSize, string> InvalidPaddingCases()
    {
        TheoryData<MkvBlockSize, string> cases = new();
        foreach (MkvBlockSize blockSize in BlockSizes)
        {
            int blockBytes = BlockBytes(blockSize);
            cases.Add(blockSize, Convert.ToHexString(WithLastByte(blockBytes, 0x00)));
            cases.Add(blockSize, Convert.ToHexString(WithLastByte(blockBytes, (byte)(blockBytes + 1))));
            cases.Add(blockSize, Convert.ToHexString(WithLastByte(blockBytes, 0xFF)));
            for (int position = 0; position < blockBytes - 1; position++)
            {
                cases.Add(blockSize, Convert.ToHexString(FullPadWithWrongByte(blockBytes, position)));
            }
        }

        return cases;
    }

    [Theory]
    [InlineData(MkvBlockSize.Mkv128)]
    [InlineData(MkvBlockSize.Mkv256)]
    public void Empty_plaintext_gives_one_padding_block(MkvBlockSize blockSize)
    {
        using MkvCipher cipher = CreateCipher(blockSize);
        int blockBytes = BlockBytes(blockSize);
        byte[] iv = SeededBytes(blockBytes, 2);
        byte[] expected = EncryptOneBlock(cipher, Xor(Filled(blockBytes, (byte)blockBytes), iv));

        byte[] ciphertext = cipher.EncryptCbc(Array.Empty<byte>(), iv);

        Assert.Equal(expected, ciphertext);
        Assert.Empty(cipher.DecryptCbc(ciphertext, iv));
    }

    [Theory]
    [InlineData(MkvBlockSize.Mkv128)]
    [InlineData(MkvBlockSize.Mkv256)]
    public void Padding_block_is_B_when_aligned(MkvBlockSize blockSize)
    {
        using MkvCipher cipher = CreateCipher(blockSize);
        int blockBytes = BlockBytes(blockSize);
        byte[] iv = SeededBytes(blockBytes, 2);
        byte[] ciphertext = cipher.EncryptCbc(SeededBytes(2 * blockBytes, 3), iv);

        byte[] lastBlock = new byte[blockBytes];
        cipher.DecryptBlock(ciphertext.AsSpan(2 * blockBytes), lastBlock);
        byte[] padding = Xor(lastBlock, ciphertext[blockBytes..(2 * blockBytes)]);

        Assert.Equal(Filled(blockBytes, (byte)blockBytes), padding);
    }

    [Theory]
    [MemberData(nameof(InvalidPaddingCases))]
    public void Every_invalid_padding_throws_same_exception(MkvBlockSize blockSize, string lastBlock)
    {
        using MkvCipher cipher = CreateCipher(blockSize);
        int blockBytes = BlockBytes(blockSize);
        byte[] iv = SeededBytes(blockBytes, 2);
        byte[] ciphertext = EncryptOneBlock(cipher, Xor(Convert.FromHexString(lastBlock), iv));

        CryptographicException exception = Assert.Throws<CryptographicException>(() => cipher.DecryptCbc(ciphertext, iv));
        Assert.Equal(DecryptFailure, exception.Message);

        byte[] destination = new byte[blockBytes];
        exception = Assert.Throws<CryptographicException>(() => cipher.DecryptCbc(ciphertext, iv, destination));
        Assert.Equal(DecryptFailure, exception.Message);
        Assert.Equal(new byte[blockBytes], destination);

        destination = new byte[blockBytes];
        exception = Assert.Throws<CryptographicException>(
            () => cipher.TryDecryptCbc(ciphertext, iv, destination, out _));
        Assert.Equal(DecryptFailure, exception.Message);
        Assert.Equal(new byte[blockBytes], destination);
    }

    [Theory]
    [InlineData(MkvBlockSize.Mkv128)]
    [InlineData(MkvBlockSize.Mkv256)]
    public void Padding_failure_zeroes_whole_destination_across_batches(MkvBlockSize blockSize)
    {
        using MkvCipher cipher = CreateCipher(blockSize);
        int blockBytes = BlockBytes(blockSize);
        byte[] iv = SeededBytes(blockBytes, 2);
        int blocks = 3 * cipher.Engine.BatchBlocks + 5;
        byte[] padded = PadReference(SeededBytes(PlaintextLengthFor(blocks, blockBytes), 3), blockBytes);
        // Flips one pad byte in the last block, so its padding is invalid.
        padded[^2] ^= 0x01;
        byte[] ciphertext = ReferenceEncrypt(cipher, padded, iv);
        byte[] destination = Filled(ciphertext.Length + 7, 0x5A);

        CryptographicException exception =
            Assert.Throws<CryptographicException>(() => cipher.DecryptCbc(ciphertext, iv, destination));

        Assert.Equal(DecryptFailure, exception.Message);
        Assert.Equal(new byte[destination.Length], destination);
    }

    [Fact]
    public void Stripped_padding_bytes_are_zeroed()
    {
        using MkvCipher cipher = CreateCipher(MkvBlockSize.Mkv128);
        byte[] iv = SeededBytes(16, 2);
        byte[] plaintext = SeededBytes(5, 3);
        byte[] ciphertext = cipher.EncryptCbc(plaintext, iv);
        byte[] destination = Filled(ciphertext.Length + 8, 0xFF);

        int length = cipher.DecryptCbc(ciphertext, iv, destination);

        Assert.Equal(5, length);
        Assert.Equal(plaintext, destination.AsSpan(0, length).ToArray());
        Assert.Equal(Filled(ciphertext.Length - length, 0), destination[length..ciphertext.Length]);
        Assert.Equal(Filled(8, 0xFF), destination[ciphertext.Length..]);
    }

    private static byte[] WithLastByte(int blockBytes, byte last)
    {
        byte[] block = Filled(blockBytes, DataByte);
        block[^1] = last;
        return block;
    }

    private static byte[] FullPadWithWrongByte(int blockBytes, int position)
    {
        byte[] block = Filled(blockBytes, (byte)blockBytes);
        block[position] ^= 0x01;
        return block;
    }
}
