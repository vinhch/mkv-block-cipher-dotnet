using Xunit;
using static MkvBlockCipher.Tests.Modes.ModeTestSupport;

namespace MkvBlockCipher.Tests.Modes;

public sealed class CbcArgumentTests
{
    [Theory]
    [MemberData(nameof(ModeTestSupport.WrongLengthCases), MemberType = typeof(ModeTestSupport))]
    public void Wrong_iv_length_throws(MkvBlockSize blockSize, int ivLength)
    {
        using MkvCipher cipher = CreateCipher(blockSize);
        int blockBytes = BlockBytes(blockSize);
        byte[] iv = new byte[ivLength];
        byte[] plaintext = SeededBytes(blockBytes, 3);
        byte[] ciphertext = SeededBytes(2 * blockBytes, 4);
        byte[] destination = new byte[2 * blockBytes];

        AssertRejectsParameter("iv", () => cipher.EncryptCbc(plaintext, iv));
        AssertRejectsParameter("iv", () => cipher.EncryptCbc(plaintext, iv, destination));
        AssertRejectsParameter("iv", () => cipher.TryEncryptCbc(plaintext, iv, destination, out _));
        AssertRejectsParameter("iv", () => cipher.DecryptCbc(ciphertext, iv));
        AssertRejectsParameter("iv", () => cipher.DecryptCbc(ciphertext, iv, destination));
        AssertRejectsParameter("iv", () => cipher.TryDecryptCbc(ciphertext, iv, destination, out _));
    }

    [Theory]
    [InlineData(MkvBlockSize.Mkv128)]
    [InlineData(MkvBlockSize.Mkv256)]
    public void Try_returns_false_when_destination_one_byte_short(MkvBlockSize blockSize)
    {
        using MkvCipher cipher = CreateCipher(blockSize);
        int blockBytes = BlockBytes(blockSize);
        byte[] iv = SeededBytes(blockBytes, 2);
        byte[] plaintext = SeededBytes(blockBytes + 3, 3);
        int ciphertextLength = 2 * blockBytes;

        Assert.False(cipher.TryEncryptCbc(plaintext, iv, new byte[ciphertextLength - 1], out int written));
        Assert.Equal(0, written);
        AssertRejectsParameter("destination", () => cipher.EncryptCbc(plaintext, iv, new byte[ciphertextLength - 1]));
        byte[] ciphertext = new byte[ciphertextLength];
        Assert.True(cipher.TryEncryptCbc(plaintext, iv, ciphertext, out written));
        Assert.Equal(ciphertextLength, written);

        Assert.False(cipher.TryDecryptCbc(ciphertext, iv, new byte[ciphertextLength - 1], out written));
        Assert.Equal(0, written);
        AssertRejectsParameter("destination", () => cipher.DecryptCbc(ciphertext, iv, new byte[ciphertextLength - 1]));
        Assert.True(cipher.TryDecryptCbc(ciphertext, iv, new byte[ciphertextLength], out written));
        Assert.Equal(plaintext.Length, written);
    }

    [Theory]
    [InlineData(false, 0, 1)]
    [InlineData(false, 1, 0)]
    [InlineData(true, 0, 1)]
    [InlineData(true, 1, 0)]
    public void Partial_overlap_throws(bool decrypt, int sourceStart, int destinationStart)
    {
        using MkvCipher cipher = CreateCipher(MkvBlockSize.Mkv128);
        byte[] buffer = new byte[48];

        ArgumentException exception = Assert.Throws<ArgumentException>(
            () => RunOverlapping(cipher, decrypt, buffer, sourceStart, destinationStart));
        Assert.Equal("destination", exception.ParamName);
    }

    [Fact]
    public void Adjacent_buffers_are_accepted()
    {
        using MkvCipher cipher = CreateCipher(MkvBlockSize.Mkv128);
        byte[] iv = new byte[16];
        byte[] buffer = new byte[48];
        byte[] plaintext = SeededBytes(16, 3);
        plaintext.CopyTo(buffer, 0);
        byte[] expected = cipher.EncryptCbc(plaintext, iv);

        Assert.Equal(32, cipher.EncryptCbc(buffer.AsSpan(0, 16), iv, buffer.AsSpan(16, 32)));
        Assert.Equal(expected, buffer.AsSpan(16, 32).ToArray());
    }

    [Theory]
    [InlineData(MkvBlockSize.Mkv128, 1)]
    [InlineData(MkvBlockSize.Mkv128, 15)]
    [InlineData(MkvBlockSize.Mkv128, 17)]
    [InlineData(MkvBlockSize.Mkv256, 1)]
    [InlineData(MkvBlockSize.Mkv256, 31)]
    [InlineData(MkvBlockSize.Mkv256, 33)]
    public void Ciphertext_not_multiple_of_block_throws_ArgumentException(MkvBlockSize blockSize, int length)
    {
        using MkvCipher cipher = CreateCipher(blockSize);
        byte[] iv = new byte[BlockBytes(blockSize)];
        byte[] ciphertext = new byte[length];
        byte[] destination = new byte[2 * BlockBytes(blockSize)];

        AssertRejectsParameter("ciphertext", () => cipher.DecryptCbc(ciphertext, iv));
        AssertRejectsParameter("ciphertext", () => cipher.DecryptCbc(ciphertext, iv, destination));
        AssertRejectsParameter("ciphertext", () => cipher.TryDecryptCbc(ciphertext, iv, destination, out _));
    }

    [Theory]
    [InlineData(MkvBlockSize.Mkv128)]
    [InlineData(MkvBlockSize.Mkv256)]
    public void Empty_ciphertext_throws_ArgumentException(MkvBlockSize blockSize)
    {
        using MkvCipher cipher = CreateCipher(blockSize);
        byte[] iv = new byte[BlockBytes(blockSize)];

        AssertRejectsParameter("ciphertext", () => cipher.DecryptCbc(Array.Empty<byte>(), iv));
    }

    [Theory]
    [InlineData(MkvBlockSize.Mkv128, 0, 16)]
    [InlineData(MkvBlockSize.Mkv128, 15, 16)]
    [InlineData(MkvBlockSize.Mkv128, 16, 32)]
    [InlineData(MkvBlockSize.Mkv128, 49, 64)]
    [InlineData(MkvBlockSize.Mkv256, 0, 32)]
    [InlineData(MkvBlockSize.Mkv256, 31, 32)]
    [InlineData(MkvBlockSize.Mkv256, 32, 64)]
    public void GetCiphertextLengthCbc_returns_next_whole_block(MkvBlockSize blockSize, int plaintextLength, int expected)
    {
        using MkvCipher cipher = CreateCipher(blockSize);

        Assert.Equal(expected, cipher.GetCiphertextLengthCbc(plaintextLength));
    }

    [Theory]
    [InlineData(MkvBlockSize.Mkv128, -1)]
    [InlineData(MkvBlockSize.Mkv128, int.MaxValue)]
    [InlineData(MkvBlockSize.Mkv256, -1)]
    [InlineData(MkvBlockSize.Mkv256, int.MaxValue)]
    public void GetCiphertextLengthCbc_rejects_negative_or_unrepresentable_length(MkvBlockSize blockSize, int plaintextLength)
    {
        using MkvCipher cipher = CreateCipher(blockSize);

        Assert.Throws<ArgumentOutOfRangeException>(() => cipher.GetCiphertextLengthCbc(plaintextLength));
    }

    [Fact]
    public void Cbc_methods_throw_after_dispose()
    {
        using MkvCipher cipher = CreateCipher(MkvBlockSize.Mkv128);
        byte[] iv = new byte[16];
        byte[] data = new byte[32];
        cipher.Dispose();

        Assert.Throws<ObjectDisposedException>(() => cipher.GetCiphertextLengthCbc(0));
        Assert.Throws<ObjectDisposedException>(() => cipher.EncryptCbc(data, iv));
        Assert.Throws<ObjectDisposedException>(() => cipher.EncryptCbc(data, iv, new byte[32]));
        Assert.Throws<ObjectDisposedException>(() => cipher.TryEncryptCbc(data, iv, new byte[32], out _));
        Assert.Throws<ObjectDisposedException>(() => cipher.DecryptCbc(data, iv));
        Assert.Throws<ObjectDisposedException>(() => cipher.DecryptCbc(data, iv, new byte[32]));
        Assert.Throws<ObjectDisposedException>(() => cipher.TryDecryptCbc(data, iv, new byte[32], out _));
    }

    private static void RunOverlapping(MkvCipher cipher, bool decrypt, byte[] buffer, int sourceStart, int destinationStart)
    {
        byte[] iv = new byte[16];
        if (decrypt)
        {
            cipher.DecryptCbc(buffer.AsSpan(sourceStart, 16), iv, buffer.AsSpan(destinationStart, 16));
        }
        else
        {
            cipher.EncryptCbc(buffer.AsSpan(sourceStart, 16), iv, buffer.AsSpan(destinationStart, 32));
        }
    }
}
