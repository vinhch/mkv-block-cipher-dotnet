using System.Security.Cryptography;
using MkvBlockCipher.Modes;
using Xunit;
using static MkvBlockCipher.Tests.Modes.ModeTestSupport;

namespace MkvBlockCipher.Tests.Modes;

public sealed class CbcCtsTests
{
    // RFC 3962 Appendix B, "Some test vectors for CBC with ciphertext stealing": AES-128 key, all-zero IV. The
    // plaintext is the 64-byte input of that section; each case uses its prefix.
    private const string Rfc3962Key = "636869636b656e207465726979616b69";
    private const string Rfc3962Plaintext =
        "4920776f756c64206c696b65207468652047656e6572616c20476175277320" +
        "436869636b656e2c20706c656173652c20616e6420776f6e746f6e20736f75702e";

    [Theory]
    [InlineData(17, "c6353568f2bf8cb4d8a580362da7ff7f97")]
    [InlineData(31, "fc00783e0efdb2c1d445d4c8eff7ed2297687268d6ecccc0c07b25e25ecfe5")]
    [InlineData(32, "39312523a78662d5be7fcbcc98ebf5a897687268d6ecccc0c07b25e25ecfe584")]
    [InlineData(47, "97687268d6ecccc0c07b25e25ecfe584b3fffd940c16a18c1b5549d2f838029e39312523a78662d5be7fcbcc98ebf5")]
    [InlineData(48, "97687268d6ecccc0c07b25e25ecfe5849dad8bbb96c4cdc03bc103e1a194bbd839312523a78662d5be7fcbcc98ebf5a8")]
    [InlineData(64, "97687268d6ecccc0c07b25e25ecfe58439312523a78662d5be7fcbcc98ebf5a84807efe836ee89a526730dbc2f7bc8409dad8bbb96c4cdc03bc103e1a194bbd8")]
    public void Core_matches_RFC3962_vectors(int length, string ciphertextHex)
    {
        byte[] key = Convert.FromHexString(Rfc3962Key);
        byte[] iv = new byte[16];
        byte[] plaintext = Convert.FromHexString(Rfc3962Plaintext).AsSpan(0, length).ToArray();
        byte[] ciphertext = new byte[length];

        CbcCts.Encrypt(new AesTestEngine(), key, plaintext, iv, ciphertext);
        Assert.Equal(Convert.FromHexString(ciphertextHex), ciphertext);

        byte[] decrypted = new byte[length];
        CbcCts.Decrypt(new AesTestEngine(), key, ciphertext, iv, decrypted);
        Assert.Equal(plaintext, decrypted);
    }

    [Theory]
    [InlineData(MkvBlockSize.Mkv128)]
    [InlineData(MkvBlockSize.Mkv256)]
    public void One_block_equals_unpadded_CBC(MkvBlockSize blockSize)
    {
        using MkvCipher cipher = CreateCipher(blockSize);
        int blockBytes = BlockBytes(blockSize);
        byte[] iv = SeededBytes(blockBytes, 2);
        byte[] plaintext = SeededBytes(blockBytes, 3);

        Assert.Equal(cipher.EncryptCbc(plaintext, iv, PaddingMode.None), cipher.EncryptCbcCts(plaintext, iv));
        Assert.Equal(plaintext, cipher.DecryptCbcCts(cipher.EncryptCbcCts(plaintext, iv), iv));
    }

    public static TheoryData<MkvBlockSize, int> LengthCases()
    {
        TheoryData<MkvBlockSize, int> cases = new();
        foreach (MkvBlockSize blockSize in BlockSizes)
        {
            int blockBytes = BlockBytes(blockSize);
            for (int length = blockBytes; length <= 3 * blockBytes + 1; length++)
            {
                cases.Add(blockSize, length);
            }
        }

        return cases;
    }

    [Theory]
    [MemberData(nameof(LengthCases))]
    public void Round_trip_lengths(MkvBlockSize blockSize, int length)
    {
        using MkvCipher cipher = CreateCipher(blockSize);
        byte[] iv = SeededBytes(BlockBytes(blockSize), 2);
        byte[] plaintext = SeededBytes(length, 3);

        byte[] ciphertext = cipher.EncryptCbcCts(plaintext, iv);

        Assert.Equal(length, ciphertext.Length);
        Assert.Equal(plaintext, cipher.DecryptCbcCts(ciphertext, iv));
    }

    [Theory]
    [MemberData(nameof(LengthCases))]
    public void In_place_round_trip(MkvBlockSize blockSize, int length)
    {
        using MkvCipher cipher = CreateCipher(blockSize);
        byte[] iv = SeededBytes(BlockBytes(blockSize), 2);
        byte[] plaintext = SeededBytes(length, 3);
        byte[] buffer = (byte[])plaintext.Clone();

        cipher.EncryptCbcCts(buffer, iv, buffer);
        Assert.Equal(cipher.EncryptCbcCts(plaintext, iv), buffer);

        cipher.DecryptCbcCts(buffer, iv, buffer);
        Assert.Equal(plaintext, buffer);
    }

    [Theory]
    [InlineData(MkvBlockSize.Mkv128, 0)]
    [InlineData(MkvBlockSize.Mkv128, 15)]
    [InlineData(MkvBlockSize.Mkv256, 0)]
    [InlineData(MkvBlockSize.Mkv256, 31)]
    public void Shorter_than_one_block_throws(MkvBlockSize blockSize, int length)
    {
        using MkvCipher cipher = CreateCipher(blockSize);
        byte[] iv = new byte[BlockBytes(blockSize)];
        byte[] destination = new byte[length];

        Assert.Throws<ArgumentException>(() => cipher.EncryptCbcCts(new byte[length], iv));
        Assert.Throws<ArgumentException>(() => cipher.EncryptCbcCts(new byte[length], iv, destination));
        Assert.Throws<ArgumentException>(() => cipher.DecryptCbcCts(new byte[length], iv));
        Assert.Throws<ArgumentException>(() => cipher.DecryptCbcCts(new byte[length], iv, destination));
    }

    [Theory]
    [InlineData(MkvBlockSize.Mkv128, 15)]
    [InlineData(MkvBlockSize.Mkv128, 17)]
    [InlineData(MkvBlockSize.Mkv256, 31)]
    [InlineData(MkvBlockSize.Mkv256, 33)]
    public void Wrong_iv_length_throws(MkvBlockSize blockSize, int ivLength)
    {
        using MkvCipher cipher = CreateCipher(blockSize);
        byte[] data = new byte[BlockBytes(blockSize) + 1];
        byte[] iv = new byte[ivLength];

        Assert.Throws<ArgumentException>(() => cipher.EncryptCbcCts(data, iv));
        Assert.Throws<ArgumentException>(() => cipher.DecryptCbcCts(data, iv));
    }

    [Theory]
    [InlineData(MkvBlockSize.Mkv128, 16)]
    [InlineData(MkvBlockSize.Mkv128, 17)]
    [InlineData(MkvBlockSize.Mkv256, 32)]
    [InlineData(MkvBlockSize.Mkv256, 33)]
    public void Destination_length_must_equal_input_length(MkvBlockSize blockSize, int length)
    {
        using MkvCipher cipher = CreateCipher(blockSize);
        byte[] iv = new byte[BlockBytes(blockSize)];
        byte[] data = new byte[length];

        foreach (int destinationLength in new[] { length - 1, length + 1 })
        {
            byte[] destination = Filled(destinationLength, 0xAA);
            Assert.Throws<ArgumentException>(() => cipher.EncryptCbcCts(data, iv, destination));
            Assert.Throws<ArgumentException>(() => cipher.DecryptCbcCts(data, iv, destination));
            Assert.All(destination, b => Assert.Equal(0xAA, b));
        }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Partial_overlap_throws_and_writes_nothing(bool decrypt)
    {
        using MkvCipher cipher = CreateCipher(MkvBlockSize.Mkv128);
        byte[] iv = new byte[16];
        byte[] buffer = SeededBytes(64, 4);
        byte[] before = (byte[])buffer.Clone();

        // The output starts 8 bytes into the input: a write would clobber input still to be read.
        if (decrypt)
        {
            Assert.Throws<ArgumentException>(() => cipher.DecryptCbcCts(buffer.AsSpan(0, 40), iv, buffer.AsSpan(8, 40)));
        }
        else
        {
            Assert.Throws<ArgumentException>(() => cipher.EncryptCbcCts(buffer.AsSpan(0, 40), iv, buffer.AsSpan(8, 40)));
        }

        Assert.Equal(before, buffer);
    }

    [Fact]
    public void Cts_methods_throw_after_dispose()
    {
        MkvCipher cipher = CreateCipher(MkvBlockSize.Mkv128);
        cipher.Dispose();
        byte[] data = new byte[17];
        byte[] iv = new byte[16];
        byte[] destination = new byte[17];

        Assert.Throws<ObjectDisposedException>(() => cipher.EncryptCbcCts(data, iv));
        Assert.Throws<ObjectDisposedException>(() => cipher.EncryptCbcCts(data, iv, destination));
        Assert.Throws<ObjectDisposedException>(() => cipher.DecryptCbcCts(data, iv));
        Assert.Throws<ObjectDisposedException>(() => cipher.DecryptCbcCts(data, iv, destination));
    }
}
