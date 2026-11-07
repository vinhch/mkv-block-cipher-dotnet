using System.Security.Cryptography;
using MkvBlockCipher.Modes;
using Xunit;
using static MkvBlockCipher.Tests.Modes.ModeTestSupport;

namespace MkvBlockCipher.Tests.Modes;

public sealed class CbcPaddingModeTests
{
    // NIST SP 800-38A, Appendix F.2.1 (CBC-AES128.Encrypt).
    private const string Sp800_38A_Key = "2b7e151628aed2a6abf7158809cf4f3c";
    private const string Sp800_38A_Iv = "000102030405060708090a0b0c0d0e0f";
    private const string Sp800_38A_Plaintext =
        "6bc1bee22e409f96e93d7e117393172a" +
        "ae2d8a571e03ac9c9eb76fac45af8e51" +
        "30c81c46a35ce411e5fbc1191a0a52ef" +
        "f69f2445df4f9b17ad2b417be66c3710";
    private const string Sp800_38A_Ciphertext =
        "7649abac8119b246cee98e9b12e9197d" +
        "5086cb9b507219ee95db113a917678b2" +
        "73bed6b8e3c1743b7116e69e22229516" +
        "3ff1caa1681fac09120eca307586e1a7";

    public static TheoryData<MkvBlockSize, int> WholeBlockCases()
    {
        TheoryData<MkvBlockSize, int> cases = new();
        foreach (MkvBlockSize blockSize in BlockSizes)
        {
            foreach (int blocks in new[] { 0, 1, 3 })
            {
                cases.Add(blockSize, blocks);
            }
        }

        return cases;
    }

    [Fact]
    public void Core_matches_SP800_38A_CBC_AES128()
    {
        byte[] key = Convert.FromHexString(Sp800_38A_Key);
        byte[] iv = Convert.FromHexString(Sp800_38A_Iv);
        byte[] plaintext = Convert.FromHexString(Sp800_38A_Plaintext);
        byte[] ciphertext = new byte[plaintext.Length];

        Cbc.Encrypt(new AesTestEngine(), key, plaintext, iv, ciphertext, PaddingMode.None);
        Assert.Equal(Convert.FromHexString(Sp800_38A_Ciphertext), ciphertext);

        byte[] decrypted = new byte[ciphertext.Length];
        Assert.Equal(plaintext.Length, Cbc.Decrypt(new AesTestEngine(), key, ciphertext, iv, decrypted, PaddingMode.None));
        Assert.Equal(plaintext, decrypted);
    }

    [Theory]
    [MemberData(nameof(WholeBlockCases))]
    public void None_round_trips_whole_blocks(MkvBlockSize blockSize, int blocks)
    {
        using MkvCipher cipher = CreateCipher(blockSize);
        int length = blocks * BlockBytes(blockSize);
        byte[] iv = SeededBytes(BlockBytes(blockSize), 2);
        byte[] plaintext = SeededBytes(length, 3);

        byte[] ciphertext = cipher.EncryptCbc(plaintext, iv, PaddingMode.None);

        Assert.Equal(length, ciphertext.Length);
        Assert.Equal(plaintext, cipher.DecryptCbc(ciphertext, iv, PaddingMode.None));
    }

    [Theory]
    [InlineData(MkvBlockSize.Mkv128)]
    [InlineData(MkvBlockSize.Mkv256)]
    public void None_rejects_partial_block(MkvBlockSize blockSize)
    {
        using MkvCipher cipher = CreateCipher(blockSize);
        int length = BlockBytes(blockSize) + 1;
        byte[] iv = SeededBytes(BlockBytes(blockSize), 2);
        byte[] destination = Filled(2 * length, 0xAA);

        Assert.Throws<ArgumentException>(() => cipher.EncryptCbc(new byte[length], iv, PaddingMode.None));
        Assert.Throws<ArgumentException>(() => cipher.EncryptCbc(new byte[length], iv, destination, PaddingMode.None));
        Assert.Throws<ArgumentException>(() => cipher.TryEncryptCbc(new byte[length], iv, destination, out _, PaddingMode.None));
        Assert.Throws<ArgumentException>(() => cipher.DecryptCbc(new byte[length], iv, PaddingMode.None));
        Assert.Throws<ArgumentException>(() => cipher.DecryptCbc(new byte[length], iv, destination, PaddingMode.None));
        Assert.Throws<ArgumentException>(() => cipher.TryDecryptCbc(new byte[length], iv, destination, out _, PaddingMode.None));
        Assert.All(destination, value => Assert.Equal(0xAA, value));
    }

    [Theory]
    [InlineData(MkvBlockSize.Mkv128)]
    [InlineData(MkvBlockSize.Mkv256)]
    public void In_place_round_trip_without_padding(MkvBlockSize blockSize)
    {
        using MkvCipher cipher = CreateCipher(blockSize);
        int blockBytes = BlockBytes(blockSize);
        byte[] iv = SeededBytes(blockBytes, 2);
        foreach (int blocks in BatchBoundaryBlockCounts(cipher.Engine.BatchBlocks))
        {
            byte[] plaintext = SeededBytes(blocks * blockBytes, 3);
            byte[] expected = cipher.EncryptCbc(plaintext, iv, PaddingMode.None);
            byte[] buffer = (byte[])plaintext.Clone();

            Assert.Equal(expected.Length, cipher.EncryptCbc(buffer, iv, buffer, PaddingMode.None));
            Assert.Equal(expected, buffer);
            Assert.Equal(plaintext.Length, cipher.DecryptCbc(buffer, iv, buffer, PaddingMode.None));
            Assert.Equal(plaintext, buffer);
        }
    }

    [Theory]
    [InlineData(MkvBlockSize.Mkv128)]
    [InlineData(MkvBlockSize.Mkv256)]
    public void Without_padding_matches_block_by_block_reference(MkvBlockSize blockSize)
    {
        using MkvCipher cipher = CreateCipher(blockSize);
        int blockBytes = BlockBytes(blockSize);
        byte[] iv = SeededBytes(blockBytes, 2);
        byte[] plaintext = SeededBytes(3 * blockBytes, 3);

        Assert.Equal(ReferenceEncrypt(cipher, plaintext, iv), cipher.EncryptCbc(plaintext, iv, PaddingMode.None));
    }

    [Fact]
    public void Unsupported_padding_mode_throws()
    {
        using MkvCipher cipher = CreateCipher(MkvBlockSize.Mkv128);
        byte[] iv = SeededBytes(16, 2);
        byte[] data = new byte[16];
        byte[] destination = new byte[32];

        Assert.Throws<ArgumentOutOfRangeException>(() => cipher.EncryptCbc(data, iv, PaddingMode.Zeros));
        Assert.Throws<ArgumentOutOfRangeException>(() => cipher.EncryptCbc(data, iv, destination, PaddingMode.Zeros));
        Assert.Throws<ArgumentOutOfRangeException>(() => cipher.TryEncryptCbc(data, iv, destination, out _, PaddingMode.Zeros));
        Assert.Throws<ArgumentOutOfRangeException>(() => cipher.DecryptCbc(data, iv, PaddingMode.Zeros));
        Assert.Throws<ArgumentOutOfRangeException>(() => cipher.DecryptCbc(data, iv, destination, PaddingMode.Zeros));
        Assert.Throws<ArgumentOutOfRangeException>(() => cipher.TryDecryptCbc(data, iv, destination, out _, PaddingMode.Zeros));
        Assert.Throws<ArgumentOutOfRangeException>(() => cipher.GetCiphertextLengthCbc(16, PaddingMode.Zeros));
    }

    [Fact]
    public void Pkcs7_default_unchanged()
    {
        using MkvCipher cipher = CreateCipher(MkvBlockSize.Mkv128);
        byte[] iv = SeededBytes(16, 2);
        byte[] plaintext = SeededBytes(37, 3);

        byte[] ciphertext = cipher.EncryptCbc(plaintext, iv);

        Assert.Equal(cipher.EncryptCbc(plaintext, iv, PaddingMode.PKCS7), ciphertext);
        Assert.Equal(plaintext, cipher.DecryptCbc(ciphertext, iv));
    }

    [Theory]
    [InlineData(MkvBlockSize.Mkv128)]
    [InlineData(MkvBlockSize.Mkv256)]
    public void Without_padding_length_is_unchanged(MkvBlockSize blockSize)
    {
        using MkvCipher cipher = CreateCipher(blockSize);
        int length = 3 * BlockBytes(blockSize);

        Assert.Equal(length, cipher.GetCiphertextLengthCbc(length, PaddingMode.None));
        Assert.Equal(0, cipher.GetCiphertextLengthCbc(0, PaddingMode.None));
    }

    [Theory]
    [InlineData(MkvBlockSize.Mkv128)]
    [InlineData(MkvBlockSize.Mkv256)]
    public void None_overloads_throw_after_dispose(MkvBlockSize blockSize)
    {
        MkvCipher cipher = CreateCipher(blockSize);
        int blockBytes = BlockBytes(blockSize);
        byte[] data = new byte[blockBytes];
        byte[] iv = new byte[blockBytes];
        byte[] destination = new byte[2 * blockBytes];
        cipher.Dispose();

        Assert.Throws<ObjectDisposedException>(() => cipher.EncryptCbc(data, iv, PaddingMode.None));
        Assert.Throws<ObjectDisposedException>(() => cipher.EncryptCbc(data, iv, destination, PaddingMode.None));
        Assert.Throws<ObjectDisposedException>(() => cipher.TryEncryptCbc(data, iv, destination, out _, PaddingMode.None));
        Assert.Throws<ObjectDisposedException>(() => cipher.DecryptCbc(data, iv, PaddingMode.None));
        Assert.Throws<ObjectDisposedException>(() => cipher.DecryptCbc(data, iv, destination, PaddingMode.None));
        Assert.Throws<ObjectDisposedException>(() => cipher.TryDecryptCbc(data, iv, destination, out _, PaddingMode.None));
        Assert.Throws<ObjectDisposedException>(() => cipher.GetCiphertextLengthCbc(blockBytes, PaddingMode.None));
    }

    // Unpadded CBC with a block-by-block loop, written here so the reference does not depend on the code under test.
    private static byte[] ReferenceEncrypt(MkvCipher cipher, byte[] plaintext, byte[] iv)
    {
        int blockBytes = cipher.BlockSizeBytes;
        byte[] ciphertext = new byte[plaintext.Length];
        byte[] previous = iv;
        for (int offset = 0; offset < plaintext.Length; offset += blockBytes)
        {
            byte[] block = Xor(plaintext[offset..(offset + blockBytes)], previous);
            cipher.EncryptBlock(block, ciphertext.AsSpan(offset, blockBytes));
            previous = ciphertext[offset..(offset + blockBytes)];
        }

        return ciphertext;
    }
}
