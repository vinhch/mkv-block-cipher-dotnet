using System.Security.Cryptography;
using MkvBlockCipher.Kernels;
using MkvBlockCipher.Modes;
using MkvBlockCipher.Primitives;
using Xunit;
using static MkvBlockCipher.Tests.Modes.ModeTestSupport;

namespace MkvBlockCipher.Tests.Modes;

public sealed class CbcTests
{
    private const string DecryptFailure = "The data could not be decrypted.";
    private const byte DataByte = 0xA5;

    public static TheoryData<MkvBlockSize, int> RoundTripCases()
    {
        TheoryData<MkvBlockSize, int> cases = new();
        foreach (MkvBlockSize blockSize in BlockSizes)
        {
            int blockBytes = BlockBytes(blockSize);
            for (int length = 0; length <= 3 * blockBytes + 1; length++)
            {
                cases.Add(blockSize, length);
            }
        }

        return cases;
    }

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
    [MemberData(nameof(RoundTripCases))]
    public void Round_trip_lengths(MkvBlockSize blockSize, int length)
    {
        using MkvCipher cipher = CreateCipher(blockSize);
        int blockBytes = BlockBytes(blockSize);
        byte[] iv = SeededBytes(blockBytes, 2);
        byte[] plaintext = SeededBytes(length, 3);

        byte[] ciphertext = cipher.EncryptCbc(plaintext, iv);

        Assert.Equal((length / blockBytes + 1) * blockBytes, ciphertext.Length);
        Assert.Equal(plaintext, cipher.DecryptCbc(ciphertext, iv));
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
    [InlineData(MkvBlockSize.Mkv128)]
    [InlineData(MkvBlockSize.Mkv256)]
    public void In_place_round_trip(MkvBlockSize blockSize)
    {
        using MkvCipher cipher = CreateCipher(blockSize);
        int blockBytes = BlockBytes(blockSize);
        byte[] iv = SeededBytes(blockBytes, 2);
        foreach (int blocks in BatchBoundaryBlockCounts(cipher.Engine.BatchBlocks))
        {
            byte[] plaintext = SeededBytes(PlaintextLengthFor(blocks, blockBytes), 3);
            byte[] expected = cipher.EncryptCbc(plaintext, iv);
            byte[] buffer = new byte[expected.Length];
            plaintext.CopyTo(buffer, 0);

            Assert.Equal(expected.Length, cipher.EncryptCbc(buffer.AsSpan(0, plaintext.Length), iv, buffer));
            Assert.Equal(expected, buffer);
            Assert.Equal(plaintext.Length, cipher.DecryptCbc(buffer, iv, buffer));
            Assert.Equal(plaintext, buffer.AsSpan(0, plaintext.Length).ToArray());
        }
    }

    [Theory]
    [InlineData(MkvBlockSize.Mkv128)]
    [InlineData(MkvBlockSize.Mkv256)]
    public void Batch_boundaries_match_block_by_block_reference(MkvBlockSize blockSize)
    {
        using MkvCipher cipher = CreateCipher(blockSize);
        int blockBytes = BlockBytes(blockSize);
        byte[] iv = SeededBytes(blockBytes, 2);
        foreach (int blocks in BatchBoundaryBlockCounts(cipher.Engine.BatchBlocks))
        {
            byte[] plaintext = SeededBytes(PlaintextLengthFor(blocks, blockBytes), 3);
            byte[] expected = ReferenceEncrypt(cipher, PadReference(plaintext, blockBytes), iv);

            Assert.Equal(expected, cipher.EncryptCbc(plaintext, iv));
            Assert.Equal(plaintext, cipher.DecryptCbc(expected, iv));
        }
    }

    [Theory]
    [MemberData(nameof(ModeTestSupport.EngineCases), MemberType = typeof(ModeTestSupport))]
    public void Every_engine_gives_the_same_chunked_cbc(MkvBlockSize blockSize, string engineName)
    {
        using MkvCipher cipher = CreateCipher(blockSize);
        int blockBytes = BlockBytes(blockSize);
        MkvParameters parameters = MkvParameters.Create(blockSize, blockBytes, Revision);
        BlockEngine engine = EngineFactory.AllSupported(parameters).Single(e => e.GetType().Name == engineName);
        BlockEngine reference = new ScalarEngine(parameters);
        byte[] roundKeys = cipher.RoundKeys.ToArray();
        byte[] iv = SeededBytes(blockBytes, 2);
        foreach (int blocks in BatchBoundaryBlockCounts(engine.BatchBlocks))
        {
            byte[] plaintext = SeededBytes(PlaintextLengthFor(blocks, blockBytes), 3);
            byte[] expected = new byte[blocks * blockBytes];
            byte[] actual = new byte[expected.Length];
            Cbc.Encrypt(reference, roundKeys, plaintext, iv, expected);
            Cbc.Encrypt(engine, roundKeys, plaintext, iv, actual);
            Assert.Equal(expected, actual);

            byte[] decrypted = new byte[expected.Length];
            int length = Cbc.Decrypt(engine, roundKeys, expected, iv, decrypted);
            Assert.Equal(plaintext, decrypted.AsSpan(0, length).ToArray());

            byte[] inPlace = (byte[])expected.Clone();
            int inPlaceLength = Cbc.Decrypt(engine, roundKeys, inPlace, iv, inPlace);
            Assert.Equal(plaintext, inPlace.AsSpan(0, inPlaceLength).ToArray());
        }
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

    [Theory]
    [InlineData(MkvBlockSize.Mkv128)]
    [InlineData(MkvBlockSize.Mkv256)]
    public void First_block_equals_EncryptBlock_of_plaintext_xor_iv(MkvBlockSize blockSize)
    {
        using MkvCipher cipher = CreateCipher(blockSize);
        int blockBytes = BlockBytes(blockSize);
        byte[] plaintext = SeededBytes(blockBytes, 4);
        byte[] iv = SeededBytes(blockBytes, 5);
        byte[] expected = EncryptOneBlock(cipher, Xor(plaintext, iv));

        byte[] ciphertext = cipher.EncryptCbc(plaintext, iv);

        Assert.Equal(expected, ciphertext[..blockBytes]);
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
