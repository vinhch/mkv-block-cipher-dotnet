using MkvBlockCipher.Kernels;
using MkvBlockCipher.Modes;
using MkvBlockCipher.Primitives;
using Xunit;
using static MkvBlockCipher.Tests.Modes.ModeTestSupport;

namespace MkvBlockCipher.Tests.Modes;

public sealed class CbcRoundTripTests
{
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
}
