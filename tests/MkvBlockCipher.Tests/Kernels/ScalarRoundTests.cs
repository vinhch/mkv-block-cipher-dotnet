using MkvBlockCipher.Kernels;
using MkvBlockCipher.Primitives;
using MkvBlockCipher.Tests.TestData;
using Xunit;

namespace MkvBlockCipher.Tests.Kernels;

public sealed class ScalarRoundTests
{
    [Fact]
    public void SubCells_constant_time_matches_table()
    {
        byte[] state = new byte[256];
        for (int x = 0; x < 256; x++)
        {
            state[x] = (byte)x;
        }

        ScalarLayers.SubCells(state, SBoxTables.Forward);

        for (int x = 0; x < 256; x++)
        {
            Assert.Equal(SBoxTables.Forward[x], state[x]);
        }
    }

    [Fact]
    public void Round1_steps_128()
    {
        AssertRound1Steps(RoundTraces.Mkv128, 4, MixMatrices.M4);
    }

    [Fact]
    public void Round1_steps_256()
    {
        AssertRound1Steps(RoundTraces.Mkv256, 8, MixMatrices.M8);
    }

    [Fact]
    public void All_rounds_128()
    {
        AssertAllRounds(MkvParameters.Create(MkvBlockSize.Mkv128, 16, MkvRevision.Rev2024), RoundTraces.Mkv128);
    }

    [Fact]
    public void All_rounds_256()
    {
        AssertAllRounds(MkvParameters.Create(MkvBlockSize.Mkv256, 32, MkvRevision.Rev2024), RoundTraces.Mkv256);
    }

    [Theory]
    [InlineData(MkvBlockSize.Mkv128, 16)]
    [InlineData(MkvBlockSize.Mkv256, 32)]
    public void InverseRound_undoes_Round(MkvBlockSize blockSize, int keyLength)
    {
        MkvParameters parameters = MkvParameters.Create(blockSize, keyLength, MkvRevision.Rev2024);
        ScalarEngine engine = new(parameters);
        Random random = new(1);
        byte[] state = new byte[parameters.BlockBytes];
        byte[] k0 = new byte[parameters.BlockBytes];
        byte[] k1 = new byte[parameters.BlockBytes];

        for (int i = 0; i < 1000; i++)
        {
            random.NextBytes(state);
            random.NextBytes(k0);
            random.NextBytes(k1);
            byte[] original = (byte[])state.Clone();

            engine.Round(state, k0, k1);
            engine.InverseRound(state, k0, k1);

            Assert.Equal(original, state);
        }
    }

    [Theory]
    [InlineData(MkvBlockSize.Mkv128)]
    [InlineData(MkvBlockSize.Mkv256)]
    public void EncryptBlocks_matches_published_ciphertext(MkvBlockSize blockSize)
    {
        (MkvParameters parameters, RoundTrace trace) = PublishedVector(blockSize);
        ScalarEngine engine = new(parameters);
        byte[] roundKeys = FlatRoundKeys(trace);
        byte[] buffer = Convert.FromHexString(trace.Plaintext);
        byte[] ciphertext = new byte[buffer.Length];

        engine.EncryptBlocks(roundKeys, buffer, ciphertext);
        Assert.Equal(trace.Ciphertext, Convert.ToHexString(ciphertext));

        engine.EncryptBlocks(roundKeys, buffer, buffer);
        Assert.Equal(trace.Ciphertext, Convert.ToHexString(buffer));
    }

    [Theory]
    [InlineData(MkvBlockSize.Mkv128)]
    [InlineData(MkvBlockSize.Mkv256)]
    public void DecryptBlocks_recovers_published_plaintext(MkvBlockSize blockSize)
    {
        (MkvParameters parameters, RoundTrace trace) = PublishedVector(blockSize);
        ScalarEngine engine = new(parameters);
        byte[] plaintext = new byte[parameters.BlockBytes];

        engine.DecryptBlocks(FlatRoundKeys(trace), Convert.FromHexString(trace.Ciphertext), plaintext);

        Assert.Equal(trace.Plaintext, Convert.ToHexString(plaintext));
    }

    [Theory]
    [InlineData(MkvBlockSize.Mkv128)]
    [InlineData(MkvBlockSize.Mkv256)]
    public void EncryptBlocks_matches_block_by_block_at_batch_boundaries(MkvBlockSize blockSize)
    {
        (MkvParameters parameters, RoundTrace trace) = PublishedVector(blockSize);
        ScalarEngine engine = new(parameters);
        byte[] roundKeys = FlatRoundKeys(trace);
        Random random = new(1);
        int batch = engine.BatchBlocks;

        foreach (int blocks in new[] { batch - 1, batch, batch + 1, 3 * batch + 5 })
        {
            byte[] source = new byte[blocks * parameters.BlockBytes];
            random.NextBytes(source);

            byte[] expected = new byte[source.Length];
            for (int offset = 0; offset < source.Length; offset += parameters.BlockBytes)
            {
                engine.EncryptBlocks(
                    roundKeys,
                    source.AsSpan(offset, parameters.BlockBytes),
                    expected.AsSpan(offset, parameters.BlockBytes));
            }

            byte[] encrypted = new byte[source.Length];
            engine.EncryptBlocks(roundKeys, source, encrypted);
            Assert.Equal(expected, encrypted);

            byte[] decrypted = new byte[source.Length];
            engine.DecryptBlocks(roundKeys, encrypted, decrypted);
            Assert.Equal(source, decrypted);
        }
    }

    [Theory]
    [InlineData(0, 16, 16, "state")]
    [InlineData(15, 16, 16, "state")]
    [InlineData(16, 15, 16, "k0")]
    [InlineData(16, 16, 17, "k1")]
    public void Round_rejects_arguments_that_are_not_one_block(
        int stateLength, int k0Length, int k1Length, string paramName)
    {
        ScalarEngine engine = new(MkvParameters.Create(MkvBlockSize.Mkv128, 16, MkvRevision.Rev2024));
        byte[] state = new byte[stateLength];
        byte[] k0 = new byte[k0Length];
        byte[] k1 = new byte[k1Length];

        AssertRejectsParameter(paramName, () => engine.Round(state, k0, k1));
        AssertRejectsParameter(paramName, () => engine.InverseRound(state, k0, k1));
    }

    [Theory]
    [InlineData(false, 17, 17, 13 * 16, "source")]
    [InlineData(true, 17, 17, 13 * 16, "source")]
    [InlineData(false, 16, 15, 13 * 16, "destination")]
    [InlineData(true, 16, 15, 13 * 16, "destination")]
    [InlineData(false, 16, 16, 12 * 16, "roundKeys")]
    [InlineData(true, 16, 16, 12 * 16, "roundKeys")]
    public void Blocks_reject_wrong_source_destination_or_round_key_length(
        bool decrypt, int sourceLength, int destinationLength, int roundKeyLength, string paramName)
    {
        ScalarEngine engine = new(MkvParameters.Create(MkvBlockSize.Mkv128, 16, MkvRevision.Rev2024));
        byte[] roundKeys = new byte[roundKeyLength];
        byte[] source = new byte[sourceLength];
        byte[] destination = new byte[destinationLength];

        AssertRejectsParameter(paramName, () => Run(engine, decrypt, roundKeys, source, destination));
    }

    [Theory]
    [InlineData(false, 0, 16)]
    [InlineData(false, 16, 0)]
    [InlineData(true, 0, 16)]
    [InlineData(true, 16, 0)]
    public void Blocks_reject_partial_overlap(bool decrypt, int sourceStart, int destinationStart)
    {
        ScalarEngine engine = new(MkvParameters.Create(MkvBlockSize.Mkv128, 16, MkvRevision.Rev2024));
        byte[] roundKeys = new byte[13 * 16];
        byte[] buffer = new byte[48];

        AssertRejectsParameter("destination", () => Run(
            engine, decrypt, roundKeys, buffer.AsSpan(sourceStart, 32), buffer.AsSpan(destinationStart, 32)));
    }

    private static void AssertRejectsParameter(string paramName, Action action)
    {
        ArgumentException exception = Assert.Throws<ArgumentException>(action);
        Assert.Equal(paramName, exception.ParamName);
    }

    private static void AssertRound1Steps(RoundTrace trace, int wordBytes, ReadOnlySpan<byte> matrix)
    {
        string[] steps = trace.Rounds[0];
        byte[] state = Convert.FromHexString(trace.Plaintext);

        ScalarLayers.AddRoundKey(state, Key(trace, 0));
        Assert.Equal(steps[0], Convert.ToHexString(state));

        ScalarLayers.SubCells(state, SBoxTables.Forward);
        Assert.Equal(steps[1], Convert.ToHexString(state));

        ScalarLayers.MixWords(state, wordBytes, matrix);
        Assert.Equal(steps[2], Convert.ToHexString(state));

        ScalarLayers.AddRoundKey(state, Key(trace, 1));
        Assert.Equal(steps[3], Convert.ToHexString(state));

        ScalarLayers.SubCells(state, SBoxTables.Forward);
        Assert.Equal(steps[4], Convert.ToHexString(state));

        ScalarLayers.XWords(state, wordBytes);
        Assert.Equal(steps[5], Convert.ToHexString(state));
    }

    private static void AssertAllRounds(MkvParameters parameters, RoundTrace trace)
    {
        ScalarEngine engine = new(parameters);
        byte[] state = Convert.FromHexString(trace.Plaintext);

        for (int round = 0; round < parameters.Rounds; round++)
        {
            engine.Round(state, Key(trace, 2 * round), Key(trace, 2 * round + 1));
            Assert.Equal(trace.Rounds[round][5], Convert.ToHexString(state));
        }

        ScalarLayers.AddRoundKey(state, Key(trace, 2 * parameters.Rounds));
        Assert.Equal(trace.Ciphertext, Convert.ToHexString(state));
    }

    private static (MkvParameters Parameters, RoundTrace Trace) PublishedVector(MkvBlockSize blockSize) =>
        blockSize == MkvBlockSize.Mkv128
            ? (MkvParameters.Create(blockSize, 16, MkvRevision.Rev2024), RoundTraces.Mkv128)
            : (MkvParameters.Create(blockSize, 32, MkvRevision.Rev2024), RoundTraces.Mkv256);

    private static byte[] Key(RoundTrace trace, int index) => Convert.FromHexString(trace.RoundKeys[index]);

    private static byte[] FlatRoundKeys(RoundTrace trace) => Convert.FromHexString(string.Concat(trace.RoundKeys));

    private static void Run(
        ScalarEngine engine, bool decrypt, ReadOnlySpan<byte> roundKeys, ReadOnlySpan<byte> source, Span<byte> destination)
    {
        if (decrypt)
        {
            engine.DecryptBlocks(roundKeys, source, destination);
        }
        else
        {
            engine.EncryptBlocks(roundKeys, source, destination);
        }
    }
}
