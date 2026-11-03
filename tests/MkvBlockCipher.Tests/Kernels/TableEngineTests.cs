using MkvBlockCipher.Kernels;
using MkvBlockCipher.Primitives;
using Xunit;

namespace MkvBlockCipher.Tests.Kernels;

public sealed class TableEngineTests
{
    private const MkvRevision Revision = MkvRevision.Rev2026;

    // Random parity reaches only part of each table, so every entry is compared with the scalar mix.
    [Theory]
    [InlineData(MkvBlockSize.Mkv128)]
    [InlineData(MkvBlockSize.Mkv256)]
    public void Forward_tables_match_scalar_mix_on_every_entry(MkvBlockSize blockSize)
    {
        int wordBytes = WordBytes(blockSize);
        ReadOnlySpan<byte> matrix = wordBytes == 4 ? MixMatrices.M4 : MixMatrices.M8;
        for (int column = 0; column < wordBytes; column++)
        {
            for (int value = 0; value < 256; value++)
            {
                ulong expected = ScalarMixOfByte(wordBytes, matrix, column, SBoxTables.Forward[value]);
                Assert.Equal(expected, ForwardEntry(wordBytes, (column << 8) | value));
            }
        }
    }

    [Theory]
    [InlineData(MkvBlockSize.Mkv128)]
    [InlineData(MkvBlockSize.Mkv256)]
    public void Inverse_tables_match_scalar_mix_on_every_entry(MkvBlockSize blockSize)
    {
        int wordBytes = WordBytes(blockSize);
        ReadOnlySpan<byte> matrix = wordBytes == 4 ? MixMatrices.M4Inverse : MixMatrices.M8Inverse;
        for (int column = 0; column < wordBytes; column++)
        {
            for (int value = 0; value < 256; value++)
            {
                ulong expected = ScalarMixOfByte(wordBytes, matrix, column, (byte)value);
                Assert.Equal(expected, InverseEntry(wordBytes, (column << 8) | value));
            }
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
        TableEngine engine = new(MkvParameters.Create(MkvBlockSize.Mkv128, 16, Revision));
        byte[] state = new byte[stateLength];
        byte[] k0 = new byte[k0Length];
        byte[] k1 = new byte[k1Length];

        AssertRejectsParameter(paramName, () => engine.Round(state, k0, k1));
        AssertRejectsParameter(paramName, () => engine.InverseRound(state, k0, k1));
    }

    [Theory]
    [InlineData(false, 0, 16)]
    [InlineData(false, 16, 0)]
    [InlineData(true, 0, 16)]
    [InlineData(true, 16, 0)]
    public void Blocks_reject_partial_overlap(bool decrypt, int sourceStart, int destinationStart)
    {
        MkvParameters parameters = MkvParameters.Create(MkvBlockSize.Mkv128, 16, Revision);
        TableEngine engine = new(parameters);
        byte[] roundKeys = new byte[(2 * parameters.Rounds + 1) * parameters.BlockBytes];
        byte[] buffer = new byte[48];

        AssertRejectsParameter("destination", () => Run(
            engine, decrypt, roundKeys, buffer.AsSpan(sourceStart, 32), buffer.AsSpan(destinationStart, 32)));
    }

    private static int WordBytes(MkvBlockSize blockSize) => blockSize == MkvBlockSize.Mkv128 ? 4 : 8;

    // Puts one byte in word 0 and reads word 0 back after the scalar mix, so the result is one table entry.
    private static ulong ScalarMixOfByte(int wordBytes, ReadOnlySpan<byte> matrix, int column, byte value)
    {
        byte[] state = new byte[4 * wordBytes];
        state[column] = value;
        ScalarLayers.MixWords(state, wordBytes, matrix);

        ulong packed = 0;
        for (int row = 0; row < wordBytes; row++)
        {
            packed |= (ulong)state[row] << (8 * row);
        }

        return packed;
    }

    private static ulong ForwardEntry(int wordBytes, int index) =>
        wordBytes == 4 ? FusedTables.Forward32[index] : FusedTables.Forward64[index];

    private static ulong InverseEntry(int wordBytes, int index) =>
        wordBytes == 4 ? FusedTables.Inverse32[index] : FusedTables.Inverse64[index];

    private static void Run(
        TableEngine engine, bool decrypt, ReadOnlySpan<byte> roundKeys, ReadOnlySpan<byte> source, Span<byte> destination)
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

    private static void AssertRejectsParameter(string paramName, Action action)
    {
        ArgumentException exception = Assert.Throws<ArgumentException>(action);
        Assert.Equal(paramName, exception.ParamName);
    }
}
