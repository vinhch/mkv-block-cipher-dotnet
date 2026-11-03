using MkvBlockCipher.Primitives;

namespace MkvBlockCipher.Kernels;

// One block per pass. Secret bytes reach only arithmetic and masked table scans, never a branch or an index.
internal sealed class ScalarEngine(MkvParameters parameters) : BlockEngine(parameters)
{
    internal override int BatchBlocks => 1;

    internal override void Round(Span<byte> state, ReadOnlySpan<byte> k0, ReadOnlySpan<byte> k1)
    {
        RequireRound(state, k0, k1);
        ForwardRound(state, k0, k1);
    }

    internal override void InverseRound(Span<byte> state, ReadOnlySpan<byte> k0, ReadOnlySpan<byte> k1)
    {
        RequireRound(state, k0, k1);
        InvertRound(state, k0, k1);
    }

    internal override void EncryptBlocks(ReadOnlySpan<byte> roundKeys, ReadOnlySpan<byte> source, Span<byte> destination)
    {
        RequireBatch(roundKeys, source, destination);
        source.CopyTo(destination);
        int blockBytes = Parameters.BlockBytes;
        for (int offset = 0; offset < destination.Length; offset += blockBytes)
        {
            EncryptBlock(destination.Slice(offset, blockBytes), roundKeys);
        }
    }

    internal override void DecryptBlocks(ReadOnlySpan<byte> roundKeys, ReadOnlySpan<byte> source, Span<byte> destination)
    {
        RequireBatch(roundKeys, source, destination);
        source.CopyTo(destination);
        int blockBytes = Parameters.BlockBytes;
        for (int offset = 0; offset < destination.Length; offset += blockBytes)
        {
            DecryptBlock(destination.Slice(offset, blockBytes), roundKeys);
        }
    }

    private ReadOnlySpan<byte> ForwardMatrix => Parameters.WordBytes == 4 ? MixMatrices.M4 : MixMatrices.M8;

    private ReadOnlySpan<byte> InverseMatrix =>
        Parameters.WordBytes == 4 ? MixMatrices.M4Inverse : MixMatrices.M8Inverse;

    private ReadOnlySpan<byte> RoundKeyAt(ReadOnlySpan<byte> roundKeys, int index) =>
        roundKeys.Slice(index * Parameters.BlockBytes, Parameters.BlockBytes);

    private void EncryptBlock(Span<byte> block, ReadOnlySpan<byte> roundKeys)
    {
        int rounds = Parameters.Rounds;
        for (int round = 0; round < rounds; round++)
        {
            ForwardRound(block, RoundKeyAt(roundKeys, 2 * round), RoundKeyAt(roundKeys, 2 * round + 1));
        }

        ScalarLayers.AddRoundKey(block, RoundKeyAt(roundKeys, 2 * rounds));
    }

    private void DecryptBlock(Span<byte> block, ReadOnlySpan<byte> roundKeys)
    {
        int rounds = Parameters.Rounds;
        ScalarLayers.AddRoundKey(block, RoundKeyAt(roundKeys, 2 * rounds));
        for (int round = rounds - 1; round >= 0; round--)
        {
            InvertRound(block, RoundKeyAt(roundKeys, 2 * round), RoundKeyAt(roundKeys, 2 * round + 1));
        }
    }

    private void ForwardRound(Span<byte> state, ReadOnlySpan<byte> k0, ReadOnlySpan<byte> k1)
    {
        int wordBytes = Parameters.WordBytes;
        ScalarLayers.AddRoundKey(state, k0);
        ScalarLayers.SubCells(state, SBoxTables.Forward);
        ScalarLayers.MixWords(state, wordBytes, ForwardMatrix);
        ScalarLayers.AddRoundKey(state, k1);
        ScalarLayers.SubCells(state, SBoxTables.Forward);
        ScalarLayers.XWords(state, wordBytes);
    }

    private void InvertRound(Span<byte> state, ReadOnlySpan<byte> k0, ReadOnlySpan<byte> k1)
    {
        int wordBytes = Parameters.WordBytes;
        ScalarLayers.XWords(state, wordBytes);
        ScalarLayers.SubCells(state, SBoxTables.Inverse);
        ScalarLayers.AddRoundKey(state, k1);
        ScalarLayers.MixWords(state, wordBytes, InverseMatrix);
        ScalarLayers.SubCells(state, SBoxTables.Inverse);
        ScalarLayers.AddRoundKey(state, k0);
    }
}
