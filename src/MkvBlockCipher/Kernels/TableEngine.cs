using System.Buffers.Binary;
using System.Numerics;
using MkvBlockCipher.Primitives;

namespace MkvBlockCipher.Kernels;

// One block per pass. The S-layers and the mix are table lookups indexed by state bytes, so timing depends on the data.
internal sealed class TableEngine(MkvParameters parameters) : BlockEngine(parameters)
{
    private const int WordsPerBlock = 4;

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

    // Same layers as ScalarEngine, with the S-layer before the mix folded into FusedTables.
    private void ForwardRound(Span<byte> state, ReadOnlySpan<byte> k0, ReadOnlySpan<byte> k1)
    {
        ScalarLayers.AddRoundKey(state, k0);
        ForwardMix(state);
        ScalarLayers.AddRoundKey(state, k1);
        Substitute(state, SBoxTables.Forward);
        ScalarLayers.XWords(state, Parameters.WordBytes);
    }

    private void InvertRound(Span<byte> state, ReadOnlySpan<byte> k0, ReadOnlySpan<byte> k1)
    {
        ScalarLayers.XWords(state, Parameters.WordBytes);
        Substitute(state, SBoxTables.Inverse);
        ScalarLayers.AddRoundKey(state, k1);
        InverseMix(state);
        Substitute(state, SBoxTables.Inverse);
        ScalarLayers.AddRoundKey(state, k0);
    }

    private void ForwardMix(Span<byte> state)
    {
        int stepBytes = Parameters.RotationStepBytes;
        if (Parameters.WordBytes == 4)
        {
            MixWords32(state, FusedTables.Forward32, stepBytes, 0);
        }
        else
        {
            MixWords64(state, FusedTables.Forward64, stepBytes, 0);
        }
    }

    private void InverseMix(Span<byte> state)
    {
        int stepBytes = Parameters.RotationStepBytes;
        if (Parameters.WordBytes == 4)
        {
            MixWords32(state, FusedTables.Inverse32, 0, stepBytes);
        }
        else
        {
            MixWords64(state, FusedTables.Inverse64, 0, stepBytes);
        }
    }

    // Each output word is the XOR of one table entry per input byte of that word. Word w reads column
    // (column + w * inputStepBytes) mod 4, and its packed output is rotated left by w * outputStepBytes bytes.
    private static void MixWords32(Span<byte> state, ReadOnlySpan<uint> table, int inputStepBytes, int outputStepBytes)
    {
        const int wordBytes = 4;
        for (int word = 0; word < WordsPerBlock; word++)
        {
            int offset = word * wordBytes;
            int inputShift = word * inputStepBytes;
            uint mixed = 0;
            for (int column = 0; column < wordBytes; column++)
            {
                mixed ^= table[(column << 8) | state[offset + ((column + inputShift) & (wordBytes - 1))]];
            }

            mixed = BitOperations.RotateLeft(mixed, 8 * word * outputStepBytes);
            BinaryPrimitives.WriteUInt32LittleEndian(state.Slice(offset, wordBytes), mixed);
        }
    }

    private static void MixWords64(Span<byte> state, ReadOnlySpan<ulong> table, int inputStepBytes, int outputStepBytes)
    {
        const int wordBytes = 8;
        for (int word = 0; word < WordsPerBlock; word++)
        {
            int offset = word * wordBytes;
            int inputShift = word * inputStepBytes;
            ulong mixed = 0;
            for (int column = 0; column < wordBytes; column++)
            {
                mixed ^= table[(column << 8) | state[offset + ((column + inputShift) & (wordBytes - 1))]];
            }

            mixed = BitOperations.RotateLeft(mixed, 8 * word * outputStepBytes);
            BinaryPrimitives.WriteUInt64LittleEndian(state.Slice(offset, wordBytes), mixed);
        }
    }

    private static void Substitute(Span<byte> state, ReadOnlySpan<byte> sbox)
    {
        for (int i = 0; i < state.Length; i++)
        {
            state[i] = sbox[state[i]];
        }
    }
}
