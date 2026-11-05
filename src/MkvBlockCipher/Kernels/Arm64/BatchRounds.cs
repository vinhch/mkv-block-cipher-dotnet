using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;
using System.Security.Cryptography;
using MkvBlockCipher.Primitives;

namespace MkvBlockCipher.Kernels.Arm64;

// 16 blocks in byte-sliced form: position p of every block sits in one Vector128, one block per byte lane.
// Each layer works lane by lane, so a batch costs one pass of the round functions for all 16 blocks.
// The stack copy is cleared; register values are not.
internal static class BatchRounds
{
    private const int WordsPerBlock = 4;

    // Compiled fully optimized on the first call. Dynamic PGO is off for these methods.
    [MethodImpl(MethodImplOptions.AggressiveOptimization)]
    internal static void Encrypt(
        MkvParameters parameters, ReadOnlySpan<byte> roundKeys, ReadOnlySpan<byte> source, Span<byte> destination)
    {
        int blockBytes = parameters.BlockBytes;
        Span<byte> sliced = stackalloc byte[source.Length];
        ByteSlice.Gather(source, blockBytes, sliced);
        Span<Vector128<byte>> state = MemoryMarshal.Cast<byte, Vector128<byte>>(sliced);
        for (int round = 0; round < parameters.Rounds; round++)
        {
            ForwardRound(
                state,
                parameters,
                RoundKey(roundKeys, blockBytes, 2 * round),
                RoundKey(roundKeys, blockBytes, 2 * round + 1));
        }

        AddRoundKey(state, RoundKey(roundKeys, blockBytes, 2 * parameters.Rounds));
        ByteSlice.Scatter(sliced, blockBytes, destination);
        CryptographicOperations.ZeroMemory(sliced);
    }

    [MethodImpl(MethodImplOptions.AggressiveOptimization)]
    internal static void Decrypt(
        MkvParameters parameters, ReadOnlySpan<byte> roundKeys, ReadOnlySpan<byte> source, Span<byte> destination)
    {
        int blockBytes = parameters.BlockBytes;
        Span<byte> sliced = stackalloc byte[source.Length];
        ByteSlice.Gather(source, blockBytes, sliced);
        Span<Vector128<byte>> state = MemoryMarshal.Cast<byte, Vector128<byte>>(sliced);
        AddRoundKey(state, RoundKey(roundKeys, blockBytes, 2 * parameters.Rounds));
        for (int round = parameters.Rounds - 1; round >= 0; round--)
        {
            InvertRound(
                state,
                parameters,
                RoundKey(roundKeys, blockBytes, 2 * round),
                RoundKey(roundKeys, blockBytes, 2 * round + 1));
        }

        ByteSlice.Scatter(sliced, blockBytes, destination);
        CryptographicOperations.ZeroMemory(sliced);
    }

    private static void ForwardRound(
        Span<Vector128<byte>> state, MkvParameters parameters, ReadOnlySpan<byte> k0, ReadOnlySpan<byte> k1)
    {
        int wordBytes = parameters.WordBytes;
        AddRoundKey(state, k0);
        SubCells(state, inverse: false);
        MixWords(
            state,
            wordBytes,
            wordBytes == 4 ? MixMatrices.M4 : MixMatrices.M8,
            parameters.RotationStepBytes,
            0);
        AddRoundKey(state, k1);
        SubCells(state, inverse: false);
        XWords(state, wordBytes);
    }

    private static void InvertRound(
        Span<Vector128<byte>> state, MkvParameters parameters, ReadOnlySpan<byte> k0, ReadOnlySpan<byte> k1)
    {
        int wordBytes = parameters.WordBytes;
        XWords(state, wordBytes);
        SubCells(state, inverse: true);
        AddRoundKey(state, k1);
        MixWords(
            state,
            wordBytes,
            wordBytes == 4 ? MixMatrices.M4Inverse : MixMatrices.M8Inverse,
            0,
            parameters.RotationStepBytes);
        SubCells(state, inverse: true);
        AddRoundKey(state, k0);
    }

    // Round keys are the same for every block, so each key byte is one broadcast across the lanes.
    private static void AddRoundKey(Span<Vector128<byte>> state, ReadOnlySpan<byte> roundKey)
    {
        for (int position = 0; position < state.Length; position++)
        {
            state[position] ^= Vector128.Create(roundKey[position]);
        }
    }

    private static void SubCells(Span<Vector128<byte>> state, bool inverse)
    {
        ReadOnlySpan<Vector128<byte>> entries = SBoxTableLookup.Entries(inverse);
        for (int position = 0; position < state.Length; position++)
        {
            state[position] = SBoxTableLookup.Lookup(state[position], entries);
        }
    }

    // Each word's output row is computed fully before it overwrites the word's bytes. Word w reads column
    // (column + w * inputStepBytes) mod wordBytes and stores row r at (r + w * outputStepBytes) mod wordBytes.
    // wordBytes is a power of two, so the mask is the modulus.
    private static void MixWords(
        Span<Vector128<byte>> state, int wordBytes, ReadOnlySpan<byte> matrix, int inputStepBytes, int outputStepBytes)
    {
        Span<Vector128<byte>> mixed = stackalloc Vector128<byte>[wordBytes];
        for (int word = 0; word < WordsPerBlock; word++)
        {
            int first = word * wordBytes;
            int inputShift = word * inputStepBytes;
            for (int row = 0; row < wordBytes; row++)
            {
                Vector128<byte> sum = Vector128<byte>.Zero;
                for (int column = 0; column < wordBytes; column++)
                {
                    int source = (column + inputShift) & (wordBytes - 1);
                    sum ^= GfMultiply.Multiply(state[first + source], matrix[row * wordBytes + column]);
                }

                mixed[row] = sum;
            }

            int outputShift = word * outputStepBytes;
            for (int row = 0; row < wordBytes; row++)
            {
                state[first + ((row + outputShift) & (wordBytes - 1))] = mixed[row];
            }
        }

        CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(mixed));
    }

    private static void XWords(Span<Vector128<byte>> state, int wordBytes)
    {
        for (int column = 0; column < wordBytes; column++)
        {
            Vector128<byte> total = Vector128<byte>.Zero;
            for (int word = 0; word < WordsPerBlock; word++)
            {
                total ^= state[word * wordBytes + column];
            }

            for (int word = 0; word < WordsPerBlock; word++)
            {
                state[word * wordBytes + column] ^= total;
            }
        }
    }

    private static ReadOnlySpan<byte> RoundKey(ReadOnlySpan<byte> roundKeys, int blockBytes, int index) =>
        roundKeys.Slice(index * blockBytes, blockBytes);
}
