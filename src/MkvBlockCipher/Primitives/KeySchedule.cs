using System.Security.Cryptography;
using MkvBlockCipher.Kernels;

namespace MkvBlockCipher.Primitives;

// Round keys RK[0..2R] come from iterating L' = G0(G(2i, R)) and R' = L' ^ G0(G(2i-1, L)), where G keys the
// round with a counter block and G0 with zero keys. Every step runs through the engine's round.
internal static class KeySchedule
{
    private const int WordsPerHalf = 4;

    internal static void Expand(BlockEngine engine, ReadOnlySpan<byte> key, Span<byte> roundKeys)
    {
        MkvParameters parameters = engine.Parameters;
        int blockBytes = parameters.BlockBytes;
        if (key.Length != parameters.KeyBytes)
        {
            throw new ArgumentException("Key length does not match the parameters.", nameof(key));
        }

        if (roundKeys.Length != (2 * parameters.Rounds + 1) * blockBytes)
        {
            throw new ArgumentException("Round keys must hold 2R+1 blocks.", nameof(roundKeys));
        }

        // Left, right, the counter block and an all-zero block. The zero block is never written,
        // so the scratch starts cleared.
        Span<byte> scratch = stackalloc byte[4 * blockBytes];
        scratch.Clear();
        Span<byte> left = scratch.Slice(0, blockBytes);
        Span<byte> right = scratch.Slice(blockBytes, blockBytes);
        Span<byte> counter = scratch.Slice(2 * blockBytes, blockBytes);
        ReadOnlySpan<byte> zero = scratch.Slice(3 * blockBytes, blockBytes);

        // Zero constants leave each counter block as the bare counter, which Rev2024 uses.
        ReadOnlySpan<byte> leftConstant = parameters.UsesRoundConstants ? RoundConstants.Left(blockBytes) : zero;
        ReadOnlySpan<byte> rightConstant = parameters.UsesRoundConstants ? RoundConstants.Right(blockBytes) : zero;

        LoadHalves(key, parameters.WordBytes, left, right);
        left.CopyTo(roundKeys);
        for (int round = 1; round <= parameters.Rounds; round++)
        {
            ApplyChain(engine, left, leftConstant, 2 * round - 1, counter, zero);
            ApplyChain(engine, right, rightConstant, 2 * round, counter, zero);
            ScalarLayers.AddRoundKey(left, right);
            right.CopyTo(roundKeys.Slice((2 * round - 1) * blockBytes));
            left.CopyTo(roundKeys.Slice(2 * round * blockBytes));

            // The new halves sit in the other buffers, so trade the two spans for the next round.
            Span<byte> previousLeft = left;
            left = right;
            right = previousLeft;
        }

        CryptographicOperations.ZeroMemory(scratch);
    }

    // G0(G(counter, block)) in place. The counter block is scratch that holds the constant with the counter
    // XORed into its last byte.
    private static void ApplyChain(
        BlockEngine engine,
        Span<byte> block,
        ReadOnlySpan<byte> constant,
        int counter,
        Span<byte> counterBlock,
        ReadOnlySpan<byte> zero)
    {
        constant.CopyTo(counterBlock);
        counterBlock[^1] ^= (byte)counter;
        engine.Round(block, counterBlock, zero);
        engine.Round(block, zero, zero);
    }

    // Words 0..3 fill the left half and words 4..7 the right. Words the key does not supply repeat
    // words 0..3, complemented.
    private static void LoadHalves(ReadOnlySpan<byte> key, int wordBytes, Span<byte> left, Span<byte> right)
    {
        int keyWords = key.Length / wordBytes;
        for (int word = 0; word < 2 * WordsPerHalf; word++)
        {
            bool complement = word >= keyWords;
            int sourceWord = complement ? word - WordsPerHalf : word;
            ReadOnlySpan<byte> source = key.Slice(sourceWord * wordBytes, wordBytes);
            Span<byte> half = word < WordsPerHalf ? left : right;
            Span<byte> target = half.Slice((word % WordsPerHalf) * wordBytes, wordBytes);
            for (int i = 0; i < wordBytes; i++)
            {
                target[i] = complement ? (byte)~source[i] : source[i];
            }
        }
    }
}
