using System.Security.Cryptography;
using MkvBlockCipher.Primitives;

namespace MkvBlockCipher.Kernels;

// Layers of one round over a block of four words, each wordBytes long. Every layer works in place.
internal static class ScalarLayers
{
    private const int WordsPerBlock = 4;

    internal static void AddRoundKey(Span<byte> state, ReadOnlySpan<byte> roundKey)
    {
        for (int i = 0; i < state.Length; i++)
        {
            state[i] ^= roundKey[i];
        }
    }

    // Every table entry is read for every byte and only the entry at index x survives,
    // so no branch or memory index depends on x.
    internal static void SubCells(Span<byte> state, ReadOnlySpan<byte> table)
    {
        for (int j = 0; j < state.Length; j++)
        {
            int x = state[j];
            byte substituted = 0;
            for (int i = 0; i < 256; i++)
            {
                byte mask = (byte)(0u - (((uint)(i ^ x) - 1) >> 31));
                substituted |= (byte)(table[i] & mask);
            }

            state[j] = substituted;
        }
    }

    // Word w reads column (col + w * inputStepBytes) mod wordBytes and writes row r to
    // (r + w * outputStepBytes) mod wordBytes. Rev2025 rotates the forward input and the inverse output.
    internal static void MixWords(
        Span<byte> state, int wordBytes, ReadOnlySpan<byte> matrix, int inputStepBytes, int outputStepBytes)
    {
        Span<byte> word = stackalloc byte[wordBytes];
        for (int w = 0; w < WordsPerBlock; w++)
        {
            int offset = w * wordBytes;
            int inputShift = w * inputStepBytes;
            int outputShift = w * outputStepBytes;
            for (int col = 0; col < wordBytes; col++)
            {
                word[col] = state[offset + (col + inputShift) % wordBytes];
            }

            for (int row = 0; row < wordBytes; row++)
            {
                byte mixed = 0;
                for (int col = 0; col < wordBytes; col++)
                {
                    mixed ^= GaloisField.Multiply(matrix[row * wordBytes + col], word[col]);
                }

                state[offset + (row + outputShift) % wordBytes] = mixed;
            }
        }

        CryptographicOperations.ZeroMemory(word);
    }

    internal static void XWords(Span<byte> state, int wordBytes)
    {
        for (int column = 0; column < wordBytes; column++)
        {
            byte total = 0;
            for (int w = 0; w < WordsPerBlock; w++)
            {
                total ^= state[w * wordBytes + column];
            }

            for (int w = 0; w < WordsPerBlock; w++)
            {
                state[w * wordBytes + column] ^= total;
            }
        }
    }
}
