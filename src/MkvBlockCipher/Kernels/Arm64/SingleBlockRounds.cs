using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.Arm;
using System.Security.Cryptography;
using MkvBlockCipher.Primitives;

namespace MkvBlockCipher.Kernels.Arm64;

// One block held in 128-bit chunks. A chunk holds 16 / wordBytes whole words, so MixWords never crosses a chunk.
// XWords crosses chunks only in its final combination.
// The stack copy is cleared; register values are not.
internal static class SingleBlockRounds
{
    private const int ChunkBytes = 16;

    private static readonly Vector128<byte> LaneIndex =
        Vector128.Create((byte)0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);

    internal static void Forward(MkvParameters parameters, Span<byte> block, ReadOnlySpan<byte> k0, ReadOnlySpan<byte> k1)
    {
        Span<Vector128<byte>> chunks = stackalloc Vector128<byte>[parameters.BlockBytes / ChunkBytes];
        Load(block, chunks);
        ForwardRound(chunks, SingleBlockMasks.For(parameters), k0, k1);
        Store(chunks, block);
        CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(chunks));
    }

    internal static void Inverse(MkvParameters parameters, Span<byte> block, ReadOnlySpan<byte> k0, ReadOnlySpan<byte> k1)
    {
        Span<Vector128<byte>> chunks = stackalloc Vector128<byte>[parameters.BlockBytes / ChunkBytes];
        Load(block, chunks);
        InvertRound(chunks, SingleBlockMasks.For(parameters), k0, k1);
        Store(chunks, block);
        CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(chunks));
    }

    internal static void Encrypt(
        MkvParameters parameters, ReadOnlySpan<byte> roundKeys, ReadOnlySpan<byte> source, Span<byte> destination)
    {
        int blockBytes = parameters.BlockBytes;
        SingleBlockMasks masks = SingleBlockMasks.For(parameters);
        Span<Vector128<byte>> chunks = stackalloc Vector128<byte>[blockBytes / ChunkBytes];
        Load(source, chunks);
        for (int round = 0; round < parameters.Rounds; round++)
        {
            ForwardRound(
                chunks,
                masks,
                RoundKey(roundKeys, blockBytes, 2 * round),
                RoundKey(roundKeys, blockBytes, 2 * round + 1));
        }

        AddRoundKey(chunks, RoundKey(roundKeys, blockBytes, 2 * parameters.Rounds));
        Store(chunks, destination);
        CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(chunks));
    }

    internal static void Decrypt(
        MkvParameters parameters, ReadOnlySpan<byte> roundKeys, ReadOnlySpan<byte> source, Span<byte> destination)
    {
        int blockBytes = parameters.BlockBytes;
        SingleBlockMasks masks = SingleBlockMasks.For(parameters);
        Span<Vector128<byte>> chunks = stackalloc Vector128<byte>[blockBytes / ChunkBytes];
        Load(source, chunks);
        AddRoundKey(chunks, RoundKey(roundKeys, blockBytes, 2 * parameters.Rounds));
        for (int round = parameters.Rounds - 1; round >= 0; round--)
        {
            InvertRound(
                chunks,
                masks,
                RoundKey(roundKeys, blockBytes, 2 * round),
                RoundKey(roundKeys, blockBytes, 2 * round + 1));
        }

        Store(chunks, destination);
        CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(chunks));
    }

    private static void ForwardRound(
        Span<Vector128<byte>> chunks, SingleBlockMasks masks, ReadOnlySpan<byte> k0, ReadOnlySpan<byte> k1)
    {
        int wordBytes = masks.WordBytes;
        AddRoundKey(chunks, k0);
        SubCells(chunks, SBoxTables.Forward);
        MixWords(
            chunks,
            wordBytes,
            wordBytes == 4 ? MixMatrices.M4 : MixMatrices.M8,
            masks.ForwardColumns,
            masks.ForwardRows);
        AddRoundKey(chunks, k1);
        SubCells(chunks, SBoxTables.Forward);
        XWords(chunks, wordBytes);
    }

    private static void InvertRound(
        Span<Vector128<byte>> chunks, SingleBlockMasks masks, ReadOnlySpan<byte> k0, ReadOnlySpan<byte> k1)
    {
        int wordBytes = masks.WordBytes;
        XWords(chunks, wordBytes);
        SubCells(chunks, SBoxTables.Inverse);
        AddRoundKey(chunks, k1);
        MixWords(
            chunks,
            wordBytes,
            wordBytes == 4 ? MixMatrices.M4Inverse : MixMatrices.M8Inverse,
            masks.InverseColumns,
            masks.InverseRows);
        SubCells(chunks, SBoxTables.Inverse);
        AddRoundKey(chunks, k0);
    }

    private static void AddRoundKey(Span<Vector128<byte>> chunks, ReadOnlySpan<byte> roundKey)
    {
        for (int chunk = 0; chunk < chunks.Length; chunk++)
        {
            chunks[chunk] ^= Vector128.Create(roundKey.Slice(ChunkBytes * chunk, ChunkBytes));
        }
    }

    private static void SubCells(Span<Vector128<byte>> chunks, ReadOnlySpan<byte> table)
    {
        for (int chunk = 0; chunk < chunks.Length; chunk++)
        {
            chunks[chunk] = SBoxTableLookup.Lookup(chunks[chunk], table);
        }
    }

    // Each column holds one word byte copied into every lane of its word, so all rows reuse it. The rotation sits in
    // the masks: the column lookup for the forward mix, the row select for the inverse.
    private static void MixWords(
        Span<Vector128<byte>> chunks,
        int wordBytes,
        ReadOnlySpan<byte> matrix,
        Vector128<byte>[] columnMasks,
        Vector128<byte>[] rowMasks)
    {
        Span<Vector128<byte>> columns = stackalloc Vector128<byte>[wordBytes];
        for (int chunk = 0; chunk < chunks.Length; chunk++)
        {
            for (int column = 0; column < wordBytes; column++)
            {
                columns[column] = AdvSimd.Arm64.VectorTableLookup(
                    chunks[chunk], columnMasks[chunk * wordBytes + column]);
            }

            Vector128<byte> mixed = Vector128<byte>.Zero;
            for (int row = 0; row < wordBytes; row++)
            {
                Vector128<byte> sum = Vector128<byte>.Zero;
                for (int column = 0; column < wordBytes; column++)
                {
                    sum ^= GfMultiply.Multiply(columns[column], matrix[row * wordBytes + column]);
                }

                mixed |= sum & rowMasks[chunk * wordBytes + row];
            }

            chunks[chunk] = mixed;
        }

        CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(columns));
    }

    // Each byte column XORs across the words of the block, and every word takes that total.
    private static void XWords(Span<Vector128<byte>> chunks, int wordBytes)
    {
        Vector128<byte> total = Vector128<byte>.Zero;
        for (int chunk = 0; chunk < chunks.Length; chunk++)
        {
            total ^= ChunkColumnSums(chunks[chunk], wordBytes);
        }

        for (int chunk = 0; chunk < chunks.Length; chunk++)
        {
            chunks[chunk] ^= total;
        }
    }

    // Lane i ends up holding the XOR of the chunk's bytes at lanes i + k * wordBytes (mod 16), one for each word.
    // Each step folds in the lanes shifted by its amount, and the doubling shifts reach every word.
    private static Vector128<byte> ChunkColumnSums(Vector128<byte> chunk, int wordBytes)
    {
        Vector128<byte> sums = chunk;
        for (int shift = wordBytes; shift < ChunkBytes; shift *= 2)
        {
            Vector128<byte> fromLane = LaneIndex + Vector128.Create((byte)shift);
            sums ^= AdvSimd.Arm64.VectorTableLookup(sums, fromLane & Vector128.Create((byte)(ChunkBytes - 1)));
        }

        return sums;
    }

    private static void Load(ReadOnlySpan<byte> block, Span<Vector128<byte>> chunks)
    {
        for (int chunk = 0; chunk < chunks.Length; chunk++)
        {
            chunks[chunk] = Vector128.Create(block.Slice(ChunkBytes * chunk, ChunkBytes));
        }
    }

    private static void Store(Span<Vector128<byte>> chunks, Span<byte> block)
    {
        for (int chunk = 0; chunk < chunks.Length; chunk++)
        {
            chunks[chunk].CopyTo(block.Slice(ChunkBytes * chunk, ChunkBytes));
        }
    }

    private static ReadOnlySpan<byte> RoundKey(ReadOnlySpan<byte> roundKeys, int blockBytes, int index) =>
        roundKeys.Slice(index * blockBytes, blockBytes);
}
