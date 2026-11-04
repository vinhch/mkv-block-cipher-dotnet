using System.Diagnostics;
using System.Runtime.Intrinsics;
using MkvBlockCipher.Primitives;

namespace MkvBlockCipher.Kernels;

// Lane masks for the single-block SIMD kernels, built once per word size and rotation step. A block is held in
// 16-byte chunks: lane i of chunk k holds block byte 16 * k + i, which is position i mod wordBytes of word
// (16 * k + i) / wordBytes. Each mask is indexed by chunk * wordBytes + column (or row).
internal sealed class SingleBlockMasks
{
    private const int ChunkBytes = 16;

    private static readonly SingleBlockMasks Unrotated4 = new(4, 0);
    private static readonly SingleBlockMasks Rotated4 = new(4, 1);
    private static readonly SingleBlockMasks Unrotated8 = new(8, 0);
    private static readonly SingleBlockMasks Rotated8 = new(8, 2);

    private SingleBlockMasks(int wordBytes, int stepBytes)
    {
        WordBytes = wordBytes;
        int chunks = 4 * wordBytes / ChunkBytes;
        ForwardColumns = ColumnMasks(wordBytes, chunks, stepBytes);
        InverseColumns = ColumnMasks(wordBytes, chunks, 0);
        ForwardRows = RowMasks(wordBytes, chunks, 0);
        InverseRows = RowMasks(wordBytes, chunks, stepBytes);
    }

    internal int WordBytes { get; }

    // Forward reads word byte (column + w * step) mod wordBytes; inverse reads the unrotated byte, because the
    // inverse rotation is applied to its output.
    internal readonly Vector128<byte>[] ForwardColumns;
    internal readonly Vector128<byte>[] InverseColumns;

    // Forward keeps each lane's own output row. Inverse keeps the row that the output rotation moves onto the lane.
    internal readonly Vector128<byte>[] ForwardRows;
    internal readonly Vector128<byte>[] InverseRows;

    // Step 0 for revisions without rotation, wordBytes / 4 for Rev2025 (see MkvParameters.Create).
    internal static SingleBlockMasks For(MkvParameters parameters) =>
        (parameters.WordBytes, parameters.RotationStepBytes) switch
        {
            (4, 0) => Unrotated4,
            (4, 1) => Rotated4,
            (8, 0) => Unrotated8,
            (8, 2) => Rotated8,
            _ => throw new UnreachableException("No masks for this word size and rotation step."),
        };

    private static Vector128<byte>[] ColumnMasks(int wordBytes, int chunks, int stepBytes)
    {
        Vector128<byte>[] masks = new Vector128<byte>[chunks * wordBytes];
        Span<byte> lanes = stackalloc byte[ChunkBytes];
        for (int chunk = 0; chunk < chunks; chunk++)
        {
            for (int column = 0; column < wordBytes; column++)
            {
                for (int lane = 0; lane < ChunkBytes; lane++)
                {
                    int word = (ChunkBytes * chunk + lane) / wordBytes;
                    int wordStart = lane - lane % wordBytes;
                    lanes[lane] = (byte)(wordStart + (column + word * stepBytes) % wordBytes);
                }

                masks[chunk * wordBytes + column] = Vector128.Create((ReadOnlySpan<byte>)lanes);
            }
        }

        return masks;
    }

    // Lane i keeps output row r when row r lands on the lane's position:
    // (r + w * stepBytes) mod wordBytes = i mod wordBytes.
    private static Vector128<byte>[] RowMasks(int wordBytes, int chunks, int stepBytes)
    {
        Vector128<byte>[] masks = new Vector128<byte>[chunks * wordBytes];
        Span<byte> lanes = stackalloc byte[ChunkBytes];
        for (int chunk = 0; chunk < chunks; chunk++)
        {
            for (int row = 0; row < wordBytes; row++)
            {
                for (int lane = 0; lane < ChunkBytes; lane++)
                {
                    int word = (ChunkBytes * chunk + lane) / wordBytes;
                    bool keeps = (row + word * stepBytes) % wordBytes == lane % wordBytes;
                    lanes[lane] = keeps ? (byte)0xFF : (byte)0;
                }

                masks[chunk * wordBytes + row] = Vector128.Create((ReadOnlySpan<byte>)lanes);
            }
        }

        return masks;
    }
}
