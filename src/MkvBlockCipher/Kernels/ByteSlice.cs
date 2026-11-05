using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;
using System.Security.Cryptography;

namespace MkvBlockCipher.Kernels;

// Converts between block-major bytes and byte-major lanes: byte p of block b sits at index p * lanes + b.
// Only public indices are used, so the copy never depends on the data.
internal static class ByteSlice
{
    internal static void Gather(ReadOnlySpan<byte> blocks, int blockBytes, Span<byte> sliced)
    {
        int lanes = blocks.Length / blockBytes;
        if (IsVectorShape(lanes, blockBytes, blocks.Length, sliced.Length))
        {
            Transpose(blocks, lanes, blockBytes, sliced);
        }
        else
        {
            GatherScalar(blocks, blockBytes, sliced);
        }
    }

    internal static void Scatter(ReadOnlySpan<byte> sliced, int blockBytes, Span<byte> blocks)
    {
        int lanes = blocks.Length / blockBytes;
        if (IsVectorShape(lanes, blockBytes, blocks.Length, sliced.Length))
        {
            Transpose(sliced, blockBytes, lanes, blocks);
        }
        else
        {
            ScatterScalar(sliced, blockBytes, blocks);
        }
    }

    // Scalar Gather. It handles every shape outside the vector path; tests compare the vector path against it.
    internal static void GatherScalar(ReadOnlySpan<byte> blocks, int blockBytes, Span<byte> sliced)
    {
        int lanes = blocks.Length / blockBytes;
        for (int lane = 0; lane < lanes; lane++)
        {
            for (int position = 0; position < blockBytes; position++)
            {
                sliced[position * lanes + lane] = blocks[lane * blockBytes + position];
            }
        }
    }

    // Scalar Scatter, the counterpart of GatherScalar.
    internal static void ScatterScalar(ReadOnlySpan<byte> sliced, int blockBytes, Span<byte> blocks)
    {
        int lanes = blocks.Length / blockBytes;
        for (int lane = 0; lane < lanes; lane++)
        {
            for (int position = 0; position < blockBytes; position++)
            {
                blocks[lane * blockBytes + position] = sliced[position * lanes + lane];
            }
        }
    }

    // Only whole 32-lane batches of 16 or 32 block bytes take the vector path, with spans of exactly that size.
    // Any other input keeps the scalar loops.
    private static bool IsVectorShape(int lanes, int blockBytes, int blocksLength, int slicedLength) =>
        Sse2.IsSupported
        && lanes == 32
        && (blockBytes == 16 || blockBytes == 32)
        && blocksLength == lanes * blockBytes
        && slicedLength == blocksLength;

    // Writes the transpose of a rows x cols byte matrix: destination[c * rows + r] = source[r * cols + c].
    // rows and cols are multiples of 16, so every tile is complete.
    private static void Transpose(ReadOnlySpan<byte> source, int rows, int cols, Span<byte> destination)
    {
        for (int row = 0; row < rows; row += 16)
        {
            for (int col = 0; col < cols; col += 16)
            {
                TransposeTile(source.Slice(row * cols + col), cols, destination.Slice(col * rows + row), rows);
            }
        }
    }

    // Transposes one 16 x 16 tile: row i is 16 bytes at source[i * sourceStride]. Four unpack stages, one per element
    // width (8, 16, 32, 64 bits). In a stage with distance d, slot i pairs with slot i + d inside each group of 2d
    // slots; the low and high interleaves go to slots 2i and 2i + 1 of that group. The shuffles depend only on position.
    private static void TransposeTile(
        ReadOnlySpan<byte> source, int sourceStride, Span<byte> destination, int destinationStride)
    {
        Span<Vector128<byte>> first = stackalloc Vector128<byte>[16];
        Span<Vector128<byte>> second = stackalloc Vector128<byte>[16];

        // IsVectorShape fixes both spans to whole 16-row tiles, so the unchecked accesses stay in bounds.
        for (int i = 0; i < 16; i++)
        {
            first[i] = Vector128.LoadUnsafe(ref MemoryMarshal.GetReference(source), (nuint)(i * sourceStride));
        }

        for (int pair = 0; pair < 16; pair += 2)
        {
            second[pair] = Sse2.UnpackLow(first[pair], first[pair + 1]);
            second[pair + 1] = Sse2.UnpackHigh(first[pair], first[pair + 1]);
        }

        for (int group = 0; group < 16; group += 4)
        {
            for (int i = 0; i < 2; i++)
            {
                Vector128<byte> x = second[group + i];
                Vector128<byte> y = second[group + i + 2];
                first[group + 2 * i] = Sse2.UnpackLow(x.AsUInt16(), y.AsUInt16()).AsByte();
                first[group + 2 * i + 1] = Sse2.UnpackHigh(x.AsUInt16(), y.AsUInt16()).AsByte();
            }
        }

        for (int group = 0; group < 16; group += 8)
        {
            for (int i = 0; i < 4; i++)
            {
                Vector128<byte> x = first[group + i];
                Vector128<byte> y = first[group + i + 4];
                second[group + 2 * i] = Sse2.UnpackLow(x.AsUInt32(), y.AsUInt32()).AsByte();
                second[group + 2 * i + 1] = Sse2.UnpackHigh(x.AsUInt32(), y.AsUInt32()).AsByte();
            }
        }

        for (int i = 0; i < 8; i++)
        {
            Vector128<byte> x = second[i];
            Vector128<byte> y = second[i + 8];
            first[2 * i] = Sse2.UnpackLow(x.AsUInt64(), y.AsUInt64()).AsByte();
            first[2 * i + 1] = Sse2.UnpackHigh(x.AsUInt64(), y.AsUInt64()).AsByte();
        }

        for (int i = 0; i < 16; i++)
        {
            first[i].StoreUnsafe(ref MemoryMarshal.GetReference(destination), (nuint)(i * destinationStride));
        }

        CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(first));
        CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(second));
    }
}
