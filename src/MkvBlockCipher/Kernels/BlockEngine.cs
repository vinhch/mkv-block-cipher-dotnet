using MkvBlockCipher.Primitives;

namespace MkvBlockCipher.Kernels;

// Round and batch kernels for one parameter set. The Require helpers enforce argument lengths and overlap.
internal abstract class BlockEngine(MkvParameters parameters)
{
    internal MkvParameters Parameters { get; } = parameters;

    // Blocks per batch-kernel pass. Modes size their scratch with it.
    internal abstract int BatchBlocks { get; }

    // Forward round F on one block, in place.
    internal abstract void Round(Span<byte> state, ReadOnlySpan<byte> k0, ReadOnlySpan<byte> k1);

    internal abstract void InverseRound(Span<byte> state, ReadOnlySpan<byte> k0, ReadOnlySpan<byte> k1);

    // Round keys hold RK[0..2R] back to back. Source and destination may start at the same offset.
    internal abstract void EncryptBlocks(ReadOnlySpan<byte> roundKeys, ReadOnlySpan<byte> source, Span<byte> destination);

    internal abstract void DecryptBlocks(ReadOnlySpan<byte> roundKeys, ReadOnlySpan<byte> source, Span<byte> destination);

    protected void RequireRound(ReadOnlySpan<byte> state, ReadOnlySpan<byte> k0, ReadOnlySpan<byte> k1)
    {
        RequireBlockLength(state.Length, nameof(state));
        RequireBlockLength(k0.Length, nameof(k0));
        RequireBlockLength(k1.Length, nameof(k1));
    }

    private void RequireBlockLength(int length, string paramName)
    {
        if (length != Parameters.BlockBytes)
        {
            throw new ArgumentException($"Expected {Parameters.BlockBytes} bytes.", paramName);
        }
    }

    protected void RequireBatch(ReadOnlySpan<byte> roundKeys, ReadOnlySpan<byte> source, ReadOnlySpan<byte> destination)
    {
        if (source.Length % Parameters.BlockBytes != 0)
        {
            throw new ArgumentException("Input is not a whole number of blocks.", nameof(source));
        }

        if (destination.Length != source.Length)
        {
            throw new ArgumentException("Output must be the same length as the input.", nameof(destination));
        }

        int roundKeyBlocks = 2 * Parameters.Rounds + 1;
        if (roundKeys.Length != roundKeyBlocks * Parameters.BlockBytes)
        {
            throw new ArgumentException($"Round keys must hold {roundKeyBlocks} blocks.", nameof(roundKeys));
        }

        // Partial overlap is rejected by contract: writing the output would overwrite part of the input.
        if (MemoryExtensions.Overlaps(source, destination, out int offset) && offset != 0)
        {
            throw new ArgumentException("Input and output partially overlap.", nameof(destination));
        }
    }
}
