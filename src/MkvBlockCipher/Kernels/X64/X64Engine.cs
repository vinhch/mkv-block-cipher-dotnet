using System.Runtime.Intrinsics.X86;
using System.Security.Cryptography;
using MkvBlockCipher.Primitives;

namespace MkvBlockCipher.Kernels.X64;

// Full batches of 32 blocks run byte-sliced. A tail of TailBatchThreshold blocks or more runs as one padded batch;
// shorter tails run one block at a time.
internal sealed class X64Engine(MkvParameters parameters) : BlockEngine(parameters)
{
    // Every kernel shuffles with SSSE3 instructions, so the engine needs them.
    internal static bool IsSupported => Ssse3.IsSupported;

    // One block per byte lane of a Vector256.
    internal override int BatchBlocks => 32;

    // Tails of this many blocks or more run as one padded batch. On Mkv128 a batch costs about 7.8 single blocks.
    internal const int TailBatchThreshold = 8;

    internal override void Round(Span<byte> state, ReadOnlySpan<byte> k0, ReadOnlySpan<byte> k1)
    {
        RequireRound(state, k0, k1);
        SingleBlockRounds.Forward(Parameters, state, k0, k1);
    }

    internal override void InverseRound(Span<byte> state, ReadOnlySpan<byte> k0, ReadOnlySpan<byte> k1)
    {
        RequireRound(state, k0, k1);
        SingleBlockRounds.Inverse(Parameters, state, k0, k1);
    }

    internal override void EncryptBlocks(ReadOnlySpan<byte> roundKeys, ReadOnlySpan<byte> source, Span<byte> destination)
    {
        RequireBatch(roundKeys, source, destination);
        int blockBytes = Parameters.BlockBytes;
        int batchBytes = BatchBlocks * blockBytes;
        int offset = 0;
        for (; destination.Length - offset >= batchBytes; offset += batchBytes)
        {
            BatchRounds.Encrypt(
                Parameters, roundKeys, source.Slice(offset, batchBytes), destination.Slice(offset, batchBytes));
        }

        int tailBytes = destination.Length - offset;
        if (tailBytes >= TailBatchThreshold * blockBytes)
        {
            EncryptTailAsBatch(roundKeys, source.Slice(offset), destination.Slice(offset));
            return;
        }

        for (; offset < destination.Length; offset += blockBytes)
        {
            SingleBlockRounds.Encrypt(
                Parameters, roundKeys, source.Slice(offset, blockBytes), destination.Slice(offset, blockBytes));
        }
    }

    internal override void DecryptBlocks(ReadOnlySpan<byte> roundKeys, ReadOnlySpan<byte> source, Span<byte> destination)
    {
        RequireBatch(roundKeys, source, destination);
        int blockBytes = Parameters.BlockBytes;
        int batchBytes = BatchBlocks * blockBytes;
        int offset = 0;
        for (; destination.Length - offset >= batchBytes; offset += batchBytes)
        {
            BatchRounds.Decrypt(
                Parameters, roundKeys, source.Slice(offset, batchBytes), destination.Slice(offset, batchBytes));
        }

        int tailBytes = destination.Length - offset;
        if (tailBytes >= TailBatchThreshold * blockBytes)
        {
            DecryptTailAsBatch(roundKeys, source.Slice(offset), destination.Slice(offset));
            return;
        }

        for (; offset < destination.Length; offset += blockBytes)
        {
            SingleBlockRounds.Decrypt(
                Parameters, roundKeys, source.Slice(offset, blockBytes), destination.Slice(offset, blockBytes));
        }
    }

    // The tail fills one zeroed batch and the padding lanes are discarded. BatchRounds reads all its input before it
    // writes, so the batch serves as both input and output.
    private void EncryptTailAsBatch(ReadOnlySpan<byte> roundKeys, ReadOnlySpan<byte> source, Span<byte> destination)
    {
        Span<byte> batch = stackalloc byte[BatchBlocks * Parameters.BlockBytes];
        source.CopyTo(batch);
        BatchRounds.Encrypt(Parameters, roundKeys, batch, batch);
        batch.Slice(0, destination.Length).CopyTo(destination);
        CryptographicOperations.ZeroMemory(batch);
    }

    private void DecryptTailAsBatch(ReadOnlySpan<byte> roundKeys, ReadOnlySpan<byte> source, Span<byte> destination)
    {
        Span<byte> batch = stackalloc byte[BatchBlocks * Parameters.BlockBytes];
        source.CopyTo(batch);
        BatchRounds.Decrypt(Parameters, roundKeys, batch, batch);
        batch.Slice(0, destination.Length).CopyTo(destination);
        CryptographicOperations.ZeroMemory(batch);
    }
}
