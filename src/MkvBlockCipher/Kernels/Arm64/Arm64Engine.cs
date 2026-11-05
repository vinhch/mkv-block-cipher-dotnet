using System.Runtime.Intrinsics.Arm;
using System.Security.Cryptography;
using MkvBlockCipher.Primitives;

namespace MkvBlockCipher.Kernels.Arm64;

// Full batches of 16 blocks run byte-sliced. A tail of TailBatchThreshold blocks or more runs as one padded batch;
// shorter tails run one block at a time.
internal sealed class Arm64Engine(MkvParameters parameters) : BlockEngine(parameters)
{
    // Every kernel looks up through AdvSimd table instructions, so the engine needs them.
    internal static bool IsSupported => AdvSimd.Arm64.IsSupported;

    // One block per byte lane of a Vector128.
    internal override int BatchBlocks => 16;

    // Tails of this many blocks or more run as one padded batch. Not measured on ARM64 hardware: a batch is
    // estimated to cost about 5.9 single blocks.
    internal const int TailBatchThreshold = 6;

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
