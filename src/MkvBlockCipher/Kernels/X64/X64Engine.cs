using System.Runtime.Intrinsics.X86;
using System.Security.Cryptography;
using MkvBlockCipher.Primitives;

namespace MkvBlockCipher.Kernels.X64;

// Full batches of 32 blocks run byte-sliced; the remaining blocks of a call run one at a time.
internal sealed class X64Engine(MkvParameters parameters) : BlockEngine(parameters)
{
    // Every kernel shuffles with SSSE3 instructions, so the engine needs them.
    internal static bool IsSupported => Ssse3.IsSupported;

    // One block per byte lane of a Vector256.
    internal override int BatchBlocks => 32;

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

        for (; offset < destination.Length; offset += blockBytes)
        {
            SingleBlockRounds.Encrypt(
                Parameters, roundKeys, source.Slice(offset, blockBytes), destination.Slice(offset, blockBytes));
        }
    }

    // A full batch with a block-sized counter is built in sliced form. Any other call keeps the default path.
    internal override void EncryptCounters(
        ReadOnlySpan<byte> roundKeys, ReadOnlySpan<byte> initialCounter, long firstIndex, Span<byte> keystream)
    {
        int blockBytes = Parameters.BlockBytes;
        if (keystream.Length != BatchBlocks * blockBytes || initialCounter.Length != blockBytes)
        {
            base.EncryptCounters(roundKeys, initialCounter, firstIndex, keystream);
            return;
        }

        RequireBatch(roundKeys, keystream, keystream);
        Span<byte> sliced = stackalloc byte[keystream.Length];
        SlicedCounters.Fill(initialCounter, firstIndex, BatchBlocks, sliced);
        BatchRounds.EncryptSliced(Parameters, roundKeys, sliced, keystream);
        CryptographicOperations.ZeroMemory(sliced);
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

        for (; offset < destination.Length; offset += blockBytes)
        {
            SingleBlockRounds.Decrypt(
                Parameters, roundKeys, source.Slice(offset, blockBytes), destination.Slice(offset, blockBytes));
        }
    }
}
