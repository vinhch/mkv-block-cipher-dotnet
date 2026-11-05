using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;
using System.Security.Cryptography;
using MkvBlockCipher.Primitives;

namespace MkvBlockCipher.Kernels.X64;

// Full batches of 64 blocks run byte-sliced in Vector512. Of the blocks left over, a run of TailBatchThreshold or more
// goes through one padded batch, and a shorter run goes one block at a time.
internal sealed class X64Avx512Engine(MkvParameters parameters) : BlockEngine(parameters)
{
    // Vector512.IsHardwareAccelerated is false where .NET does not prefer 512-bit vectors by default, and
    // DOTNET_PreferredVectorBitWidth=256 turns it off, so the 256-bit engines run instead.
    internal static bool IsSupported => Vector512.IsHardwareAccelerated && Avx512BW.IsSupported && Gfni.V512.IsSupported;

    // Unmeasured. One 64-block pass costs about as much as 64 / 3.3 = 19.4 single blocks, since a single block
    // runs about 3.3 times slower per byte.
    internal const int TailBatchThreshold = 20;

    // One block per byte lane of a Vector512.
    internal override int BatchBlocks => 64;

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
            BatchRounds512.Encrypt(
                Parameters, roundKeys, source.Slice(offset, batchBytes), destination.Slice(offset, batchBytes));
        }

        int tailBlocks = (destination.Length - offset) / blockBytes;
        if (tailBlocks >= TailBatchThreshold)
        {
            EncryptPaddedTail(roundKeys, source.Slice(offset), destination.Slice(offset));
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
            BatchRounds512.Decrypt(
                Parameters, roundKeys, source.Slice(offset, batchBytes), destination.Slice(offset, batchBytes));
        }

        int tailBlocks = (destination.Length - offset) / blockBytes;
        if (tailBlocks >= TailBatchThreshold)
        {
            DecryptPaddedTail(roundKeys, source.Slice(offset), destination.Slice(offset));
            return;
        }

        for (; offset < destination.Length; offset += blockBytes)
        {
            SingleBlockRounds.Decrypt(
                Parameters, roundKeys, source.Slice(offset, blockBytes), destination.Slice(offset, blockBytes));
        }
    }

    // Lanes past the tail hold zeros, since stackalloc clears them. Their output is never copied out.
    private void EncryptPaddedTail(ReadOnlySpan<byte> roundKeys, ReadOnlySpan<byte> source, Span<byte> destination)
    {
        Span<byte> batch = stackalloc byte[BatchBlocks * Parameters.BlockBytes];
        source.CopyTo(batch);
        BatchRounds512.Encrypt(Parameters, roundKeys, batch, batch);
        batch.Slice(0, destination.Length).CopyTo(destination);
        CryptographicOperations.ZeroMemory(batch);
    }

    // Lanes past the tail hold zeros, since stackalloc clears them. Their output is never copied out.
    private void DecryptPaddedTail(ReadOnlySpan<byte> roundKeys, ReadOnlySpan<byte> source, Span<byte> destination)
    {
        Span<byte> batch = stackalloc byte[BatchBlocks * Parameters.BlockBytes];
        source.CopyTo(batch);
        BatchRounds512.Decrypt(Parameters, roundKeys, batch, batch);
        batch.Slice(0, destination.Length).CopyTo(destination);
        CryptographicOperations.ZeroMemory(batch);
    }
}
