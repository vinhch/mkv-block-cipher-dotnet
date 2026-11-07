using System.Security.Cryptography;
using MkvBlockCipher.Kernels;
using MkvBlockCipher.Primitives;

namespace MkvBlockCipher.Tests.Modes;

// Raw AES as a block engine: the round keys argument is the AES key itself, so the core modes can be checked
// against published AES vectors and the BCL.
internal sealed class AesTestEngine() : BlockEngine(MkvParameters.Create(MkvBlockSize.Mkv128, 16, MkvRevision.Rev2025))
{
    internal override int BatchBlocks => 4;

    internal override void Round(Span<byte> state, ReadOnlySpan<byte> k0, ReadOnlySpan<byte> k1) =>
        throw new NotSupportedException("AesTestEngine has no round function.");

    internal override void InverseRound(Span<byte> state, ReadOnlySpan<byte> k0, ReadOnlySpan<byte> k1) =>
        throw new NotSupportedException("AesTestEngine has no round function.");

    internal override void EncryptBlocks(ReadOnlySpan<byte> roundKeys, ReadOnlySpan<byte> source, Span<byte> destination)
    {
        // Copied first: BlockEngine allows source and destination to share a start.
        byte[] input = source.ToArray();
        using Aes aes = CreateAes(roundKeys);
        aes.EncryptEcb(input, destination, PaddingMode.None);
    }

    internal override void DecryptBlocks(ReadOnlySpan<byte> roundKeys, ReadOnlySpan<byte> source, Span<byte> destination)
    {
        byte[] input = source.ToArray();
        using Aes aes = CreateAes(roundKeys);
        aes.DecryptEcb(input, destination, PaddingMode.None);
    }

    private static Aes CreateAes(ReadOnlySpan<byte> key)
    {
        Aes aes = Aes.Create();
        aes.Key = key.ToArray();
        return aes;
    }
}
