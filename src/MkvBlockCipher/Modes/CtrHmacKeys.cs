using System.Security.Cryptography;
using System.Text;

namespace MkvBlockCipher.Modes;

// Key derivation and length rules for the authenticated mode.
internal static class CtrHmacKeys
{
    internal const int KeyBytes = 32;
    internal const int MacKeyBytes = 32;

    // The block counter is 32 bits and starts at 1, so one nonce covers at most 2^32 - 1 blocks.
    private const long MaxBlocks = uint.MaxValue;

    internal static int BlockBytes(MkvBlockSize blockSize) => blockSize switch
    {
        MkvBlockSize.Mkv128 => 16,
        MkvBlockSize.Mkv256 => 32,
        _ => throw new ArgumentOutOfRangeException(nameof(blockSize)),
    };

    // Longest key the block size accepts, which selects its highest round count.
    internal static int EncKeyBytes(int blockBytes) => 2 * blockBytes;

    // The info string binds each key to its purpose, block size and revision.
    internal static void Derive(
        ReadOnlySpan<byte> key,
        string purpose,
        int blockBytes,
        MkvRevision revision,
        Span<byte> output)
    {
        int year = revision switch
        {
            MkvRevision.Rev2024 => 2024,
            MkvRevision.Rev2026 => 2026,
            _ => throw new ArgumentOutOfRangeException(nameof(revision)),
        };
        byte[] info = Encoding.ASCII.GetBytes($"MkvBlockCipher/CtrHmac/v1/{purpose}/{blockBytes * 8}/{year}");
        HKDF.DeriveKey(HashAlgorithmName.SHA256, key, output, ReadOnlySpan<byte>.Empty, info);
    }

    internal static void ThrowIfTooLong(long plaintextBytes, int blockBytes)
    {
        if (plaintextBytes > MaxBlocks * blockBytes)
        {
            throw new ArgumentException("The message is too long for one nonce.");
        }
    }
}
