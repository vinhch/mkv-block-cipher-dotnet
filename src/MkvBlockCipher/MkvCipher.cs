using System.Security.Cryptography;
using MkvBlockCipher.Kernels;
using MkvBlockCipher.Primitives;

namespace MkvBlockCipher;

/// <summary>
/// Keyed cipher for one 128-bit or 256-bit block per call. The key is expanded once in the constructor and not
/// kept. Concurrent calls to the block methods are safe after construction; Dispose must not overlap them.
/// </summary>
public sealed class MkvCipher : IDisposable
{
    // Pinned so the GC cannot compact the array and leave an unzeroed copy of the round keys behind.
    private readonly byte[] _roundKeys;
    private bool _disposed;

    /// <summary>Expands a key for one block size and revision. The key is read only during construction.</summary>
    /// <param name="blockSize">Block size of the cipher.</param>
    /// <param name="key">
    /// Key bytes. Mkv128 takes 16, 24 or 32 bytes; Mkv256 takes 32, 48 or 64 bytes.
    /// </param>
    /// <param name="revision">Round-count revision. Defaults to <see cref="MkvRevision.Rev2026"/>.</param>
    /// <param name="engine">Engine implementation. Defaults to <see cref="MkvEngine.ConstantTime"/>.</param>
    /// <exception cref="ArgumentException">The key length is not valid for <paramref name="blockSize"/>.</exception>
    /// <exception cref="ArgumentOutOfRangeException">An enum argument is not a defined value.</exception>
    public MkvCipher(
        MkvBlockSize blockSize,
        ReadOnlySpan<byte> key,
        MkvRevision revision = MkvRevision.Rev2026,
        MkvEngine engine = MkvEngine.ConstantTime)
    {
        MkvParameters parameters = MkvParameters.Create(blockSize, key.Length, revision, nameof(key));
        Engine = EngineFactory.Create(parameters, engine);
        BlockSizeBytes = parameters.BlockBytes;
        _roundKeys = GC.AllocateArray<byte>((2 * parameters.Rounds + 1) * parameters.BlockBytes, pinned: true);
        KeySchedule.Expand(Engine, key, _roundKeys);
    }

    /// <summary>Block length in bytes: 16 for Mkv128, 32 for Mkv256.</summary>
    public int BlockSizeBytes { get; }

    internal BlockEngine Engine { get; }

    // No disposal check: tests read the zeroed buffer after Dispose.
    internal ReadOnlySpan<byte> RoundKeys => _roundKeys;

    /// <summary>
    /// Encrypts exactly one block. Both spans must be <see cref="BlockSizeBytes"/> long. The spans may be the same
    /// span for in-place use; partial overlap is rejected.
    /// </summary>
    /// <param name="source">Plaintext block.</param>
    /// <param name="destination">Receives the ciphertext block.</param>
    /// <exception cref="ObjectDisposedException">The instance has been disposed.</exception>
    /// <exception cref="ArgumentException">A span has the wrong length, or the spans partially overlap.</exception>
    public void EncryptBlock(ReadOnlySpan<byte> source, Span<byte> destination)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        RequireBlockLengths(source, destination);
        Engine.EncryptBlocks(RoundKeys, source, destination);
    }

    /// <summary>
    /// Decrypts exactly one block. Both spans must be <see cref="BlockSizeBytes"/> long. The spans may be the same
    /// span for in-place use; partial overlap is rejected.
    /// </summary>
    /// <param name="source">Ciphertext block.</param>
    /// <param name="destination">Receives the plaintext block.</param>
    /// <exception cref="ObjectDisposedException">The instance has been disposed.</exception>
    /// <exception cref="ArgumentException">A span has the wrong length, or the spans partially overlap.</exception>
    public void DecryptBlock(ReadOnlySpan<byte> source, Span<byte> destination)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        RequireBlockLengths(source, destination);
        Engine.DecryptBlocks(RoundKeys, source, destination);
    }

    /// <summary>
    /// Zeroes the round keys. Block methods throw <see cref="ObjectDisposedException"/> afterwards. A second call does
    /// nothing.
    /// </summary>
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        CryptographicOperations.ZeroMemory(_roundKeys);
    }

    private void RequireBlockLengths(ReadOnlySpan<byte> source, Span<byte> destination)
    {
        if (source.Length != BlockSizeBytes)
        {
            throw new ArgumentException($"Expected {BlockSizeBytes} bytes.", nameof(source));
        }

        if (destination.Length != BlockSizeBytes)
        {
            throw new ArgumentException($"Expected {BlockSizeBytes} bytes.", nameof(destination));
        }
    }
}
