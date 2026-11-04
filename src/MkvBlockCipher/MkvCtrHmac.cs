using System.Buffers.Binary;
using System.Security.Cryptography;
using MkvBlockCipher.Modes;

namespace MkvBlockCipher;

/// <summary>
/// Authenticated encryption: CTR with the block cipher keystream, then HMAC-SHA256 over the associated data, nonce,
/// ciphertext and both lengths (encrypt-then-MAC). The 32-byte key is read only during construction. Decrypt verifies
/// the tag before it decrypts anything.
/// </summary>
/// <remarks>
/// Not thread-safe: the instance holds one reusable <see cref="IncrementalHash"/>. Callers must not overlap calls,
/// and Dispose must not overlap them either.
/// </remarks>
public sealed class MkvCtrHmac : IDisposable
{
    /// <summary>Tag length in bytes: the HMAC-SHA256 output.</summary>
    public const int TagSizeBytes = 32;

    // The block counter fills the last four bytes of the counter block.
    private const int CounterBytes = 4;

    private const uint FirstCounter = 1;

    private readonly int _blockBytes;
    private readonly MkvCipher _cipher;
    private readonly IncrementalHash _mac;
    private bool _disposed;

    /// <summary>Derives the cipher and MAC keys from <paramref name="key"/>.</summary>
    /// <param name="blockSize">Block size of the underlying cipher.</param>
    /// <param name="key">Exactly 32 bytes. The key is read only during construction.</param>
    /// <param name="revision">Round-count revision. Defaults to <see cref="MkvRevision.Rev2026"/>.</param>
    /// <param name="engine">Engine implementation. Defaults to <see cref="MkvEngine.ConstantTime"/>.</param>
    /// <exception cref="ArgumentException"><paramref name="key"/> is not 32 bytes.</exception>
    /// <exception cref="ArgumentOutOfRangeException">An enum argument is not a defined value.</exception>
    public MkvCtrHmac(
        MkvBlockSize blockSize,
        ReadOnlySpan<byte> key,
        MkvRevision revision = MkvRevision.Rev2026,
        MkvEngine engine = MkvEngine.ConstantTime)
    {
        RequireLength(key, CtrHmacKeys.KeyBytes, nameof(key));
        _blockBytes = CtrHmacKeys.BlockBytes(blockSize);

        // The derived keys are secret, so they are zeroed on every path. The cipher and the MAC state keep their own copies.
        byte[] encKey = new byte[CtrHmacKeys.EncKeyBytes(_blockBytes)];
        byte[] macKey = new byte[CtrHmacKeys.MacKeyBytes];
        try
        {
            CtrHmacKeys.Derive(key, "enc", _blockBytes, revision, encKey);
            CtrHmacKeys.Derive(key, "mac", _blockBytes, revision, macKey);
            _cipher = new MkvCipher(blockSize, encKey, revision, engine);
            _mac = IncrementalHash.CreateHMAC(HashAlgorithmName.SHA256, macKey);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(encKey);
            CryptographicOperations.ZeroMemory(macKey);
        }
    }

    /// <summary>Nonce length in bytes: the block size minus the 4-byte block counter.</summary>
    public int NonceSizeBytes => _blockBytes - CounterBytes;

    /// <summary>
    /// Encrypts <paramref name="plaintext"/> into <paramref name="ciphertext"/> and writes the tag. A nonce must not be
    /// reused with the same key.
    /// </summary>
    /// <param name="nonce"><see cref="NonceSizeBytes"/> bytes.</param>
    /// <param name="plaintext">Data to encrypt. Any length, including zero.</param>
    /// <param name="ciphertext">
    /// Receives the ciphertext, the same length as <paramref name="plaintext"/>. May be the same span for in-place use.
    /// </param>
    /// <param name="tag"><see cref="TagSizeBytes"/> bytes. Receives the tag.</param>
    /// <param name="associatedData">Data to authenticate without encrypting. Any length, including zero.</param>
    /// <exception cref="ObjectDisposedException">The instance has been disposed.</exception>
    /// <exception cref="ArgumentException">
    /// A length is wrong, the message needs more than 2^32 - 1 blocks, or an output overlaps an input other than
    /// <paramref name="plaintext"/> and <paramref name="ciphertext"/> in place. Nothing is written in these cases.
    /// </exception>
    public void Encrypt(
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> plaintext,
        Span<byte> ciphertext,
        Span<byte> tag,
        ReadOnlySpan<byte> associatedData = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        RequireLength(nonce, NonceSizeBytes, nameof(nonce));
        RequireLength(ciphertext, plaintext.Length, nameof(ciphertext));
        RequireLength(tag, TagSizeBytes, nameof(tag));
        CtrHmacKeys.ThrowIfTooLong(plaintext.Length, _blockBytes);
        BufferChecks.ThrowIfPartialOverlap(plaintext, ciphertext, nameof(ciphertext));
        RequireDisjoint(ciphertext, nonce, nameof(ciphertext));
        RequireDisjoint(ciphertext, associatedData, nameof(ciphertext));
        RequireDisjoint(tag, plaintext, nameof(tag));
        RequireDisjoint(tag, ciphertext, nameof(tag));
        RequireDisjoint(tag, nonce, nameof(tag));
        RequireDisjoint(tag, associatedData, nameof(tag));

        Span<byte> counter = stackalloc byte[_blockBytes];
        FillInitialCounter(nonce, counter);
        _cipher.TransformCtr(counter, plaintext, ciphertext);
        ComputeTag(associatedData, nonce, ciphertext, tag);
    }

    /// <summary>
    /// Verifies the tag, then decrypts. Nothing is decrypted unless the tag matches. A mismatch zeroes
    /// <paramref name="plaintext"/> before it throws.
    /// </summary>
    /// <param name="nonce"><see cref="NonceSizeBytes"/> bytes, the nonce used to encrypt.</param>
    /// <param name="ciphertext">Data to decrypt. Any length, including zero.</param>
    /// <param name="tag"><see cref="TagSizeBytes"/> bytes, the tag from encryption.</param>
    /// <param name="plaintext">
    /// Receives the plaintext, the same length as <paramref name="ciphertext"/>. May be the same span for in-place use.
    /// On a tag mismatch this span is zeroed, which also clears the ciphertext when the two are the same span.
    /// </param>
    /// <param name="associatedData">The associated data used to encrypt. Any length, including zero.</param>
    /// <exception cref="ObjectDisposedException">The instance has been disposed.</exception>
    /// <exception cref="ArgumentException">
    /// A length is wrong, the message needs more than 2^32 - 1 blocks, or an output overlaps an input other than
    /// <paramref name="plaintext"/> and <paramref name="ciphertext"/> in place.
    /// </exception>
    /// <exception cref="CryptographicException">The tag does not match. The message is the generic decrypt failure.</exception>
    public void Decrypt(
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> ciphertext,
        ReadOnlySpan<byte> tag,
        Span<byte> plaintext,
        ReadOnlySpan<byte> associatedData = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        RequireLength(nonce, NonceSizeBytes, nameof(nonce));
        RequireLength(tag, TagSizeBytes, nameof(tag));
        RequireLength(plaintext, ciphertext.Length, nameof(plaintext));
        CtrHmacKeys.ThrowIfTooLong(ciphertext.Length, _blockBytes);
        BufferChecks.ThrowIfPartialOverlap(ciphertext, plaintext, nameof(plaintext));
        RequireDisjoint(plaintext, nonce, nameof(plaintext));
        RequireDisjoint(plaintext, tag, nameof(plaintext));
        RequireDisjoint(plaintext, associatedData, nameof(plaintext));

        Span<byte> expectedTag = stackalloc byte[TagSizeBytes];
        ComputeTag(associatedData, nonce, ciphertext, expectedTag);
        bool tagMatches = CryptographicOperations.FixedTimeEquals(expectedTag, tag);
        CryptographicOperations.ZeroMemory(expectedTag);
        if (!tagMatches)
        {
            CryptographicOperations.ZeroMemory(plaintext);
            throw new CryptographicException(DecryptFailure.Message);
        }

        Span<byte> counter = stackalloc byte[_blockBytes];
        FillInitialCounter(nonce, counter);
        _cipher.TransformCtr(counter, ciphertext, plaintext);
    }

    /// <summary>
    /// Releases the cipher, which zeroes its round keys, and the MAC state. Later calls throw
    /// <see cref="ObjectDisposedException"/>. A second call does nothing.
    /// </summary>
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        _cipher.Dispose();
        _mac.Dispose();
    }

    // Counter block = nonce || big-endian counter, starting at FirstCounter.
    private static void FillInitialCounter(ReadOnlySpan<byte> nonce, Span<byte> counter)
    {
        nonce.CopyTo(counter);
        BinaryPrimitives.WriteUInt32BigEndian(counter[nonce.Length..], FirstCounter);
    }

    // Fixed-width length fields keep the boundaries between the hashed fields unambiguous.
    private void ComputeTag(
        ReadOnlySpan<byte> associatedData,
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> ciphertext,
        Span<byte> tag)
    {
        _mac.AppendData(associatedData);
        _mac.AppendData(nonce);
        _mac.AppendData(ciphertext);
        Span<byte> lengths = stackalloc byte[2 * sizeof(ulong)];
        BinaryPrimitives.WriteUInt64LittleEndian(lengths, (ulong)associatedData.Length);
        BinaryPrimitives.WriteUInt64LittleEndian(lengths[sizeof(ulong)..], (ulong)ciphertext.Length);
        _mac.AppendData(lengths);
        _mac.GetHashAndReset(tag);
    }

    // Encrypt writes the ciphertext before it reads the associated data, so any alias would corrupt the tag.
    private static void RequireDisjoint(ReadOnlySpan<byte> output, ReadOnlySpan<byte> input, string paramName)
    {
        if (MemoryExtensions.Overlaps(output, input))
        {
            throw new ArgumentException("Output overlaps an input.", paramName);
        }
    }

    private static void RequireLength(ReadOnlySpan<byte> value, int expected, string paramName)
    {
        if (value.Length != expected)
        {
            throw new ArgumentException($"Expected {expected} bytes.", paramName);
        }
    }
}
