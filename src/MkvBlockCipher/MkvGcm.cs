using System.Buffers.Binary;
using System.Security.Cryptography;
using MkvBlockCipher.Modes;

namespace MkvBlockCipher;

/// <summary>
/// Authenticated encryption: GCM (SP 800-38D) over the MKV 128-bit block cipher, with a 12-byte nonce and a tag of 12 to 16
/// bytes. The key is read only during construction. Decrypt verifies the tag before it decrypts anything.
/// </summary>
/// <remarks>
/// Never reuse a nonce with the same key: a reused nonce reveals the XOR of two plaintexts and lets an attacker forge tags.
/// With random 96-bit nonces, keep the number of messages per key below 2^32. A truncated tag gives weaker forgery
/// resistance; prefer 16 bytes unless the format requires less. Concurrent Encrypt and Decrypt calls are safe after
/// construction; Dispose must not overlap them.
/// </remarks>
public sealed class MkvGcm : IDisposable
{
    private const int BlockBytes = 16;
    private const int NonceBytes = 12;

    /// <summary>Nonce lengths in bytes: exactly 12.</summary>
    public static KeySizes NonceByteSizes { get; } = new(NonceBytes, NonceBytes, 0);

    /// <summary>Tag lengths in bytes: 12 to 16.</summary>
    public static KeySizes TagByteSizes { get; } = new(12, 16, 1);

    /// <summary>Bytes of the nonce that a STREAM segment takes from the caller: the rest is the index and the last flag.</summary>
    public const int StreamNoncePrefixBytes = 7;

    private readonly MkvCipher _cipher;

    // Pinned so the GC cannot leave an unzeroed copy of H behind.
    private readonly byte[] _h;
    private bool _disposed;

    /// <summary>Derives the GHASH key from <paramref name="key"/>. The key is read only during construction.</summary>
    /// <param name="key">16, 24 or 32 bytes (MKV-128).</param>
    /// <param name="tagSizeInBytes">Tag length in bytes: 12 to 16.</param>
    /// <param name="revision">Algorithm revision. Defaults to <see cref="MkvRevision.Rev2025"/>.</param>
    /// <param name="engine">Engine implementation. Defaults to <see cref="MkvEngine.ConstantTime"/>.</param>
    /// <exception cref="ArgumentException"><paramref name="key"/> is not a valid MKV-128 key length.</exception>
    /// <exception cref="ArgumentOutOfRangeException">
    /// <paramref name="tagSizeInBytes"/> is outside 12 to 16, or an enum argument is not a defined value.
    /// </exception>
    public MkvGcm(
        ReadOnlySpan<byte> key,
        int tagSizeInBytes,
        MkvRevision revision = MkvRevision.Rev2025,
        MkvEngine engine = MkvEngine.ConstantTime)
    {
        if (tagSizeInBytes < TagByteSizes.MinSize || tagSizeInBytes > TagByteSizes.MaxSize)
        {
            throw new ArgumentOutOfRangeException(nameof(tagSizeInBytes), "Expected a tag of 12 to 16 bytes.");
        }

        TagSizeInBytes = tagSizeInBytes;
        _cipher = new MkvCipher(MkvBlockSize.Mkv128, key, revision, engine);
        _h = GC.AllocateArray<byte>(BlockBytes, pinned: true);
        Gcm.ComputeH(_cipher.Engine, _cipher.RoundKeys, _h);
    }

    /// <summary>Tag length in bytes, fixed at construction.</summary>
    public int TagSizeInBytes { get; }

    /// <summary>
    /// Encrypts <paramref name="plaintext"/> and writes the tag. A nonce must not be reused with the same key.
    /// </summary>
    /// <param name="nonce">Exactly 12 bytes.</param>
    /// <param name="plaintext">Data to encrypt. Any length, including zero.</param>
    /// <param name="ciphertext">
    /// Receives the ciphertext, the same length as <paramref name="plaintext"/>. May be the same span for in-place use.
    /// </param>
    /// <param name="tag"><see cref="TagSizeInBytes"/> bytes. Receives the tag.</param>
    /// <param name="associatedData">Data to authenticate without encrypting. Any length, including zero.</param>
    /// <exception cref="ObjectDisposedException">The instance has been disposed.</exception>
    /// <exception cref="ArgumentException">
    /// A length is wrong, or an output overlaps an input other than <paramref name="plaintext"/> and
    /// <paramref name="ciphertext"/> in place. Nothing is written in these cases.
    /// </exception>
    public void Encrypt(
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> plaintext,
        Span<byte> ciphertext,
        Span<byte> tag,
        ReadOnlySpan<byte> associatedData = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        RequireLength(nonce, NonceBytes, nameof(nonce));
        RequireLength(ciphertext, plaintext.Length, nameof(ciphertext));
        RequireLength(tag, TagSizeInBytes, nameof(tag));
        BufferChecks.ThrowIfPartialOverlap(plaintext, ciphertext, nameof(ciphertext));
        RequireDisjoint(ciphertext, nonce, nameof(ciphertext));
        RequireDisjoint(ciphertext, associatedData, nameof(ciphertext));
        RequireDisjoint(tag, plaintext, nameof(tag));
        RequireDisjoint(tag, ciphertext, nameof(tag));
        RequireDisjoint(tag, nonce, nameof(tag));
        RequireDisjoint(tag, associatedData, nameof(tag));

        Gcm.Encrypt(_cipher.Engine, _cipher.RoundKeys, _h, nonce, plaintext, ciphertext, tag, associatedData);
    }

    /// <summary>
    /// Verifies the tag, then decrypts. Nothing is decrypted unless the tag matches. A mismatch zeroes
    /// <paramref name="plaintext"/> before it throws.
    /// </summary>
    /// <param name="nonce">Exactly 12 bytes, the nonce used to encrypt.</param>
    /// <param name="ciphertext">Data to decrypt. Any length, including zero.</param>
    /// <param name="tag"><see cref="TagSizeInBytes"/> bytes, the tag from <see cref="Encrypt"/>.</param>
    /// <param name="plaintext">
    /// Receives the plaintext, the same length as <paramref name="ciphertext"/>. May be the same span for in-place use.
    /// </param>
    /// <param name="associatedData">The associated data used to encrypt.</param>
    /// <exception cref="ObjectDisposedException">The instance has been disposed.</exception>
    /// <exception cref="ArgumentException">
    /// A length is wrong, or an output overlaps an input other than <paramref name="ciphertext"/> and
    /// <paramref name="plaintext"/> in place. Nothing is written in these cases.
    /// </exception>
    /// <exception cref="CryptographicException">The tag does not match. <paramref name="plaintext"/> is zeroed.</exception>
    public void Decrypt(
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> ciphertext,
        ReadOnlySpan<byte> tag,
        Span<byte> plaintext,
        ReadOnlySpan<byte> associatedData = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        RequireLength(nonce, NonceBytes, nameof(nonce));
        RequireLength(tag, TagSizeInBytes, nameof(tag));
        RequireLength(plaintext, ciphertext.Length, nameof(plaintext));
        BufferChecks.ThrowIfPartialOverlap(ciphertext, plaintext, nameof(plaintext));
        RequireDisjoint(plaintext, nonce, nameof(plaintext));
        RequireDisjoint(plaintext, tag, nameof(plaintext));
        RequireDisjoint(plaintext, associatedData, nameof(plaintext));

        if (!Gcm.Decrypt(_cipher.Engine, _cipher.RoundKeys, _h, nonce, ciphertext, tag, plaintext, associatedData))
        {
            CryptographicOperations.ZeroMemory(plaintext);
            throw new CryptographicException(DecryptFailure.Message);
        }
    }

    /// <summary>
    /// Encrypts one STREAM segment. The nonce is <paramref name="noncePrefix"/>, then <paramref name="segmentIndex"/> as
    /// 4 big-endian bytes, then one byte that is 1 for the last segment and 0 otherwise. Use each (key, prefix) pair for
    /// one stream only, and never reuse a segment index within it.
    /// </summary>
    /// <param name="noncePrefix"><see cref="StreamNoncePrefixBytes"/> bytes, the same for every segment of a stream.</param>
    /// <param name="segmentIndex">Zero-based segment number.</param>
    /// <param name="isLastSegment">True only for the final segment of the stream.</param>
    /// <param name="plaintext">Data to encrypt. Any length, including zero.</param>
    /// <param name="ciphertext">
    /// Receives the ciphertext, the same length as <paramref name="plaintext"/>. May be the same span for in-place use.
    /// </param>
    /// <param name="tag"><see cref="TagSizeInBytes"/> bytes. Receives the tag.</param>
    /// <param name="associatedData">Data to authenticate without encrypting. Any length, including zero.</param>
    /// <exception cref="ObjectDisposedException">The instance has been disposed.</exception>
    /// <exception cref="ArgumentException">
    /// <paramref name="noncePrefix"/> is not <see cref="StreamNoncePrefixBytes"/> long, or a length is wrong, or an output
    /// overlaps an input other than <paramref name="plaintext"/> and <paramref name="ciphertext"/> in place.
    /// Nothing is written in these cases.
    /// </exception>
    public void EncryptSegment(
        ReadOnlySpan<byte> noncePrefix,
        uint segmentIndex,
        bool isLastSegment,
        ReadOnlySpan<byte> plaintext,
        Span<byte> ciphertext,
        Span<byte> tag,
        ReadOnlySpan<byte> associatedData = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        Span<byte> nonce = stackalloc byte[NonceBytes];
        BuildSegmentNonce(noncePrefix, segmentIndex, isLastSegment, nonce);
        Encrypt(nonce, plaintext, ciphertext, tag, associatedData);
    }

    /// <summary>
    /// Verifies one STREAM segment, then decrypts it. The nonce is built as for <see cref="EncryptSegment"/>. Nothing is
    /// decrypted unless the tag matches. A mismatch zeroes <paramref name="plaintext"/> before it throws.
    /// </summary>
    /// <param name="noncePrefix"><see cref="StreamNoncePrefixBytes"/> bytes, the prefix used to encrypt the segment.</param>
    /// <param name="segmentIndex">The segment number used to encrypt.</param>
    /// <param name="isLastSegment">The last-segment flag used to encrypt.</param>
    /// <param name="ciphertext">Data to decrypt. Any length, including zero.</param>
    /// <param name="tag"><see cref="TagSizeInBytes"/> bytes, the tag from <see cref="EncryptSegment"/>.</param>
    /// <param name="plaintext">
    /// Receives the plaintext, the same length as <paramref name="ciphertext"/>. May be the same span for in-place use.
    /// </param>
    /// <param name="associatedData">The associated data used to encrypt.</param>
    /// <exception cref="ObjectDisposedException">The instance has been disposed.</exception>
    /// <exception cref="ArgumentException">
    /// <paramref name="noncePrefix"/> is not <see cref="StreamNoncePrefixBytes"/> long, or a length is wrong, or an output
    /// overlaps an input other than <paramref name="ciphertext"/> and <paramref name="plaintext"/> in place.
    /// Nothing is written in these cases.
    /// </exception>
    /// <exception cref="CryptographicException">The tag does not match. <paramref name="plaintext"/> is zeroed.</exception>
    public void DecryptSegment(
        ReadOnlySpan<byte> noncePrefix,
        uint segmentIndex,
        bool isLastSegment,
        ReadOnlySpan<byte> ciphertext,
        ReadOnlySpan<byte> tag,
        Span<byte> plaintext,
        ReadOnlySpan<byte> associatedData = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        Span<byte> nonce = stackalloc byte[NonceBytes];
        BuildSegmentNonce(noncePrefix, segmentIndex, isLastSegment, nonce);
        Decrypt(nonce, ciphertext, tag, plaintext, associatedData);
    }

    /// <summary>
    /// Zeroes the GHASH key and the cipher's round keys. Encrypt and Decrypt throw <see cref="ObjectDisposedException"/>
    /// afterwards. A second call does nothing.
    /// </summary>
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        CryptographicOperations.ZeroMemory(_h);
        _cipher.Dispose();
    }

    private static void BuildSegmentNonce(ReadOnlySpan<byte> noncePrefix, uint segmentIndex, bool isLastSegment, Span<byte> nonce)
    {
        RequireLength(noncePrefix, StreamNoncePrefixBytes, nameof(noncePrefix));
        noncePrefix.CopyTo(nonce);
        BinaryPrimitives.WriteUInt32BigEndian(nonce.Slice(StreamNoncePrefixBytes), segmentIndex);
        nonce[NonceBytes - 1] = isLastSegment ? (byte)0x01 : (byte)0x00;
    }

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
