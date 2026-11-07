using System.Security.Cryptography;
using MkvBlockCipher.Modes;

namespace MkvBlockCipher;

/// <summary>
/// Authenticated encryption: CCM (SP 800-38C) over the MKV 128-bit block cipher, with a 7 to 13-byte nonce and an even tag
/// of 4 to 16 bytes. The tag length is the length of the tag span passed to each call. The key is read only during
/// construction.
/// </summary>
/// <remarks>
/// Never reuse a nonce with the same key: a reused nonce reveals the XOR of two plaintexts and lets an attacker forge tags.
/// The nonce length sets the payload limit: the length field holds q = 15 - nonce length bytes, so a payload is at most
/// 2^(8q) - 1 bytes. That limits a 13-byte nonce to 65535 bytes and a 12-byte nonce to 16777215 bytes. Nonces of 11 bytes
/// or fewer allow any int-length payload. Concurrent Encrypt and Decrypt calls are safe after construction; Dispose must not
/// overlap them.
/// </remarks>
public sealed class MkvCcm : IDisposable
{
    /// <summary>Nonce lengths in bytes: 7 to 13.</summary>
    public static KeySizes NonceByteSizes { get; } = new(7, 13, 1);

    /// <summary>Tag lengths in bytes: 4 to 16, in steps of 2.</summary>
    public static KeySizes TagByteSizes { get; } = new(4, 16, 2);

    private readonly MkvCipher _cipher;
    private bool _disposed;

    /// <summary>Expands the key. The key is read only during construction.</summary>
    /// <param name="key">16, 24 or 32 bytes (MKV-128).</param>
    /// <param name="revision">Algorithm revision. Defaults to <see cref="MkvRevision.Rev2025"/>.</param>
    /// <param name="engine">Engine implementation. Defaults to <see cref="MkvEngine.ConstantTime"/>.</param>
    /// <exception cref="ArgumentException"><paramref name="key"/> is not a valid MKV-128 key length.</exception>
    /// <exception cref="ArgumentOutOfRangeException">An enum argument is not a defined value.</exception>
    public MkvCcm(ReadOnlySpan<byte> key, MkvRevision revision = MkvRevision.Rev2025, MkvEngine engine = MkvEngine.ConstantTime)
    {
        _cipher = new MkvCipher(MkvBlockSize.Mkv128, key, revision, engine);
    }

    /// <summary>
    /// Encrypts <paramref name="plaintext"/> and writes the tag. A nonce must not be reused with the same key.
    /// </summary>
    /// <param name="nonce">7 to 13 bytes. The payload limit depends on its length; see the remarks.</param>
    /// <param name="plaintext">Data to encrypt. Any length within the payload limit, including zero.</param>
    /// <param name="ciphertext">
    /// Receives the ciphertext, the same length as <paramref name="plaintext"/>. May be the same span for in-place use.
    /// </param>
    /// <param name="tag">4 to 16 bytes, an even length. Receives the tag.</param>
    /// <param name="associatedData">Data to authenticate without encrypting. Any length, including zero.</param>
    /// <exception cref="ObjectDisposedException">The instance has been disposed.</exception>
    /// <exception cref="ArgumentException">
    /// A length is wrong, the payload exceeds the limit for the nonce length, or an output overlaps an input other than
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
        RequireNonceAndTag(nonce, tag);
        RequirePayloadLength(plaintext, nonce.Length, nameof(plaintext));
        RequireLength(ciphertext, plaintext.Length, nameof(ciphertext));
        BufferChecks.ThrowIfPartialOverlap(plaintext, ciphertext, nameof(ciphertext));
        RequireDisjoint(ciphertext, nonce, nameof(ciphertext));
        RequireDisjoint(ciphertext, associatedData, nameof(ciphertext));
        RequireDisjoint(tag, plaintext, nameof(tag));
        RequireDisjoint(tag, ciphertext, nameof(tag));
        RequireDisjoint(tag, nonce, nameof(tag));
        RequireDisjoint(tag, associatedData, nameof(tag));

        Ccm.Encrypt(_cipher.Engine, _cipher.RoundKeys, nonce, plaintext, ciphertext, tag, associatedData);
    }

    /// <summary>
    /// Decrypts and verifies the tag. A mismatch zeroes <paramref name="plaintext"/> before it throws.
    /// </summary>
    /// <param name="nonce">7 to 13 bytes, the nonce used to encrypt.</param>
    /// <param name="ciphertext">Data to decrypt. Any length within the payload limit, including zero.</param>
    /// <param name="tag">4 to 16 bytes, the tag from <see cref="Encrypt"/>, the same length.</param>
    /// <param name="plaintext">
    /// Receives the plaintext, the same length as <paramref name="ciphertext"/>. May be the same span for in-place use.
    /// </param>
    /// <param name="associatedData">The associated data used to encrypt.</param>
    /// <exception cref="ObjectDisposedException">The instance has been disposed.</exception>
    /// <exception cref="ArgumentException">
    /// A length is wrong, the payload exceeds the limit for the nonce length, or an output overlaps an input other than
    /// <paramref name="ciphertext"/> and <paramref name="plaintext"/> in place. Nothing is written in these cases.
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
        RequireNonceAndTag(nonce, tag);
        RequirePayloadLength(ciphertext, nonce.Length, nameof(ciphertext));
        RequireLength(plaintext, ciphertext.Length, nameof(plaintext));
        BufferChecks.ThrowIfPartialOverlap(ciphertext, plaintext, nameof(plaintext));
        RequireDisjoint(plaintext, nonce, nameof(plaintext));
        RequireDisjoint(plaintext, tag, nameof(plaintext));
        RequireDisjoint(plaintext, associatedData, nameof(plaintext));

        if (!Ccm.Decrypt(_cipher.Engine, _cipher.RoundKeys, nonce, ciphertext, tag, plaintext, associatedData))
        {
            CryptographicOperations.ZeroMemory(plaintext);
            throw new CryptographicException(DecryptFailure.Message);
        }
    }

    /// <summary>
    /// Zeroes the cipher's round keys. Encrypt and Decrypt throw <see cref="ObjectDisposedException"/> afterwards. A second
    /// call does nothing.
    /// </summary>
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        _cipher.Dispose();
    }

    private static void RequireNonceAndTag(ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> tag)
    {
        if (!IsLegalSize(nonce.Length, NonceByteSizes))
        {
            throw new ArgumentException("Expected a nonce of 7 to 13 bytes.", nameof(nonce));
        }

        if (!IsLegalSize(tag.Length, TagByteSizes))
        {
            throw new ArgumentException("Expected a tag of 4 to 16 bytes, an even length.", nameof(tag));
        }
    }

    // A payload must fit in q = 15 - nonce length bytes (SP 800-38C A.1). Only q below 4 (nonces of 12 or 13 bytes) can be
    // exceeded by an int length.
    private static void RequirePayloadLength(ReadOnlySpan<byte> payload, int nonceLength, string paramName)
    {
        int lengthBytes = 15 - nonceLength;
        if (lengthBytes >= sizeof(int))
        {
            return;
        }

        long maxLength = (1L << (8 * lengthBytes)) - 1;
        if (payload.Length > maxLength)
        {
            throw new ArgumentException($"Expected at most {maxLength} bytes for a {nonceLength}-byte nonce.", paramName);
        }
    }


    private static bool IsLegalSize(int size, KeySizes sizes) =>
        size >= sizes.MinSize && size <= sizes.MaxSize && (size - sizes.MinSize) % sizes.SkipSize == 0;

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
