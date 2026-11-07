using System.Security.Cryptography;
using MkvBlockCipher.Modes;

namespace MkvBlockCipher;

public sealed partial class MkvCipher
{
    /// <summary>
    /// Wraps key data with AES Key Wrap (RFC 3394, NIST SP 800-38F) into a new array 8 bytes longer than the input.
    /// </summary>
    /// <remarks>
    /// The input is a whole number of 8-byte blocks, at least 16 bytes. Key wrap needs a 128-bit block, so it is
    /// available only for <see cref="MkvBlockSize.Mkv128"/>.
    /// </remarks>
    /// <param name="plaintext">Key data: a multiple of 8 bytes, at least 16.</param>
    /// <returns>The wrapped key, <paramref name="plaintext"/> plus 8 bytes.</returns>
    /// <exception cref="ObjectDisposedException">The instance has been disposed.</exception>
    /// <exception cref="InvalidOperationException">The block size is <see cref="MkvBlockSize.Mkv256"/>.</exception>
    /// <exception cref="ArgumentException"><paramref name="plaintext"/> is not a multiple of 8 bytes, or is shorter than 16.</exception>
    public byte[] EncryptKeyWrap(ReadOnlySpan<byte> plaintext)
    {
        byte[] ciphertext = new byte[plaintext.Length + 8];
        EncryptKeyWrap(plaintext, ciphertext);
        return ciphertext;
    }

    /// <summary>
    /// Wraps key data with AES Key Wrap into <paramref name="destination"/>, which must be 8 bytes longer than the
    /// plaintext. The plaintext and the destination may start at the same offset for in-place use.
    /// </summary>
    /// <param name="plaintext">Key data: a multiple of 8 bytes, at least 16.</param>
    /// <param name="destination">Receives the wrapped key. Its length is <paramref name="plaintext"/>'s plus 8.</param>
    /// <exception cref="ObjectDisposedException">The instance has been disposed.</exception>
    /// <exception cref="InvalidOperationException">The block size is <see cref="MkvBlockSize.Mkv256"/>.</exception>
    /// <exception cref="ArgumentException">
    /// <paramref name="plaintext"/> is not a multiple of 8 bytes or is shorter than 16, <paramref name="destination"/>
    /// is not precisely sized, or the spans partially overlap. Nothing is written in these cases.
    /// </exception>
    public void EncryptKeyWrap(ReadOnlySpan<byte> plaintext, Span<byte> destination)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        RequireKeyWrapBlockSize();
        if (plaintext.Length < 16 || plaintext.Length % 8 != 0)
        {
            throw new ArgumentException("Expected a multiple of 8 bytes, at least 16.", nameof(plaintext));
        }

        RequireDestinationLength(destination, plaintext.Length + 8);
        BufferChecks.ThrowIfPartialOverlap(plaintext, destination, nameof(destination));
        KeyWrap.Wrap(Engine, RoundKeys, KeyWrap.KwInitialValue, plaintext, destination);
    }

    /// <summary>
    /// Unwraps an AES Key Wrap value into a new array 8 bytes shorter than the ciphertext.
    /// </summary>
    /// <param name="ciphertext">A wrapped key: a multiple of 8 bytes, at least 24.</param>
    /// <returns>The key data.</returns>
    /// <exception cref="ObjectDisposedException">The instance has been disposed.</exception>
    /// <exception cref="InvalidOperationException">The block size is <see cref="MkvBlockSize.Mkv256"/>.</exception>
    /// <exception cref="ArgumentException"><paramref name="ciphertext"/> is not a multiple of 8 bytes or is shorter than 24.</exception>
    /// <exception cref="System.Security.Cryptography.CryptographicException">The integrity check failed.</exception>
    public byte[] DecryptKeyWrap(ReadOnlySpan<byte> ciphertext)
    {
        byte[] plaintext = new byte[Math.Max(ciphertext.Length - 8, 0)];
        DecryptKeyWrap(ciphertext, plaintext);
        return plaintext;
    }

    /// <summary>
    /// Unwraps an AES Key Wrap value into <paramref name="destination"/>. The ciphertext and the destination may start
    /// at the same offset for in-place use.
    /// </summary>
    /// <remarks>
    /// On an integrity failure the destination's first <c>ciphertext.Length - 8</c> bytes are zeroed before the
    /// exception is thrown.
    /// </remarks>
    /// <param name="ciphertext">A wrapped key: a multiple of 8 bytes, at least 24.</param>
    /// <param name="destination">Receives the key data. Must hold at least <c>ciphertext.Length - 8</c> bytes.</param>
    /// <returns>The number of bytes written, <c>ciphertext.Length - 8</c>.</returns>
    /// <exception cref="ObjectDisposedException">The instance has been disposed.</exception>
    /// <exception cref="InvalidOperationException">The block size is <see cref="MkvBlockSize.Mkv256"/>.</exception>
    /// <exception cref="ArgumentException">
    /// <paramref name="ciphertext"/> is not a multiple of 8 bytes or is shorter than 24, <paramref name="destination"/>
    /// is too short, or the spans partially overlap. Nothing is written in these cases.
    /// </exception>
    /// <exception cref="System.Security.Cryptography.CryptographicException">The integrity check failed.</exception>
    public int DecryptKeyWrap(ReadOnlySpan<byte> ciphertext, Span<byte> destination)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        RequireKeyWrapBlockSize();
        int plaintextLength = ciphertext.Length - 8;
        if (destination.Length < plaintextLength)
        {
            throw new ArgumentException("Destination must hold at least ciphertext.Length - 8 bytes.", nameof(destination));
        }

        BufferChecks.ThrowIfPartialOverlap(ciphertext, destination, nameof(destination));
        Span<byte> recoveredValue = stackalloc byte[8];
        if (!KeyWrap.TryUnwrap(Engine, RoundKeys, ciphertext, destination, recoveredValue))
        {
            throw new ArgumentException("Expected a multiple of 8 bytes, at least 24.", nameof(ciphertext));
        }

        bool intact = CryptographicOperations.FixedTimeEquals(recoveredValue, KeyWrap.KwInitialValue);
        CryptographicOperations.ZeroMemory(recoveredValue);
        if (!intact)
        {
            CryptographicOperations.ZeroMemory(destination.Slice(0, plaintextLength));
            throw new CryptographicException(DecryptFailure.Message);
        }

        return plaintextLength;
    }

    /// <summary>
    /// Wraps key data of any non-zero length with AES Key Wrap with Padding (RFC 5649, NIST SP 800-38F) into a new array.
    /// </summary>
    /// <remarks>
    /// Key wrap needs a 128-bit block, so it is available only for <see cref="MkvBlockSize.Mkv128"/>. The output is
    /// <see cref="GetKeyWrapPaddedLength"/> bytes.
    /// </remarks>
    /// <param name="plaintext">Key data, at least one byte.</param>
    /// <returns>The wrapped key.</returns>
    /// <exception cref="ObjectDisposedException">The instance has been disposed.</exception>
    /// <exception cref="InvalidOperationException">The block size is <see cref="MkvBlockSize.Mkv256"/>.</exception>
    /// <exception cref="ArgumentException"><paramref name="plaintext"/> is empty.</exception>
    public byte[] EncryptKeyWrapPadded(ReadOnlySpan<byte> plaintext)
    {
        byte[] ciphertext = new byte[plaintext.IsEmpty ? 0 : GetKeyWrapPaddedLength(plaintext.Length)];
        EncryptKeyWrapPadded(plaintext, ciphertext);
        return ciphertext;
    }

    /// <summary>
    /// Wraps key data with AES Key Wrap with Padding into <paramref name="destination"/>, which must be exactly
    /// <see cref="GetKeyWrapPaddedLength"/> bytes long. The plaintext and the destination may start at the same offset
    /// for in-place use.
    /// </summary>
    /// <param name="plaintext">Key data, at least one byte.</param>
    /// <param name="destination">Receives the wrapped key.</param>
    /// <exception cref="ObjectDisposedException">The instance has been disposed.</exception>
    /// <exception cref="InvalidOperationException">The block size is <see cref="MkvBlockSize.Mkv256"/>.</exception>
    /// <exception cref="ArgumentException">
    /// <paramref name="plaintext"/> is empty, <paramref name="destination"/> is not precisely sized, or the spans
    /// partially overlap. Nothing is written in these cases.
    /// </exception>
    public void EncryptKeyWrapPadded(ReadOnlySpan<byte> plaintext, Span<byte> destination)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        RequireKeyWrapBlockSize();
        if (plaintext.IsEmpty)
        {
            throw new ArgumentException("Plaintext must not be empty.", nameof(plaintext));
        }

        RequireDestinationLength(destination, GetKeyWrapPaddedLength(plaintext.Length));
        BufferChecks.ThrowIfPartialOverlap(plaintext, destination, nameof(destination));
        KeyWrap.WrapPadded(Engine, RoundKeys, plaintext, destination);
    }

    /// <summary>
    /// Unwraps an AES Key Wrap with Padding value into a new array of the recovered key length.
    /// </summary>
    /// <param name="ciphertext">A wrapped key: a multiple of 8 bytes, at least 16.</param>
    /// <returns>The key data.</returns>
    /// <exception cref="ObjectDisposedException">The instance has been disposed.</exception>
    /// <exception cref="InvalidOperationException">The block size is <see cref="MkvBlockSize.Mkv256"/>.</exception>
    /// <exception cref="ArgumentException"><paramref name="ciphertext"/> is not a multiple of 8 bytes or is shorter than 16.</exception>
    /// <exception cref="System.Security.Cryptography.CryptographicException">The integrity check failed.</exception>
    public byte[] DecryptKeyWrapPadded(ReadOnlySpan<byte> ciphertext)
    {
        // The recovered length is known only after the check, so the result is copied out of a ciphertext-sized
        // buffer, which is zeroed.
        byte[] buffer = new byte[Math.Max(ciphertext.Length - 8, 0)];
        int length = DecryptKeyWrapPadded(ciphertext, buffer);
        byte[] plaintext = buffer.AsSpan(0, length).ToArray();
        CryptographicOperations.ZeroMemory(buffer);
        return plaintext;
    }

    /// <summary>
    /// Unwraps an AES Key Wrap with Padding value into <paramref name="destination"/>. The ciphertext and the destination
    /// may start at the same offset for in-place use.
    /// </summary>
    /// <remarks>
    /// Throws <see cref="System.Security.Cryptography.CryptographicException"/> when the integrity check fails, with the
    /// same message for every failure. The destination's first <c>ciphertext.Length - 8</c> bytes are zeroed first.
    /// </remarks>
    /// <param name="ciphertext">A wrapped key: a multiple of 8 bytes, at least 16.</param>
    /// <param name="destination">Receives the key data. Must hold at least <c>ciphertext.Length - 8</c> bytes.</param>
    /// <returns>The number of bytes in the unwrapped key.</returns>
    /// <exception cref="ObjectDisposedException">The instance has been disposed.</exception>
    /// <exception cref="InvalidOperationException">The block size is <see cref="MkvBlockSize.Mkv256"/>.</exception>
    /// <exception cref="ArgumentException">
    /// <paramref name="ciphertext"/> is not a multiple of 8 bytes or is shorter than 16, <paramref name="destination"/>
    /// is too short, or the spans partially overlap. Nothing is written in these cases.
    /// </exception>
    /// <exception cref="System.Security.Cryptography.CryptographicException">The integrity check failed.</exception>
    public int DecryptKeyWrapPadded(ReadOnlySpan<byte> ciphertext, Span<byte> destination)
    {
        if (!TryDecryptKeyWrapPadded(ciphertext, destination, out int bytesWritten))
        {
            throw new ArgumentException("Destination must hold at least ciphertext.Length - 8 bytes.", nameof(destination));
        }

        return bytesWritten;
    }

    /// <summary>
    /// Attempts to unwrap an AES Key Wrap with Padding value into <paramref name="destination"/>.
    /// </summary>
    /// <remarks>
    /// Returns false, writing nothing, when <paramref name="destination"/> holds less than <c>ciphertext.Length - 8</c>
    /// bytes. Throws <see cref="System.Security.Cryptography.CryptographicException"/> when the integrity check fails;
    /// the destination's first <c>ciphertext.Length - 8</c> bytes are zeroed first.
    /// </remarks>
    /// <param name="ciphertext">A wrapped key: a multiple of 8 bytes, at least 16.</param>
    /// <param name="destination">Receives the key data.</param>
    /// <param name="bytesWritten">The number of bytes written, or zero.</param>
    /// <returns>true if the key was unwrapped; false if the destination is too short.</returns>
    /// <exception cref="ObjectDisposedException">The instance has been disposed.</exception>
    /// <exception cref="InvalidOperationException">The block size is <see cref="MkvBlockSize.Mkv256"/>.</exception>
    /// <exception cref="ArgumentException"><paramref name="ciphertext"/> is not a multiple of 8 bytes or is shorter than 16, or the spans partially overlap.</exception>
    /// <exception cref="System.Security.Cryptography.CryptographicException">The integrity check failed.</exception>
    public bool TryDecryptKeyWrapPadded(ReadOnlySpan<byte> ciphertext, Span<byte> destination, out int bytesWritten)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        RequireKeyWrapBlockSize();
        if (ciphertext.Length < 16 || ciphertext.Length % 8 != 0)
        {
            throw new ArgumentException("Expected a multiple of 8 bytes, at least 16.", nameof(ciphertext));
        }

        bytesWritten = 0;
        int capacity = ciphertext.Length - 8;
        if (destination.Length < capacity)
        {
            return false;
        }

        BufferChecks.ThrowIfPartialOverlap(ciphertext, destination, nameof(destination));
        if (!KeyWrap.TryUnwrapPadded(Engine, RoundKeys, ciphertext, destination, out bytesWritten))
        {
            CryptographicOperations.ZeroMemory(destination.Slice(0, capacity));
            bytesWritten = 0;
            throw new CryptographicException(DecryptFailure.Message);
        }

        return true;
    }

    /// <summary>
    /// Gets the output length of AES Key Wrap with Padding for a plaintext length: the plaintext rounded up to a whole
    /// number of 8-byte blocks, plus 8.
    /// </summary>
    /// <param name="plaintextLength">Key data length in bytes, at least one.</param>
    /// <returns>The wrapped length in bytes.</returns>
    /// <exception cref="ArgumentOutOfRangeException">
    /// <paramref name="plaintextLength"/> is zero or negative, or the wrapped length does not fit in an <see cref="int"/>.
    /// </exception>
    public static int GetKeyWrapPaddedLength(int plaintextLength)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(plaintextLength);
        long paddedLength = ((plaintextLength + 7L) / 8 * 8) + 8;
        if (paddedLength > int.MaxValue)
        {
            throw new ArgumentOutOfRangeException(nameof(plaintextLength));
        }

        return (int)paddedLength;
    }

    private void RequireKeyWrapBlockSize()
    {
        if (BlockSizeBytes != 16)
        {
            throw new InvalidOperationException("Key wrap needs a 128-bit block: use MkvBlockSize.Mkv128.");
        }
    }

    private static void RequireDestinationLength(Span<byte> destination, int length)
    {
        if (destination.Length != length)
        {
            throw new ArgumentException("Destination must be precisely sized.", nameof(destination));
        }
    }
}
