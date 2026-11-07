using System.Security.Cryptography;
using MkvBlockCipher.Modes;

namespace MkvBlockCipher;

public sealed partial class MkvCipher
{
    /// <summary>
    /// Returns the ciphertext length for a plaintext length. With PKCS#7 this is the next whole block after the plaintext;
    /// a plaintext that already fills whole blocks gains one full padding block. With <see cref="PaddingMode.None"/> the
    /// length is unchanged.
    /// </summary>
    /// <param name="plaintextLength">Plaintext length in bytes.</param>
    /// <param name="paddingMode"><see cref="PaddingMode.PKCS7"/> (default) or <see cref="PaddingMode.None"/>.</param>
    /// <returns>Ciphertext length in bytes, always a whole number of blocks.</returns>
    /// <exception cref="ObjectDisposedException">The instance has been disposed.</exception>
    /// <exception cref="ArgumentOutOfRangeException">
    /// <paramref name="plaintextLength"/> is negative, the ciphertext length would exceed <see cref="int.MaxValue"/>, or
    /// <paramref name="paddingMode"/> is not supported.
    /// </exception>
    /// <exception cref="ArgumentException">
    /// <paramref name="paddingMode"/> is <see cref="PaddingMode.None"/> and <paramref name="plaintextLength"/> is not a
    /// whole number of blocks.
    /// </exception>
    public int GetCiphertextLengthCbc(int plaintextLength, PaddingMode paddingMode = PaddingMode.PKCS7)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentOutOfRangeException.ThrowIfNegative(plaintextLength);
        RequirePadding(paddingMode);
        if (paddingMode == PaddingMode.None)
        {
            if (plaintextLength % BlockSizeBytes != 0)
            {
                throw new ArgumentException("Plaintext must be a whole number of blocks for PaddingMode.None.", nameof(plaintextLength));
            }

            return plaintextLength;
        }

        long ciphertextLength = ((long)plaintextLength / BlockSizeBytes + 1) * BlockSizeBytes;
        if (ciphertextLength > int.MaxValue)
        {
            throw new ArgumentOutOfRangeException(nameof(plaintextLength), "The ciphertext length exceeds int.MaxValue.");
        }

        return (int)ciphertextLength;
    }

    /// <summary>
    /// Encrypts with CBC into a new array of <see cref="GetCiphertextLengthCbc"/> bytes. Use a fresh, unpredictable IV
    /// for each message under the same key.
    /// </summary>
    /// <param name="plaintext">Data to encrypt. Any length with PKCS#7; a whole number of blocks with <see cref="PaddingMode.None"/>.</param>
    /// <param name="iv"><see cref="BlockSizeBytes"/> bytes.</param>
    /// <param name="paddingMode"><see cref="PaddingMode.PKCS7"/> (default) or <see cref="PaddingMode.None"/>.</param>
    /// <returns>The ciphertext.</returns>
    /// <exception cref="ObjectDisposedException">The instance has been disposed.</exception>
    /// <exception cref="ArgumentException">
    /// <paramref name="iv"/> has the wrong length, or <paramref name="paddingMode"/> is <see cref="PaddingMode.None"/> and
    /// <paramref name="plaintext"/> is not a whole number of blocks.
    /// </exception>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="paddingMode"/> is not supported.</exception>
    public byte[] EncryptCbc(ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> iv, PaddingMode paddingMode = PaddingMode.PKCS7)
    {
        byte[] ciphertext = new byte[GetCiphertextLengthCbc(plaintext.Length, paddingMode)];
        EncryptCbc(plaintext, iv, ciphertext, paddingMode);
        return ciphertext;
    }

    /// <summary>
    /// Encrypts with CBC into <paramref name="destination"/>. The plaintext and the destination may start at the same
    /// offset for in-place use; partial overlap is rejected.
    /// </summary>
    /// <param name="plaintext">Data to encrypt. Any length with PKCS#7; a whole number of blocks with <see cref="PaddingMode.None"/>.</param>
    /// <param name="iv"><see cref="BlockSizeBytes"/> bytes.</param>
    /// <param name="destination">Receives the ciphertext. Must hold <see cref="GetCiphertextLengthCbc"/> bytes.</param>
    /// <param name="paddingMode"><see cref="PaddingMode.PKCS7"/> (default) or <see cref="PaddingMode.None"/>.</param>
    /// <returns>The number of bytes written.</returns>
    /// <exception cref="ObjectDisposedException">The instance has been disposed.</exception>
    /// <exception cref="ArgumentException">
    /// <paramref name="iv"/> has the wrong length, the destination is too short, the spans partially overlap, or
    /// <paramref name="paddingMode"/> is <see cref="PaddingMode.None"/> and <paramref name="plaintext"/> is not a whole
    /// number of blocks.
    /// </exception>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="paddingMode"/> is not supported.</exception>
    public int EncryptCbc(ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> iv, Span<byte> destination, PaddingMode paddingMode = PaddingMode.PKCS7)
    {
        if (!TryEncryptCbc(plaintext, iv, destination, out int bytesWritten, paddingMode))
        {
            throw new ArgumentException("Destination is too short for the ciphertext.", nameof(destination));
        }

        return bytesWritten;
    }

    /// <summary>
    /// Encrypts as the non-Try overload does, but returns false instead of throwing when the destination is too short.
    /// Nothing is written in that case.
    /// </summary>
    /// <param name="plaintext">Data to encrypt. Any length with PKCS#7; a whole number of blocks with <see cref="PaddingMode.None"/>.</param>
    /// <param name="iv"><see cref="BlockSizeBytes"/> bytes.</param>
    /// <param name="destination">Receives the ciphertext.</param>
    /// <param name="bytesWritten">Bytes written, or 0 when the destination is too short.</param>
    /// <param name="paddingMode"><see cref="PaddingMode.PKCS7"/> (default) or <see cref="PaddingMode.None"/>.</param>
    /// <returns>False when the destination is too short; otherwise true.</returns>
    /// <exception cref="ObjectDisposedException">The instance has been disposed.</exception>
    /// <exception cref="ArgumentException">
    /// <paramref name="iv"/> has the wrong length, the spans partially overlap, or <paramref name="paddingMode"/> is
    /// <see cref="PaddingMode.None"/> and <paramref name="plaintext"/> is not a whole number of blocks.
    /// </exception>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="paddingMode"/> is not supported.</exception>
    public bool TryEncryptCbc(
        ReadOnlySpan<byte> plaintext,
        ReadOnlySpan<byte> iv,
        Span<byte> destination,
        out int bytesWritten,
        PaddingMode paddingMode = PaddingMode.PKCS7)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        RequireIvLength(iv);
        BufferChecks.ThrowIfPartialOverlap(plaintext, destination, nameof(destination));
        int ciphertextLength = GetCiphertextLengthCbc(plaintext.Length, paddingMode);
        if (destination.Length < ciphertextLength)
        {
            bytesWritten = 0;
            return false;
        }

        Cbc.Encrypt(Engine, RoundKeys, plaintext, iv, destination, paddingMode);
        bytesWritten = ciphertextLength;
        return true;
    }

    /// <summary>
    /// Decrypts CBC into a new array sized to the plaintext. With PKCS#7 the padding is removed; with
    /// <see cref="PaddingMode.None"/> the plaintext is the same length as the ciphertext.
    /// </summary>
    /// <param name="ciphertext">A whole number of blocks; non-empty with PKCS#7.</param>
    /// <param name="iv"><see cref="BlockSizeBytes"/> bytes, the IV used to encrypt.</param>
    /// <param name="paddingMode"><see cref="PaddingMode.PKCS7"/> (default) or <see cref="PaddingMode.None"/>.</param>
    /// <returns>The plaintext.</returns>
    /// <exception cref="ObjectDisposedException">The instance has been disposed.</exception>
    /// <exception cref="ArgumentException">
    /// <paramref name="iv"/> has the wrong length, or <paramref name="ciphertext"/> is not a whole number of blocks, or it
    /// is empty and <paramref name="paddingMode"/> is PKCS#7.
    /// </exception>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="paddingMode"/> is not supported.</exception>
    /// <exception cref="CryptographicException">The padding is not valid.</exception>
    public byte[] DecryptCbc(ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> iv, PaddingMode paddingMode = PaddingMode.PKCS7)
    {
        byte[] buffer = new byte[ciphertext.Length];
        int plaintextLength = DecryptCbc(ciphertext, iv, buffer, paddingMode);
        byte[] plaintext = buffer.AsSpan(0, plaintextLength).ToArray();
        CryptographicOperations.ZeroMemory(buffer);
        return plaintext;
    }

    /// <summary>
    /// Decrypts CBC into <paramref name="destination"/>. The plaintext is decrypted in place in the destination; with
    /// PKCS#7 the padding is stripped afterwards, so the destination must be at least as long as the ciphertext. The
    /// stripped padding bytes are zeroed. On a padding failure the whole destination is zeroed before the exception.
    /// </summary>
    /// <param name="ciphertext">A whole number of blocks; non-empty with PKCS#7. May be the same span as the destination.</param>
    /// <param name="iv"><see cref="BlockSizeBytes"/> bytes, the IV used to encrypt.</param>
    /// <param name="destination">Receives the plaintext. Must hold at least as many bytes as the ciphertext.</param>
    /// <param name="paddingMode"><see cref="PaddingMode.PKCS7"/> (default) or <see cref="PaddingMode.None"/>.</param>
    /// <returns>The plaintext length.</returns>
    /// <exception cref="ObjectDisposedException">The instance has been disposed.</exception>
    /// <exception cref="ArgumentException">
    /// <paramref name="iv"/> has the wrong length, <paramref name="ciphertext"/> is not a whole number of blocks or is
    /// empty with PKCS#7, the destination is shorter than the ciphertext, or the spans partially overlap.
    /// </exception>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="paddingMode"/> is not supported.</exception>
    /// <exception cref="CryptographicException">The padding is not valid.</exception>
    public int DecryptCbc(ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> iv, Span<byte> destination, PaddingMode paddingMode = PaddingMode.PKCS7)
    {
        if (!TryDecryptCbc(ciphertext, iv, destination, out int bytesWritten, paddingMode))
        {
            throw new ArgumentException("Destination is shorter than the ciphertext.", nameof(destination));
        }

        return bytesWritten;
    }

    /// <summary>
    /// Decrypts as the non-Try overload does, but returns false instead of throwing when the destination is shorter than
    /// the ciphertext. Nothing is written in that case. A padding failure still throws.
    /// </summary>
    /// <param name="ciphertext">A whole number of blocks; non-empty with PKCS#7. May be the same span as the destination.</param>
    /// <param name="iv"><see cref="BlockSizeBytes"/> bytes, the IV used to encrypt.</param>
    /// <param name="destination">Receives the plaintext.</param>
    /// <param name="bytesWritten">The plaintext length, or 0 when the destination is too short.</param>
    /// <param name="paddingMode"><see cref="PaddingMode.PKCS7"/> (default) or <see cref="PaddingMode.None"/>.</param>
    /// <returns>False when the destination is too short; otherwise true.</returns>
    /// <exception cref="ObjectDisposedException">The instance has been disposed.</exception>
    /// <exception cref="ArgumentException">
    /// <paramref name="iv"/> has the wrong length, <paramref name="ciphertext"/> is not a whole number of blocks or is
    /// empty with PKCS#7, or the spans partially overlap.
    /// </exception>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="paddingMode"/> is not supported.</exception>
    /// <exception cref="CryptographicException">The padding is not valid.</exception>
    public bool TryDecryptCbc(
        ReadOnlySpan<byte> ciphertext,
        ReadOnlySpan<byte> iv,
        Span<byte> destination,
        out int bytesWritten,
        PaddingMode paddingMode = PaddingMode.PKCS7)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        RequireIvLength(iv);
        RequirePadding(paddingMode);
        RequireWholeBlocks(ciphertext, paddingMode);
        BufferChecks.ThrowIfPartialOverlap(ciphertext, destination, nameof(destination));
        if (destination.Length < ciphertext.Length)
        {
            bytesWritten = 0;
            return false;
        }

        bytesWritten = Cbc.Decrypt(Engine, RoundKeys, ciphertext, iv, destination, paddingMode);
        return true;
    }

    private void RequireIvLength(ReadOnlySpan<byte> iv)
    {
        if (iv.Length != BlockSizeBytes)
        {
            throw new ArgumentException($"Expected {BlockSizeBytes} bytes.", nameof(iv));
        }
    }

    private static void RequirePadding(PaddingMode paddingMode)
    {
        if (paddingMode != PaddingMode.PKCS7 && paddingMode != PaddingMode.None)
        {
            throw new ArgumentOutOfRangeException(nameof(paddingMode), "Only PaddingMode.PKCS7 and PaddingMode.None are supported.");
        }
    }

    private void RequireWholeBlocks(ReadOnlySpan<byte> ciphertext, PaddingMode paddingMode)
    {
        if (ciphertext.Length % BlockSizeBytes != 0)
        {
            throw new ArgumentException("Ciphertext must be a whole number of blocks.", nameof(ciphertext));
        }

        // PKCS#7 always has at least one block to read its padding from; unpadded CBC may be empty.
        if (ciphertext.Length == 0 && paddingMode == PaddingMode.PKCS7)
        {
            throw new ArgumentException("Ciphertext must be a non-empty whole number of blocks.", nameof(ciphertext));
        }
    }
}
