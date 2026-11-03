using System.Security.Cryptography;
using MkvBlockCipher.Modes;

namespace MkvBlockCipher;

public sealed partial class MkvCipher
{
    /// <summary>
    /// Returns the ciphertext length for a plaintext length: the next whole block after the plaintext. A plaintext that
    /// already fills whole blocks gains one full padding block.
    /// </summary>
    /// <param name="plaintextLength">Plaintext length in bytes.</param>
    /// <returns>Ciphertext length in bytes, always a whole number of blocks.</returns>
    /// <exception cref="ObjectDisposedException">The instance has been disposed.</exception>
    /// <exception cref="ArgumentOutOfRangeException">
    /// <paramref name="plaintextLength"/> is negative, or the ciphertext length would exceed <see cref="int.MaxValue"/>.
    /// </exception>
    public int GetCiphertextLengthCbc(int plaintextLength)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentOutOfRangeException.ThrowIfNegative(plaintextLength);
        long ciphertextLength = ((long)plaintextLength / BlockSizeBytes + 1) * BlockSizeBytes;
        if (ciphertextLength > int.MaxValue)
        {
            throw new ArgumentOutOfRangeException(nameof(plaintextLength), "The ciphertext length exceeds int.MaxValue.");
        }

        return (int)ciphertextLength;
    }

    /// <summary>
    /// Encrypts with CBC and PKCS#7 padding into a new array of <see cref="GetCiphertextLengthCbc"/> bytes. Use a fresh,
    /// unpredictable IV for each message under the same key.
    /// </summary>
    /// <param name="plaintext">Data to encrypt. Any length, including zero.</param>
    /// <param name="iv"><see cref="BlockSizeBytes"/> bytes.</param>
    /// <returns>The ciphertext.</returns>
    /// <exception cref="ObjectDisposedException">The instance has been disposed.</exception>
    /// <exception cref="ArgumentException"><paramref name="iv"/> has the wrong length.</exception>
    public byte[] EncryptCbc(ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> iv)
    {
        byte[] ciphertext = new byte[GetCiphertextLengthCbc(plaintext.Length)];
        EncryptCbc(plaintext, iv, ciphertext);
        return ciphertext;
    }

    /// <summary>
    /// Encrypts with CBC and PKCS#7 padding into <paramref name="destination"/>. The plaintext and the destination may
    /// start at the same offset for in-place use; partial overlap is rejected.
    /// </summary>
    /// <param name="plaintext">Data to encrypt. Any length, including zero.</param>
    /// <param name="iv"><see cref="BlockSizeBytes"/> bytes.</param>
    /// <param name="destination">Receives the ciphertext. Must hold <see cref="GetCiphertextLengthCbc"/> bytes.</param>
    /// <returns>The number of bytes written.</returns>
    /// <exception cref="ObjectDisposedException">The instance has been disposed.</exception>
    /// <exception cref="ArgumentException">
    /// <paramref name="iv"/> has the wrong length, the destination is too short, or the spans partially overlap.
    /// </exception>
    public int EncryptCbc(ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> iv, Span<byte> destination)
    {
        if (!TryEncryptCbc(plaintext, iv, destination, out int bytesWritten))
        {
            throw new ArgumentException("Destination is too short for the ciphertext.", nameof(destination));
        }

        return bytesWritten;
    }

    /// <summary>
    /// Encrypts as the non-Try overload does, but returns false instead of throwing when the destination is too short.
    /// Nothing is written in that case.
    /// </summary>
    /// <param name="plaintext">Data to encrypt. Any length, including zero.</param>
    /// <param name="iv"><see cref="BlockSizeBytes"/> bytes.</param>
    /// <param name="destination">Receives the ciphertext.</param>
    /// <param name="bytesWritten">Bytes written, or 0 when the destination is too short.</param>
    /// <returns>False when the destination is too short; otherwise true.</returns>
    /// <exception cref="ObjectDisposedException">The instance has been disposed.</exception>
    /// <exception cref="ArgumentException"><paramref name="iv"/> has the wrong length, or the spans partially overlap.</exception>
    public bool TryEncryptCbc(ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> iv, Span<byte> destination, out int bytesWritten)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        RequireIvLength(iv);
        BufferChecks.ThrowIfPartialOverlap(plaintext, destination, nameof(destination));
        int ciphertextLength = GetCiphertextLengthCbc(plaintext.Length);
        if (destination.Length < ciphertextLength)
        {
            bytesWritten = 0;
            return false;
        }

        Cbc.Encrypt(Engine, RoundKeys, plaintext, iv, destination);
        bytesWritten = ciphertextLength;
        return true;
    }

    /// <summary>
    /// Decrypts CBC with PKCS#7 padding into a new array sized to the plaintext.
    /// </summary>
    /// <param name="ciphertext">A non-empty whole number of blocks.</param>
    /// <param name="iv"><see cref="BlockSizeBytes"/> bytes, the IV used to encrypt.</param>
    /// <returns>The plaintext.</returns>
    /// <exception cref="ObjectDisposedException">The instance has been disposed.</exception>
    /// <exception cref="ArgumentException">
    /// <paramref name="iv"/> has the wrong length, or <paramref name="ciphertext"/> is empty or not a whole number of blocks.
    /// </exception>
    /// <exception cref="CryptographicException">The padding is not valid.</exception>
    public byte[] DecryptCbc(ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> iv)
    {
        byte[] buffer = new byte[ciphertext.Length];
        int plaintextLength = DecryptCbc(ciphertext, iv, buffer);
        byte[] plaintext = buffer.AsSpan(0, plaintextLength).ToArray();
        CryptographicOperations.ZeroMemory(buffer);
        return plaintext;
    }

    /// <summary>
    /// Decrypts CBC with PKCS#7 padding into <paramref name="destination"/>. The plaintext is decrypted in place in the
    /// destination and the padding is stripped afterwards, so the destination must be at least as long as the ciphertext.
    /// The stripped padding bytes are zeroed. On a padding failure the whole destination is zeroed before the exception.
    /// </summary>
    /// <param name="ciphertext">A non-empty whole number of blocks. May be the same span as the destination.</param>
    /// <param name="iv"><see cref="BlockSizeBytes"/> bytes, the IV used to encrypt.</param>
    /// <param name="destination">Receives the plaintext. Must hold at least as many bytes as the ciphertext.</param>
    /// <returns>The plaintext length.</returns>
    /// <exception cref="ObjectDisposedException">The instance has been disposed.</exception>
    /// <exception cref="ArgumentException">
    /// <paramref name="iv"/> has the wrong length, <paramref name="ciphertext"/> is empty or not a whole number of blocks,
    /// the destination is shorter than the ciphertext, or the spans partially overlap.
    /// </exception>
    /// <exception cref="CryptographicException">The padding is not valid.</exception>
    public int DecryptCbc(ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> iv, Span<byte> destination)
    {
        if (!TryDecryptCbc(ciphertext, iv, destination, out int bytesWritten))
        {
            throw new ArgumentException("Destination is shorter than the ciphertext.", nameof(destination));
        }

        return bytesWritten;
    }

    /// <summary>
    /// Decrypts as the non-Try overload does, but returns false instead of throwing when the destination is shorter than
    /// the ciphertext. Nothing is written in that case. A padding failure still throws.
    /// </summary>
    /// <param name="ciphertext">A non-empty whole number of blocks. May be the same span as the destination.</param>
    /// <param name="iv"><see cref="BlockSizeBytes"/> bytes, the IV used to encrypt.</param>
    /// <param name="destination">Receives the plaintext.</param>
    /// <param name="bytesWritten">The plaintext length, or 0 when the destination is too short.</param>
    /// <returns>False when the destination is too short; otherwise true.</returns>
    /// <exception cref="ObjectDisposedException">The instance has been disposed.</exception>
    /// <exception cref="ArgumentException">
    /// <paramref name="iv"/> has the wrong length, <paramref name="ciphertext"/> is empty or not a whole number of blocks,
    /// or the spans partially overlap.
    /// </exception>
    /// <exception cref="CryptographicException">The padding is not valid.</exception>
    public bool TryDecryptCbc(ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> iv, Span<byte> destination, out int bytesWritten)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        RequireIvLength(iv);
        RequireWholeBlocks(ciphertext);
        BufferChecks.ThrowIfPartialOverlap(ciphertext, destination, nameof(destination));
        if (destination.Length < ciphertext.Length)
        {
            bytesWritten = 0;
            return false;
        }

        bytesWritten = Cbc.Decrypt(Engine, RoundKeys, ciphertext, iv, destination);
        return true;
    }

    private void RequireIvLength(ReadOnlySpan<byte> iv)
    {
        if (iv.Length != BlockSizeBytes)
        {
            throw new ArgumentException($"Expected {BlockSizeBytes} bytes.", nameof(iv));
        }
    }

    private void RequireWholeBlocks(ReadOnlySpan<byte> ciphertext)
    {
        if (ciphertext.Length == 0 || ciphertext.Length % BlockSizeBytes != 0)
        {
            throw new ArgumentException("Ciphertext must be a non-empty whole number of blocks.", nameof(ciphertext));
        }
    }
}
