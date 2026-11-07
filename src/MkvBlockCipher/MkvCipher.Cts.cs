using MkvBlockCipher.Modes;

namespace MkvBlockCipher;

public sealed partial class MkvCipher
{
    /// <summary>
    /// Encrypts with CBC ciphertext stealing into a new array of the same length as the plaintext. The IV rules are
    /// those of CBC, except for deterministic use such as file names; see the security notes.
    /// </summary>
    /// <remarks>
    /// Input of exactly one block is plain CBC. Longer input has its last two blocks swapped, and the final block is
    /// truncated, so no padding is added. The output is not authenticated.
    /// </remarks>
    /// <param name="plaintext">At least <see cref="BlockSizeBytes"/> bytes.</param>
    /// <param name="iv"><see cref="BlockSizeBytes"/> bytes.</param>
    /// <returns>The ciphertext, the same length as <paramref name="plaintext"/>.</returns>
    /// <exception cref="ObjectDisposedException">The instance has been disposed.</exception>
    /// <exception cref="ArgumentException"><paramref name="iv"/> has the wrong length, or <paramref name="plaintext"/> is shorter than one block.</exception>
    public byte[] EncryptCbcCts(ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> iv)
    {
        byte[] ciphertext = new byte[plaintext.Length];
        EncryptCbcCts(plaintext, iv, ciphertext);
        return ciphertext;
    }

    /// <summary>
    /// Encrypts with CBC ciphertext stealing into <paramref name="destination"/>, which must be the same length as the
    /// plaintext. The plaintext and the destination may start at the same offset for in-place use.
    /// </summary>
    /// <param name="plaintext">At least <see cref="BlockSizeBytes"/> bytes.</param>
    /// <param name="iv"><see cref="BlockSizeBytes"/> bytes.</param>
    /// <param name="destination">Receives the ciphertext. Its length must equal <paramref name="plaintext"/>'s.</param>
    /// <exception cref="ObjectDisposedException">The instance has been disposed.</exception>
    /// <exception cref="ArgumentException">
    /// <paramref name="iv"/> has the wrong length, <paramref name="plaintext"/> is shorter than one block, the destination
    /// length differs from the plaintext length, or the spans partially overlap. Nothing is written in these cases.
    /// </exception>
    public void EncryptCbcCts(ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> iv, Span<byte> destination)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        RequireIvLength(iv);
        RequireCtsLength(plaintext, destination, nameof(plaintext));
        BufferChecks.ThrowIfPartialOverlap(plaintext, destination, nameof(destination));
        CbcCts.Encrypt(Engine, RoundKeys, plaintext, iv, destination);
    }

    /// <summary>
    /// Decrypts CBC ciphertext stealing into a new array of the same length as the ciphertext.
    /// </summary>
    /// <param name="ciphertext">At least <see cref="BlockSizeBytes"/> bytes.</param>
    /// <param name="iv"><see cref="BlockSizeBytes"/> bytes, the IV used to encrypt.</param>
    /// <returns>The plaintext, the same length as <paramref name="ciphertext"/>.</returns>
    /// <exception cref="ObjectDisposedException">The instance has been disposed.</exception>
    /// <exception cref="ArgumentException"><paramref name="iv"/> has the wrong length, or <paramref name="ciphertext"/> is shorter than one block.</exception>
    public byte[] DecryptCbcCts(ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> iv)
    {
        byte[] plaintext = new byte[ciphertext.Length];
        DecryptCbcCts(ciphertext, iv, plaintext);
        return plaintext;
    }

    /// <summary>
    /// Decrypts CBC ciphertext stealing into <paramref name="destination"/>, which must be the same length as the
    /// ciphertext. The ciphertext and the destination may start at the same offset for in-place use.
    /// </summary>
    /// <param name="ciphertext">At least <see cref="BlockSizeBytes"/> bytes. May be the same span as the destination.</param>
    /// <param name="iv"><see cref="BlockSizeBytes"/> bytes, the IV used to encrypt.</param>
    /// <param name="destination">Receives the plaintext. Its length must equal <paramref name="ciphertext"/>'s.</param>
    /// <exception cref="ObjectDisposedException">The instance has been disposed.</exception>
    /// <exception cref="ArgumentException">
    /// <paramref name="iv"/> has the wrong length, <paramref name="ciphertext"/> is shorter than one block, the destination
    /// length differs from the ciphertext length, or the spans partially overlap. Nothing is written in these cases.
    /// </exception>
    public void DecryptCbcCts(ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> iv, Span<byte> destination)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        RequireIvLength(iv);
        RequireCtsLength(ciphertext, destination, nameof(ciphertext));
        BufferChecks.ThrowIfPartialOverlap(ciphertext, destination, nameof(destination));
        CbcCts.Decrypt(Engine, RoundKeys, ciphertext, iv, destination);
    }

    private void RequireCtsLength(ReadOnlySpan<byte> input, Span<byte> destination, string inputName)
    {
        if (input.Length < BlockSizeBytes)
        {
            throw new ArgumentException($"Expected at least {BlockSizeBytes} bytes.", inputName);
        }

        if (destination.Length != input.Length)
        {
            throw new ArgumentException("Destination must be the same length as the input.", nameof(destination));
        }
    }
}
