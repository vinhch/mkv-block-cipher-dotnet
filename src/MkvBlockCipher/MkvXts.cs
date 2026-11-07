using System.Security.Cryptography;
using MkvBlockCipher.Modes;

namespace MkvBlockCipher;

/// <summary>
/// IEEE 1619 XTS over 128-bit blocks: encrypts one data unit at a time, with a 32- or 64-byte key split into a data half
/// and a tweak half. XTS does not authenticate: a modified ciphertext decrypts to garbage without an error.
/// </summary>
/// <remarks>
/// Use each data unit number once per key; reusing one with the same key leaks which blocks changed. A data unit is at
/// least 16 bytes and at most 2^20 blocks (16 MiB). Concurrent Encrypt and Decrypt calls are safe after construction;
/// Dispose must not overlap them.
/// </remarks>
public sealed class MkvXts : IDisposable
{
    private const int BlockBytes = 16;

    // 2^20 blocks of 16 bytes: the per-data-unit limit.
    private const int MaxDataUnitBytes = 1 << 24;

    private readonly MkvCipher _dataCipher;
    private readonly MkvCipher _tweakCipher;
    private bool _disposed;

    /// <summary>Derives the data and tweak ciphers from <paramref name="key"/>. The key is read only during construction.</summary>
    /// <param name="key">
    /// 32 or 64 bytes: the first half is the data key and the second half the tweak key. The halves must differ.
    /// </param>
    /// <param name="revision">Algorithm revision. Defaults to <see cref="MkvRevision.Rev2025"/>.</param>
    /// <param name="engine">Engine implementation. Defaults to <see cref="MkvEngine.ConstantTime"/>.</param>
    /// <exception cref="ArgumentException"><paramref name="key"/> is not 32 or 64 bytes, or its two halves are equal.</exception>
    /// <exception cref="ArgumentOutOfRangeException">An enum argument is not a defined value.</exception>
    public MkvXts(ReadOnlySpan<byte> key, MkvRevision revision = MkvRevision.Rev2025, MkvEngine engine = MkvEngine.ConstantTime)
    {
        if (key.Length is not (32 or 64))
        {
            throw new ArgumentException("Expected a 32-byte or 64-byte key.", nameof(key));
        }

        int halfLength = key.Length / 2;
        ReadOnlySpan<byte> dataKey = key.Slice(0, halfLength);
        ReadOnlySpan<byte> tweakKey = key.Slice(halfLength);
        if (CryptographicOperations.FixedTimeEquals(dataKey, tweakKey))
        {
            throw new ArgumentException("The two key halves must differ.", nameof(key));
        }

        _dataCipher = new MkvCipher(MkvBlockSize.Mkv128, dataKey, revision, engine);
        try
        {
            _tweakCipher = new MkvCipher(MkvBlockSize.Mkv128, tweakKey, revision, engine);
        }
        catch
        {
            _dataCipher.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Encrypts one data unit. <paramref name="plaintext"/> may be any length from 16 bytes up to 2^20 blocks; a partial
    /// final block is handled by ciphertext stealing, so the output has the same length.
    /// </summary>
    /// <param name="dataUnitNumber">The data unit (sector) number. Use each number once per key.</param>
    /// <param name="plaintext">At least 16 bytes and at most 16 MiB.</param>
    /// <param name="ciphertext">Receives the ciphertext, the same length as <paramref name="plaintext"/>. May be the same span for in-place use.</param>
    /// <exception cref="ObjectDisposedException">The instance has been disposed.</exception>
    /// <exception cref="ArgumentException">
    /// The length is out of range, <paramref name="ciphertext"/> has a different length, or the spans partially overlap.
    /// Nothing is written in these cases.
    /// </exception>
    public void Encrypt(ulong dataUnitNumber, ReadOnlySpan<byte> plaintext, Span<byte> ciphertext)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        RequireDataUnitLength(plaintext.Length, nameof(plaintext), ciphertext.Length, nameof(ciphertext));
        BufferChecks.ThrowIfPartialOverlap(plaintext, ciphertext, nameof(ciphertext));
        Xts.Encrypt(_dataCipher.Engine, _dataCipher.RoundKeys, _tweakCipher.RoundKeys, dataUnitNumber, plaintext, ciphertext);
    }

    /// <summary>
    /// Decrypts one data unit. XTS has no integrity check, so a wrong key or data unit number yields garbage, not an error.
    /// </summary>
    /// <param name="dataUnitNumber">The data unit number used to encrypt.</param>
    /// <param name="ciphertext">At least 16 bytes and at most 16 MiB.</param>
    /// <param name="plaintext">Receives the plaintext, the same length as <paramref name="ciphertext"/>. May be the same span for in-place use.</param>
    /// <exception cref="ObjectDisposedException">The instance has been disposed.</exception>
    /// <exception cref="ArgumentException">
    /// The length is out of range, <paramref name="plaintext"/> has a different length, or the spans partially overlap.
    /// Nothing is written in these cases.
    /// </exception>
    public void Decrypt(ulong dataUnitNumber, ReadOnlySpan<byte> ciphertext, Span<byte> plaintext)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        RequireDataUnitLength(ciphertext.Length, nameof(ciphertext), plaintext.Length, nameof(plaintext));
        BufferChecks.ThrowIfPartialOverlap(ciphertext, plaintext, nameof(plaintext));
        Xts.Decrypt(_dataCipher.Engine, _dataCipher.RoundKeys, _tweakCipher.RoundKeys, dataUnitNumber, ciphertext, plaintext);
    }

    /// <summary>
    /// Releases both ciphers, which zero their round keys. Later calls throw <see cref="ObjectDisposedException"/>.
    /// A second call does nothing.
    /// </summary>
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        _dataCipher.Dispose();
        _tweakCipher.Dispose();
    }

    private static void RequireDataUnitLength(int inputLength, string inputName, int outputLength, string outputName)
    {
        if (inputLength < BlockBytes)
        {
            throw new ArgumentException($"Expected at least {BlockBytes} bytes.", inputName);
        }

        if (inputLength > MaxDataUnitBytes)
        {
            throw new ArgumentException("The data unit is longer than 2^20 blocks.", inputName);
        }

        if (outputLength != inputLength)
        {
            throw new ArgumentException("Output must be the same length as the input.", outputName);
        }
    }
}
