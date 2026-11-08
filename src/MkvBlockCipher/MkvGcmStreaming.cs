using System.Security.Cryptography;
using MkvBlockCipher.Modes;

namespace MkvBlockCipher;

/// <summary>
/// Authenticated segmented streams over <see cref="MkvGcm"/>. Each segment is sealed with the STREAM construction, so a
/// reader detects truncation, reordering, dropped or repeated segments, and trailing data. Decryption writes a segment's
/// plaintext only after its tag verifies.
/// </summary>
/// <remarks>
/// Wire format: each segment is its ciphertext then its tag; every segment but the last holds <c>segmentSizeBytes</c> of
/// ciphertext, and the last holds 0 to that many. No header or length prefix. Input that is an exact multiple of the
/// segment size ends in a full final segment; empty input is one tag.
/// Use one key and one nonce prefix per stream: derive a key per stream (HKDF-SHA256 with a stored random salt), or use prefixes that never repeat under the key.
/// A stream holds at most 2^32 segments. Nothing stops a rollback to an older complete stream under the same key, prefix and associated data.
/// </remarks>
public static class MkvGcmStreaming
{
    /// <summary>Default plaintext bytes per segment: 64 KiB.</summary>
    public const int DefaultSegmentSizeBytes = 65536;

    /// <summary>Smallest allowed segment size in bytes.</summary>
    public const int MinSegmentSizeBytes = 16;

    /// <summary>Largest allowed segment size in bytes: 16 MiB.</summary>
    public const int MaxSegmentSizeBytes = 1 << 24;

    /// <summary>
    /// Encrypts all of <paramref name="source"/> to <paramref name="destination"/> in segments. Writes the wire format
    /// described in the type remarks, then flushes <paramref name="destination"/>.
    /// </summary>
    /// <param name="gcm">The key. Must not be disposed until the call returns.</param>
    /// <param name="noncePrefix"><see cref="MkvGcm.StreamNoncePrefixBytes"/> bytes, the same for every segment of the stream.</param>
    /// <param name="source">The plaintext. Read to its end; not disposed.</param>
    /// <param name="destination">Receives the ciphertext. Not disposed.</param>
    /// <param name="segmentSizeBytes">Plaintext bytes per segment, from <see cref="MinSegmentSizeBytes"/> to <see cref="MaxSegmentSizeBytes"/>.</param>
    /// <param name="associatedData">Bound to every segment and not stored.</param>
    /// <exception cref="ArgumentNullException"><paramref name="gcm"/>, <paramref name="source"/> or <paramref name="destination"/> is null.</exception>
    /// <exception cref="ArgumentException">
    /// <paramref name="noncePrefix"/> is not 7 bytes, <paramref name="source"/> is not readable, <paramref name="destination"/>
    /// is not writable. Nothing is read or written for these. The 2^32-segment error is raised when the limit is reached,
    /// after earlier segments were written; discard them.
    /// </exception>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="segmentSizeBytes"/> is out of range.</exception>
    /// <exception cref="ObjectDisposedException"><paramref name="gcm"/> has been disposed.</exception>
    /// <remarks>
    /// On any exception the output is incomplete and must be discarded. Exceptions from the streams propagate unwrapped.
    /// Buffers: two pinned arrays per call, zeroed before return.
    /// </remarks>
    public static void Encrypt(
        MkvGcm gcm,
        ReadOnlySpan<byte> noncePrefix,
        Stream source,
        Stream destination,
        int segmentSizeBytes = DefaultSegmentSizeBytes,
        ReadOnlySpan<byte> associatedData = default)
    {
        Validate(gcm, noncePrefix, source, destination, segmentSizeBytes);
        EncryptCore(gcm, noncePrefix, source, destination, segmentSizeBytes, associatedData, firstSegmentIndex: 0);
    }

    /// <summary>
    /// Decrypts a stream written by <see cref="Encrypt"/>, verifying each segment before writing its plaintext.
    /// </summary>
    /// <param name="gcm">The key. Must not be disposed until the call returns.</param>
    /// <param name="noncePrefix"><see cref="MkvGcm.StreamNoncePrefixBytes"/> bytes, the prefix used to encrypt.</param>
    /// <param name="source">The ciphertext. Read to its end; not disposed.</param>
    /// <param name="destination">Receives the verified plaintext. Not disposed.</param>
    /// <param name="segmentSizeBytes">The segment size used to encrypt.</param>
    /// <param name="associatedData">The associated data used to encrypt.</param>
    /// <exception cref="ArgumentNullException"><paramref name="gcm"/>, <paramref name="source"/> or <paramref name="destination"/> is null.</exception>
    /// <exception cref="ArgumentException">
    /// <paramref name="noncePrefix"/> is not 7 bytes, <paramref name="source"/> is not readable, or <paramref name="destination"/>
    /// is not writable. Nothing is read or written for these.
    /// </exception>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="segmentSizeBytes"/> is out of range.</exception>
    /// <exception cref="CryptographicException">
    /// The stream is truncated, extended, reordered, or altered, or was encrypted with other values. Segments before the
    /// failing one were already written; discard them.
    /// </exception>
    /// <exception cref="ObjectDisposedException"><paramref name="gcm"/> has been disposed.</exception>
    /// <remarks>
    /// Buffers: two pinned arrays per call, zeroed before return. The failing segment's plaintext is never written.
    /// </remarks>
    public static void Decrypt(
        MkvGcm gcm,
        ReadOnlySpan<byte> noncePrefix,
        Stream source,
        Stream destination,
        int segmentSizeBytes = DefaultSegmentSizeBytes,
        ReadOnlySpan<byte> associatedData = default)
    {
        Validate(gcm, noncePrefix, source, destination, segmentSizeBytes);
        DecryptCore(gcm, noncePrefix, source, destination, segmentSizeBytes, associatedData, firstSegmentIndex: 0);
    }

    // The loops take the first segment index as a seam, so the 2^32 limit is reachable without 2^32 segments.
    internal static void EncryptCore(
        MkvGcm gcm,
        ReadOnlySpan<byte> noncePrefix,
        Stream source,
        Stream destination,
        int segmentSizeBytes,
        ReadOnlySpan<byte> associatedData,
        uint firstSegmentIndex)
    {
        int tagBytes = gcm.TagSizeInBytes;
        // The extra byte is the lookahead that tells a full non-final segment from the final one.
        byte[] input = GC.AllocateUninitializedArray<byte>(segmentSizeBytes + tagBytes + 1, pinned: true);
        byte[] output = GC.AllocateUninitializedArray<byte>(segmentSizeBytes + tagBytes, pinned: true);
        try
        {
            int carried = 0;
            uint index = firstSegmentIndex;
            while (true)
            {
                int total = FillSegment(source, input, carried, segmentSizeBytes + 1);
                bool isLast = total <= segmentSizeBytes;
                if (!isLast && index == uint.MaxValue)
                {
                    throw new ArgumentException("The input needs more than 2^32 segments.", nameof(source));
                }

                int plaintextBytes = isLast ? total : segmentSizeBytes;
                gcm.EncryptSegment(noncePrefix, index, isLast, input.AsSpan(0, plaintextBytes),
                    output.AsSpan(0, plaintextBytes), output.AsSpan(plaintextBytes, tagBytes), associatedData);
                destination.Write(output.AsSpan(0, plaintextBytes + tagBytes));

                if (isLast)
                {
                    break;
                }

                input[0] = input[segmentSizeBytes];
                carried = 1;
                index++;
            }

            destination.Flush();
        }
        finally
        {
            CryptographicOperations.ZeroMemory(input);
            CryptographicOperations.ZeroMemory(output);
        }
    }

    internal static void DecryptCore(
        MkvGcm gcm,
        ReadOnlySpan<byte> noncePrefix,
        Stream source,
        Stream destination,
        int segmentSizeBytes,
        ReadOnlySpan<byte> associatedData,
        uint firstSegmentIndex)
    {
        int tagBytes = gcm.TagSizeInBytes;
        int wireSegmentBytes = segmentSizeBytes + tagBytes;
        byte[] input = GC.AllocateUninitializedArray<byte>(wireSegmentBytes + 1, pinned: true);
        byte[] output = GC.AllocateUninitializedArray<byte>(wireSegmentBytes, pinned: true);
        try
        {
            int carried = 0;
            uint index = firstSegmentIndex;
            while (true)
            {
                int total = FillSegment(source, input, carried, wireSegmentBytes + 1);
                bool isLast = total <= wireSegmentBytes;
                int wireBytes = isLast ? total : wireSegmentBytes;
                ThrowIfBadFraming(isLast, wireBytes, tagBytes, index);

                int plaintextBytes = wireBytes - tagBytes;
                gcm.DecryptSegment(noncePrefix, index, isLast, input.AsSpan(0, plaintextBytes),
                    input.AsSpan(plaintextBytes, tagBytes), output.AsSpan(0, plaintextBytes), associatedData);
                destination.Write(output.AsSpan(0, plaintextBytes));

                if (isLast)
                {
                    break;
                }

                input[0] = input[wireSegmentBytes];
                carried = 1;
                index++;
            }

            destination.Flush();
        }
        finally
        {
            CryptographicOperations.ZeroMemory(input);
            CryptographicOperations.ZeroMemory(output);
        }
    }

    // Reads until buffer holds wantedBytes or the source ends. The first `carried` bytes are kept from the last segment.
    private static int FillSegment(Stream source, byte[] buffer, int carried, int wantedBytes)
    {
        int missing = wantedBytes - carried;
        return carried + source.ReadAtLeast(buffer.AsSpan(carried, missing), missing, throwOnEndOfStream: false);
    }

    // Rejects framing the encryptor never produces. Checked before the tag, so no plaintext is decrypted for them.
    private static void ThrowIfBadFraming(bool isLast, int wireBytes, int tagBytes, uint index)
    {
        bool shortFinal = isLast && wireBytes < tagBytes;
        bool emptyFinalAfterFirst = isLast && wireBytes == tagBytes && index != 0;
        bool nonFinalAtLastIndex = !isLast && index == uint.MaxValue;
        if (shortFinal || emptyFinalAfterFirst || nonFinalAtLastIndex)
        {
            throw new CryptographicException(DecryptFailure.Message);
        }
    }

    private static void Validate(
        MkvGcm gcm, ReadOnlySpan<byte> noncePrefix, Stream source, Stream destination, int segmentSizeBytes)
    {
        ArgumentNullException.ThrowIfNull(gcm);
        ArgumentNullException.ThrowIfNull(source);
        ArgumentNullException.ThrowIfNull(destination);
        if (noncePrefix.Length != MkvGcm.StreamNoncePrefixBytes)
        {
            throw new ArgumentException($"Expected {MkvGcm.StreamNoncePrefixBytes} bytes.", nameof(noncePrefix));
        }

        if (segmentSizeBytes < MinSegmentSizeBytes || segmentSizeBytes > MaxSegmentSizeBytes)
        {
            throw new ArgumentOutOfRangeException(
                nameof(segmentSizeBytes), $"Expected {MinSegmentSizeBytes} to {MaxSegmentSizeBytes} bytes.");
        }

        if (!source.CanRead)
        {
            throw new ArgumentException("The source stream must be readable.", nameof(source));
        }

        if (!destination.CanWrite)
        {
            throw new ArgumentException("The destination stream must be writable.", nameof(destination));
        }
    }
}
