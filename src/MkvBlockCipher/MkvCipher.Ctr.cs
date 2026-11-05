using MkvBlockCipher.Modes;

namespace MkvBlockCipher;

public sealed partial class MkvCipher
{
    /// <summary>
    /// XORs <paramref name="source"/> with the CTR keystream and writes the result to <paramref name="destination"/>.
    /// Keystream block i is the block cipher applied to <paramref name="initialCounter"/> plus i, the counter read
    /// as one big-endian integer over the whole block. Encrypting and decrypting are the same call. A partial last
    /// block uses the start of its keystream block. The source and the destination may start at the same offset for
    /// in-place use; partial overlap is rejected. Reusing an initial counter with the same key for two messages
    /// reveals the XOR of their plaintexts.
    /// </summary>
    /// <param name="initialCounter"><see cref="BlockSizeBytes"/> bytes.</param>
    /// <param name="source">Data to transform. Any length, including zero.</param>
    /// <param name="destination">
    /// Receives the transformed bytes. Must hold at least <paramref name="source"/> bytes; any extra bytes are
    /// left untouched.
    /// </param>
    /// <exception cref="ObjectDisposedException">The instance has been disposed.</exception>
    /// <exception cref="ArgumentException">
    /// <paramref name="initialCounter"/> has the wrong length, <paramref name="destination"/> is shorter than
    /// <paramref name="source"/>, the spans partially overlap, or the counter would wrap past all-ones. Nothing
    /// is written in these cases.
    /// </exception>
    public void TransformCtr(ReadOnlySpan<byte> initialCounter, ReadOnlySpan<byte> source, Span<byte> destination)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (initialCounter.Length != BlockSizeBytes)
        {
            throw new ArgumentException($"Expected {BlockSizeBytes} bytes.", nameof(initialCounter));
        }

        if (destination.Length < source.Length)
        {
            throw new ArgumentException("Destination is shorter than the source.", nameof(destination));
        }

        BufferChecks.ThrowIfPartialOverlap(source, destination, nameof(destination));
        Ctr.Transform(Engine, RoundKeys, initialCounter, source, destination);
    }

    /// <summary>
    /// Returns the CTR transform of <paramref name="source"/> in a new array of the same length.
    /// </summary>
    /// <param name="initialCounter"><see cref="BlockSizeBytes"/> bytes.</param>
    /// <param name="source">Data to transform. Any length, including zero.</param>
    /// <returns>The transformed bytes.</returns>
    /// <exception cref="ObjectDisposedException">The instance has been disposed.</exception>
    /// <exception cref="ArgumentException">
    /// <paramref name="initialCounter"/> has the wrong length, or the counter would wrap past all-ones.
    /// </exception>
    public byte[] TransformCtr(ReadOnlySpan<byte> initialCounter, ReadOnlySpan<byte> source)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        byte[] destination = new byte[source.Length];
        TransformCtr(initialCounter, source, destination);
        return destination;
    }
}
