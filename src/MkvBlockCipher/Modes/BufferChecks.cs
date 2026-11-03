namespace MkvBlockCipher.Modes;

internal static class BufferChecks
{
    // A shared start is in-place use. Any other overlap lets a write clobber input that is still to be read.
    internal static void ThrowIfPartialOverlap(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, string paramName)
    {
        if (MemoryExtensions.Overlaps(a, b, out int offset) && offset != 0)
        {
            throw new ArgumentException("Input and output partially overlap.", paramName);
        }
    }
}
