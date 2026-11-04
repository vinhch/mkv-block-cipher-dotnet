using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;

namespace MkvBlockCipher.Modes;

// XOR for CTR keystream and CBC chains. Destination may be the same span as left or right; partial overlap is not supported.
internal static class ByteXor
{
    internal static void Xor(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right, Span<byte> destination)
    {
        if (right.Length != left.Length)
        {
            throw new ArgumentException("Right operand must match the left operand length.", nameof(right));
        }

        if (destination.Length != left.Length)
        {
            throw new ArgumentException("Destination must match the operand length.", nameof(destination));
        }

        // Lengths are equal, so the unchecked loads and stores below stay inside all three spans.
        // Each vector loads both operands before its store, which keeps the in-place cases correct.
        int offset = 0;
        if (Vector256.IsHardwareAccelerated)
        {
            for (; offset + Vector256<byte>.Count <= left.Length; offset += Vector256<byte>.Count)
            {
                Vector256<byte> xored = Vector256.LoadUnsafe(ref MemoryMarshal.GetReference(left), (nuint)offset)
                    ^ Vector256.LoadUnsafe(ref MemoryMarshal.GetReference(right), (nuint)offset);
                xored.StoreUnsafe(ref MemoryMarshal.GetReference(destination), (nuint)offset);
            }
        }

        if (Vector128.IsHardwareAccelerated)
        {
            for (; offset + Vector128<byte>.Count <= left.Length; offset += Vector128<byte>.Count)
            {
                Vector128<byte> xored = Vector128.LoadUnsafe(ref MemoryMarshal.GetReference(left), (nuint)offset)
                    ^ Vector128.LoadUnsafe(ref MemoryMarshal.GetReference(right), (nuint)offset);
                xored.StoreUnsafe(ref MemoryMarshal.GetReference(destination), (nuint)offset);
            }
        }

        for (; offset < left.Length; offset++)
        {
            destination[offset] = (byte)(left[offset] ^ right[offset]);
        }
    }
}
