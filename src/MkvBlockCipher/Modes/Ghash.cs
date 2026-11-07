using System.Buffers.Binary;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;
using System.Security.Cryptography;

namespace MkvBlockCipher.Modes;

// GHASH over GF(2^128) as SP 800-38D defines it: the field element of a block has its bit 0 (x^0) in the most significant
// bit of byte 0. Both paths compute the same function; the software path needs no CPU feature and no table.
internal static class Ghash
{
    private const int BlockBytes = 16;

    internal static void Compute(ReadOnlySpan<byte> h, ReadOnlySpan<byte> associatedData, ReadOnlySpan<byte> ciphertext, Span<byte> output)
    {
        if (Pclmulqdq.IsSupported)
        {
            ComputePclmul(h, associatedData, ciphertext, output);
        }
        else
        {
            ComputeSoftware(h, associatedData, ciphertext, output);
        }
    }

    internal static void ComputeSoftware(ReadOnlySpan<byte> h, ReadOnlySpan<byte> associatedData, ReadOnlySpan<byte> ciphertext, Span<byte> output)
    {
        Hash(h, associatedData, ciphertext, output, usePclmul: false);
    }

    internal static void ComputePclmul(ReadOnlySpan<byte> h, ReadOnlySpan<byte> associatedData, ReadOnlySpan<byte> ciphertext, Span<byte> output)
    {
        Hash(h, associatedData, ciphertext, output, usePclmul: true);
    }

    // Output is written last, so it may overlap the inputs.
    private static void Hash(
        ReadOnlySpan<byte> h, ReadOnlySpan<byte> associatedData, ReadOnlySpan<byte> ciphertext, Span<byte> output, bool usePclmul)
    {
        RequireLength(h, nameof(h));
        RequireLength(output, nameof(output));

        Span<byte> state = stackalloc byte[BlockBytes];
        Span<byte> block = stackalloc byte[BlockBytes];
        AbsorbPadded(h, associatedData, state, block, usePclmul);
        AbsorbPadded(h, ciphertext, state, block, usePclmul);

        BinaryPrimitives.WriteUInt64BigEndian(block, (ulong)associatedData.Length * 8);
        BinaryPrimitives.WriteUInt64BigEndian(block.Slice(8), (ulong)ciphertext.Length * 8);
        Absorb(h, block, state, usePclmul);

        state.CopyTo(output);
        CryptographicOperations.ZeroMemory(state);
        CryptographicOperations.ZeroMemory(block);
    }

    private static void AbsorbPadded(
        ReadOnlySpan<byte> h, ReadOnlySpan<byte> data, Span<byte> state, Span<byte> block, bool usePclmul)
    {
        int wholeBlocksLength = data.Length - data.Length % BlockBytes;
        for (int offset = 0; offset < wholeBlocksLength; offset += BlockBytes)
        {
            Absorb(h, data.Slice(offset, BlockBytes), state, usePclmul);
        }

        if (wholeBlocksLength < data.Length)
        {
            block.Clear();
            data.Slice(wholeBlocksLength).CopyTo(block);
            Absorb(h, block, state, usePclmul);
        }
    }

    private static void Absorb(ReadOnlySpan<byte> h, ReadOnlySpan<byte> block, Span<byte> state, bool usePclmul)
    {
        ByteXor.Xor(state, block, state);
        if (usePclmul)
        {
            MultiplyPclmul(h, state);
        }
        else
        {
            MultiplySoftware(h, state);
        }
    }

    private static void MultiplySoftware(ReadOnlySpan<byte> h, Span<byte> y)
    {
        Span<uint> hLimbs = stackalloc uint[4];
        Span<uint> yLimbs = stackalloc uint[4];
        Span<uint> product = stackalloc uint[8];
        LoadNormal(h, hLimbs);
        LoadNormal(y, yLimbs);

        for (int i = 0; i < 4; i++)
        {
            for (int j = 0; j < 4; j++)
            {
                ulong term = Clmul32(yLimbs[i], hLimbs[j]);
                product[i + j] ^= (uint)term;
                product[i + j + 1] ^= (uint)(term >> 32);
            }
        }

        UInt128 reduced = Reduce(Pack(product.Slice(0, 4)), Pack(product.Slice(4, 4)));
        Unpack(reduced, yLimbs);
        StoreNormal(yLimbs, y);

        CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(hLimbs));
        CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(yLimbs));
        CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(product));
    }

    // Carry-less 32x32 product from integer multiplies. Operand bits are split by position mod 4, so each integer product
    // holds at most 8 terms per column. A column's sum fits in the 4 bits above its position, so no carry reaches the next
    // column, and bit k of a product is the parity of column k. XOR then combines the products without losing parity.
    private static ulong Clmul32(uint x, uint y)
    {
        ulong x0 = x & 0x11111111u;
        ulong x1 = x & 0x22222222u;
        ulong x2 = x & 0x44444444u;
        ulong x3 = x & 0x88888888u;
        ulong y0 = y & 0x11111111u;
        ulong y1 = y & 0x22222222u;
        ulong y2 = y & 0x44444444u;
        ulong y3 = y & 0x88888888u;

        ulong z0 = (x0 * y0) ^ (x1 * y3) ^ (x2 * y2) ^ (x3 * y1);
        ulong z1 = (x0 * y1) ^ (x1 * y0) ^ (x2 * y3) ^ (x3 * y2);
        ulong z2 = (x0 * y2) ^ (x1 * y1) ^ (x2 * y0) ^ (x3 * y3);
        ulong z3 = (x0 * y3) ^ (x1 * y2) ^ (x2 * y1) ^ (x3 * y0);

        return (z0 & 0x1111111111111111ul)
            | (z1 & 0x2222222222222222ul)
            | (z2 & 0x4444444444444444ul)
            | (z3 & 0x8888888888888888ul);
    }

    // Reduction modulo x^128 + x^7 + x^2 + x + 1. Each shifted-out term above x^127 folds back as a degree below 7 term.
    private static UInt128 Reduce(UInt128 low, UInt128 high)
    {
        UInt128 overflow = (high >> 127) ^ (high >> 126) ^ (high >> 121);
        low ^= high ^ (high << 1) ^ (high << 2) ^ (high << 7);
        return low ^ overflow ^ (overflow << 1) ^ (overflow << 2) ^ (overflow << 7);
    }

    // Each 32-bit word is reversed so bit i of the element is x^i: the first word of the block holds x^0 to x^31.
    private static void LoadNormal(ReadOnlySpan<byte> block, Span<uint> limbs)
    {
        for (int k = 0; k < 4; k++)
        {
            limbs[k] = ReverseBits(BinaryPrimitives.ReadUInt32BigEndian(block.Slice(4 * k)));
        }
    }

    private static void StoreNormal(ReadOnlySpan<uint> limbs, Span<byte> block)
    {
        for (int k = 0; k < 4; k++)
        {
            BinaryPrimitives.WriteUInt32BigEndian(block.Slice(4 * k), ReverseBits(limbs[k]));
        }
    }

    private static UInt128 Pack(ReadOnlySpan<uint> limbs) =>
        limbs[0] | ((UInt128)limbs[1] << 32) | ((UInt128)limbs[2] << 64) | ((UInt128)limbs[3] << 96);

    private static void Unpack(UInt128 value, Span<uint> limbs)
    {
        for (int k = 0; k < 4; k++)
        {
            limbs[k] = (uint)(value >> (32 * k));
        }
    }

    private static uint ReverseBits(uint value)
    {
        value = ((value >> 1) & 0x55555555u) | ((value & 0x55555555u) << 1);
        value = ((value >> 2) & 0x33333333u) | ((value & 0x33333333u) << 2);
        value = ((value >> 4) & 0x0F0F0F0Fu) | ((value & 0x0F0F0F0Fu) << 4);
        value = ((value >> 8) & 0x00FF00FFu) | ((value & 0x00FF00FFu) << 8);
        return (value >> 16) | (value << 16);
    }

    private static void MultiplyPclmul(ReadOnlySpan<byte> h, Span<byte> y)
    {
        Vector128<ulong> product = MultiplyReflected(LoadReflected(y), LoadReflected(h));
        BinaryPrimitives.WriteUInt64BigEndian(y, product.GetElement(1));
        BinaryPrimitives.WriteUInt64BigEndian(y.Slice(8), product.GetElement(0));
    }

    // Lane 0 holds bytes 8 to 15 as a big-endian integer, the byte-reversed layout the reflected multiply expects.
    private static Vector128<ulong> LoadReflected(ReadOnlySpan<byte> block) =>
        Vector128.Create(BinaryPrimitives.ReadUInt64BigEndian(block.Slice(8)), BinaryPrimitives.ReadUInt64BigEndian(block));

    // Reflected product: the 256-bit carry-less product is shifted left by one bit, then reduced in two folds.
    private static Vector128<ulong> MultiplyReflected(Vector128<ulong> a, Vector128<ulong> b)
    {
        Vector128<ulong> low = Pclmulqdq.CarrylessMultiply(a, b, 0x00);
        Vector128<ulong> middle = Pclmulqdq.CarrylessMultiply(a, b, 0x10) ^ Pclmulqdq.CarrylessMultiply(a, b, 0x01);
        Vector128<ulong> high = Pclmulqdq.CarrylessMultiply(a, b, 0x11);
        low ^= Sse2.ShiftLeftLogical128BitLane(middle, 8);
        high ^= Sse2.ShiftRightLogical128BitLane(middle, 8);

        Vector128<uint> lowWords = low.AsUInt32();
        Vector128<uint> highWords = high.AsUInt32();
        Vector128<uint> lowCarry = Sse2.ShiftRightLogical(lowWords, 31);
        Vector128<uint> highCarry = Sse2.ShiftRightLogical(highWords, 31);
        lowWords = Sse2.ShiftLeftLogical(lowWords, 1) | Sse2.ShiftLeftLogical128BitLane(lowCarry, 4);
        highWords = Sse2.ShiftLeftLogical(highWords, 1)
            | Sse2.ShiftLeftLogical128BitLane(highCarry, 4)
            | Sse2.ShiftRightLogical128BitLane(lowCarry, 12);

        Vector128<uint> foldOne = Sse2.ShiftLeftLogical(lowWords, 31)
            ^ Sse2.ShiftLeftLogical(lowWords, 30)
            ^ Sse2.ShiftLeftLogical(lowWords, 25);
        Vector128<uint> foldOneCarry = Sse2.ShiftRightLogical128BitLane(foldOne, 4);
        lowWords ^= Sse2.ShiftLeftLogical128BitLane(foldOne, 12);

        Vector128<uint> foldTwo = Sse2.ShiftRightLogical(lowWords, 1)
            ^ Sse2.ShiftRightLogical(lowWords, 2)
            ^ Sse2.ShiftRightLogical(lowWords, 7)
            ^ foldOneCarry;
        lowWords ^= foldTwo;

        return (highWords ^ lowWords).AsUInt64();
    }

    private static void RequireLength(ReadOnlySpan<byte> value, string paramName)
    {
        if (value.Length != BlockBytes)
        {
            throw new ArgumentException("Expected 16 bytes.", paramName);
        }
    }
}
