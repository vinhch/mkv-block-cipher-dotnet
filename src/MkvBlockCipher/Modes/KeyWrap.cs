using System.Buffers.Binary;
using System.Security.Cryptography;
using MkvBlockCipher.Kernels;

namespace MkvBlockCipher.Modes;

// Key wrap over a block engine: W and W^-1 of NIST SP 800-38F (KW, RFC 3394) and the padded form of RFC 5649 (KWP).
// Stack scratch is fixed-size locals (an 8-byte A value, an 8-byte counter and one 16-byte block), never sized by
// the input. Callers check lengths, overlap and the block size first.
internal static class KeyWrap
{
    private const int SemiblockBytes = 8;

    // The six rounds of W and W^-1 (RFC 3394 section 2.2.1).
    private const int Rounds = 6;

    // RFC 3394 section 2.2.3: the KW initial value.
    internal static ReadOnlySpan<byte> KwInitialValue => [0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6];

    // RFC 5649 section 3: the fixed high half of the alternative initial value.
    private static ReadOnlySpan<byte> PaddingPrefix => [0xA6, 0x59, 0x59, 0xA6];

    // Plaintext is a whole number of semiblocks, at least two. Destination is plaintext.Length + 8 bytes and may start
    // at the plaintext's start.
    internal static void Wrap(
        BlockEngine engine,
        ReadOnlySpan<byte> roundKeys,
        ReadOnlySpan<byte> initialValue,
        ReadOnlySpan<byte> plaintext,
        Span<byte> destination)
    {
        // Overlap-safe: an in-place plaintext starts at destination[0] and moves to offset 8.
        plaintext.CopyTo(destination.Slice(SemiblockBytes));
        WrapInPlace(engine, roundKeys, initialValue, destination);
    }

    // Plaintext is 1 or more bytes; destination is GetKeyWrapPaddedLength bytes and may start at the plaintext's start.
    // The initial value carries only the public length, so it is not zeroed.
    internal static void WrapPadded(
        BlockEngine engine,
        ReadOnlySpan<byte> roundKeys,
        ReadOnlySpan<byte> plaintext,
        Span<byte> destination)
    {
        Span<byte> initialValue = stackalloc byte[SemiblockBytes];
        PaddingPrefix.CopyTo(initialValue);
        BinaryPrimitives.WriteUInt32BigEndian(initialValue.Slice(4), (uint)plaintext.Length);

        if (destination.Length == 2 * SemiblockBytes)
        {
            WrapSingleBlock(engine, roundKeys, initialValue, plaintext, destination);
            return;
        }

        plaintext.CopyTo(destination.Slice(SemiblockBytes, plaintext.Length));
        destination.Slice(SemiblockBytes + plaintext.Length).Clear();
        WrapInPlace(engine, roundKeys, initialValue, destination);
    }

    // Unwraps W^-1 into destination, which receives the semiblocks after the A value. Returns false, writing nothing,
    // unless ciphertext is a whole number of semiblocks, at least three. recoveredValue receives the A value; the
    // caller compares it with the initial value it expects.
    internal static bool TryUnwrap(
        BlockEngine engine,
        ReadOnlySpan<byte> roundKeys,
        ReadOnlySpan<byte> ciphertext,
        Span<byte> destination,
        Span<byte> recoveredValue)
    {
        if (ciphertext.Length % SemiblockBytes != 0 || ciphertext.Length < 3 * SemiblockBytes)
        {
            return false;
        }

        UnwrapSemiblocks(engine, roundKeys, ciphertext, destination, recoveredValue);
        return true;
    }

    // KWP unwrap (RFC 5649 section 4.2). Ciphertext is a whole number of semiblocks, at least two. Writes the padded
    // plaintext to destination, which the caller zeroes when the check fails. Returns whether the integrity check
    // passed; plaintextLength is the MLI, meaningful only on true.
    internal static bool TryUnwrapPadded(
        BlockEngine engine,
        ReadOnlySpan<byte> roundKeys,
        ReadOnlySpan<byte> ciphertext,
        Span<byte> destination,
        out int plaintextLength)
    {
        int blockCount = (ciphertext.Length - SemiblockBytes) / SemiblockBytes;
        int paddedLength = blockCount * SemiblockBytes;
        Span<byte> recoveredValue = stackalloc byte[SemiblockBytes];

        if (blockCount == 1)
        {
            // A single semiblock is one block decryption, not the W^-1 rounds.
            Span<byte> block = stackalloc byte[2 * SemiblockBytes];
            engine.DecryptBlocks(roundKeys, ciphertext, block);
            block.Slice(0, SemiblockBytes).CopyTo(recoveredValue);
            block.Slice(SemiblockBytes).CopyTo(destination);
            CryptographicOperations.ZeroMemory(block);
        }
        else
        {
            UnwrapSemiblocks(engine, roundKeys, ciphertext, destination, recoveredValue);
        }

        // Every check runs before the one decision, so no early exit depends on the unwrapped bytes.
        // The MLI range check is plain comparisons combined with `&`; the sign mask is used only in the padding loop.
        long mli = BinaryPrimitives.ReadUInt32BigEndian(recoveredValue.Slice(4));
        bool prefixOk = CryptographicOperations.FixedTimeEquals(recoveredValue.Slice(0, 4), PaddingPrefix);
        bool lengthOk = (mli > SemiblockBytes * (long)(blockCount - 1)) & (mli <= paddedLength);

        byte paddingBits = 0;
        for (int offset = 0; offset < paddedLength; offset++)
        {
            // 0xFF from the MLI onward, 0x00 before it.
            byte fromMli = (byte)~(int)(((long)offset - mli) >> 63);
            paddingBits |= (byte)(destination[offset] & fromMli);
        }

        plaintextLength = (int)mli;
        CryptographicOperations.ZeroMemory(recoveredValue);
        return prefixOk & lengthOk & (paddingBits == 0);
    }

    private static void WrapSingleBlock(
        BlockEngine engine,
        ReadOnlySpan<byte> roundKeys,
        ReadOnlySpan<byte> initialValue,
        ReadOnlySpan<byte> plaintext,
        Span<byte> destination)
    {
        // The plaintext is copied before destination is written, so in-place use is safe.
        Span<byte> block = stackalloc byte[2 * SemiblockBytes];
        initialValue.CopyTo(block);
        plaintext.CopyTo(block.Slice(SemiblockBytes));
        block.Slice(SemiblockBytes + plaintext.Length).Clear();
        engine.EncryptBlocks(roundKeys, block, destination);
        CryptographicOperations.ZeroMemory(block);
    }

    // W over destination: the A value starts as initialValue and ends in destination[0..8); semiblock i is at 8i.
    private static void WrapInPlace(
        BlockEngine engine,
        ReadOnlySpan<byte> roundKeys,
        ReadOnlySpan<byte> initialValue,
        Span<byte> destination)
    {
        int blockCount = (destination.Length - SemiblockBytes) / SemiblockBytes;
        Span<byte> a = stackalloc byte[SemiblockBytes];
        Span<byte> counter = stackalloc byte[SemiblockBytes];
        Span<byte> block = stackalloc byte[2 * SemiblockBytes];
        initialValue.CopyTo(a);

        for (int round = 0; round < Rounds; round++)
        {
            for (int i = 1; i <= blockCount; i++)
            {
                a.CopyTo(block);
                destination.Slice(SemiblockBytes * i, SemiblockBytes).CopyTo(block.Slice(SemiblockBytes));
                engine.EncryptBlocks(roundKeys, block, block);

                block.Slice(0, SemiblockBytes).CopyTo(a);
                BinaryPrimitives.WriteUInt64BigEndian(counter, (ulong)blockCount * (ulong)round + (ulong)i);
                ByteXor.Xor(a, counter, a);
                block.Slice(SemiblockBytes).CopyTo(destination.Slice(SemiblockBytes * i, SemiblockBytes));
            }
        }

        a.CopyTo(destination);
        CryptographicOperations.ZeroMemory(a);
        CryptographicOperations.ZeroMemory(block);
    }

    // W^-1 over ciphertext, which may start where destination starts. The A value is copied out first, because the
    // semiblocks land at destination[0] and would overwrite it.
    private static void UnwrapSemiblocks(
        BlockEngine engine,
        ReadOnlySpan<byte> roundKeys,
        ReadOnlySpan<byte> ciphertext,
        Span<byte> destination,
        Span<byte> recoveredValue)
    {
        int blockCount = (ciphertext.Length - SemiblockBytes) / SemiblockBytes;
        ciphertext.Slice(0, SemiblockBytes).CopyTo(recoveredValue);
        ciphertext.Slice(SemiblockBytes, SemiblockBytes * blockCount).CopyTo(destination);

        Span<byte> counter = stackalloc byte[SemiblockBytes];
        Span<byte> block = stackalloc byte[2 * SemiblockBytes];
        for (int round = Rounds - 1; round >= 0; round--)
        {
            for (int i = blockCount; i >= 1; i--)
            {
                BinaryPrimitives.WriteUInt64BigEndian(counter, (ulong)blockCount * (ulong)round + (ulong)i);
                ByteXor.Xor(recoveredValue, counter, block.Slice(0, SemiblockBytes));
                destination.Slice(SemiblockBytes * (i - 1), SemiblockBytes).CopyTo(block.Slice(SemiblockBytes));
                engine.DecryptBlocks(roundKeys, block, block);

                block.Slice(0, SemiblockBytes).CopyTo(recoveredValue);
                block.Slice(SemiblockBytes).CopyTo(destination.Slice(SemiblockBytes * (i - 1), SemiblockBytes));
            }
        }

        CryptographicOperations.ZeroMemory(block);
    }
}
