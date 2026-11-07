using System.Buffers.Binary;
using System.Security.Cryptography;
using MkvBlockCipher.Kernels;

namespace MkvBlockCipher.Modes;

// IEEE 1619 XTS over one data unit, 128-bit blocks. The tweak is E(tweak key, unit as 16 little-endian bytes) and is
// doubled in GF(2^128) per block. A final partial block uses ciphertext stealing (IEEE 1619 section 5.3). Callers
// check lengths and overlap first.
internal static class Xts
{
    private const int BlockBytes = 16;

    internal static void Encrypt(
        BlockEngine engine,
        ReadOnlySpan<byte> dataRoundKeys,
        ReadOnlySpan<byte> tweakRoundKeys,
        ulong dataUnitNumber,
        ReadOnlySpan<byte> source,
        Span<byte> destination)
    {
        Span<byte> tweak = stackalloc byte[BlockBytes];
        InitialTweak(engine, tweakRoundKeys, dataUnitNumber, tweak);

        int tailLength = source.Length % BlockBytes;
        int bulkLength = BulkLength(source.Length, tailLength);
        Crypt(engine, dataRoundKeys, tweak, source.Slice(0, bulkLength), destination.Slice(0, bulkLength), decrypt: false);
        if (tailLength != 0)
        {
            StealEncrypt(engine, dataRoundKeys, tweak, source, destination, tailLength);
        }

        CryptographicOperations.ZeroMemory(tweak);
    }

    internal static void Decrypt(
        BlockEngine engine,
        ReadOnlySpan<byte> dataRoundKeys,
        ReadOnlySpan<byte> tweakRoundKeys,
        ulong dataUnitNumber,
        ReadOnlySpan<byte> source,
        Span<byte> destination)
    {
        Span<byte> tweak = stackalloc byte[BlockBytes];
        InitialTweak(engine, tweakRoundKeys, dataUnitNumber, tweak);

        int tailLength = source.Length % BlockBytes;
        int bulkLength = BulkLength(source.Length, tailLength);
        Crypt(engine, dataRoundKeys, tweak, source.Slice(0, bulkLength), destination.Slice(0, bulkLength), decrypt: true);
        if (tailLength != 0)
        {
            StealDecrypt(engine, dataRoundKeys, tweak, source, destination, tailLength);
        }

        CryptographicOperations.ZeroMemory(tweak);
    }

    // With a partial tail, the last full block goes through stealing, so the bulk stops one block earlier.
    private static int BulkLength(int length, int tailLength)
    {
        int fullBlocks = length / BlockBytes;
        return (tailLength == 0 ? fullBlocks : fullBlocks - 1) * BlockBytes;
    }

    // Advances tweak past the bulk: on return it holds the tweak of the first block after it.
    private static void Crypt(
        BlockEngine engine,
        ReadOnlySpan<byte> roundKeys,
        Span<byte> tweak,
        ReadOnlySpan<byte> source,
        Span<byte> destination,
        bool decrypt)
    {
        Span<byte> tweaks = stackalloc byte[engine.BatchBlocks * BlockBytes];
        for (int offset = 0; offset < source.Length;)
        {
            int batchLength = Math.Min(tweaks.Length, source.Length - offset);
            Span<byte> batchTweaks = tweaks.Slice(0, batchLength);
            FillTweaks(tweak, batchTweaks);

            Span<byte> batch = destination.Slice(offset, batchLength);
            ByteXor.Xor(source.Slice(offset, batchLength), batchTweaks, batch);
            if (decrypt)
            {
                engine.DecryptBlocks(roundKeys, batch, batch);
            }
            else
            {
                engine.EncryptBlocks(roundKeys, batch, batch);
            }

            ByteXor.Xor(batch, batchTweaks, batch);
            offset += batchLength;
        }

        CryptographicOperations.ZeroMemory(tweaks);
    }

    // Writes the tweaks for a batch in order, doubling tweak after each one.
    private static void FillTweaks(Span<byte> tweak, Span<byte> batchTweaks)
    {
        for (int offset = 0; offset < batchTweaks.Length; offset += BlockBytes)
        {
            tweak.CopyTo(batchTweaks.Slice(offset, BlockBytes));
            Double(tweak);
        }
    }

    // CC = E(P[n-1] ^ T[n-1]) ^ T[n-1]; PP = P[n] || CC[tail..]; C[n-1] = E(PP ^ T[n]) ^ T[n]; C[n] = CC[..tail].
    private static void StealEncrypt(
        BlockEngine engine,
        ReadOnlySpan<byte> roundKeys,
        ReadOnlySpan<byte> penultimateTweak,
        ReadOnlySpan<byte> source,
        Span<byte> destination,
        int tailLength)
    {
        int penultimateOffset = source.Length - tailLength - BlockBytes;
        int tailOffset = source.Length - tailLength;

        Span<byte> lastTweak = stackalloc byte[BlockBytes];
        Span<byte> chained = stackalloc byte[BlockBytes];
        Span<byte> padded = stackalloc byte[BlockBytes];
        penultimateTweak.CopyTo(lastTweak);
        Double(lastTweak);

        ProcessBlock(engine, roundKeys, source.Slice(penultimateOffset, BlockBytes), penultimateTweak, chained, decrypt: false);

        source.Slice(tailOffset, tailLength).CopyTo(padded);
        chained.Slice(tailLength).CopyTo(padded.Slice(tailLength));
        ProcessBlock(engine, roundKeys, padded, lastTweak, destination.Slice(penultimateOffset, BlockBytes), decrypt: false);
        chained.Slice(0, tailLength).CopyTo(destination.Slice(tailOffset, tailLength));

        CryptographicOperations.ZeroMemory(lastTweak);
        CryptographicOperations.ZeroMemory(chained);
        CryptographicOperations.ZeroMemory(padded);
    }

    // PP = D(C[n-1] ^ T[n]) ^ T[n]; CC = C[n] || PP[tail..]; P[n-1] = D(CC ^ T[n-1]) ^ T[n-1]; P[n] = PP[..tail].
    private static void StealDecrypt(
        BlockEngine engine,
        ReadOnlySpan<byte> roundKeys,
        ReadOnlySpan<byte> penultimateTweak,
        ReadOnlySpan<byte> source,
        Span<byte> destination,
        int tailLength)
    {
        int penultimateOffset = source.Length - tailLength - BlockBytes;
        int tailOffset = source.Length - tailLength;

        Span<byte> lastTweak = stackalloc byte[BlockBytes];
        Span<byte> padded = stackalloc byte[BlockBytes];
        Span<byte> chained = stackalloc byte[BlockBytes];
        penultimateTweak.CopyTo(lastTweak);
        Double(lastTweak);

        ProcessBlock(engine, roundKeys, source.Slice(penultimateOffset, BlockBytes), lastTweak, padded, decrypt: true);

        source.Slice(tailOffset, tailLength).CopyTo(chained);
        padded.Slice(tailLength).CopyTo(chained.Slice(tailLength));
        ProcessBlock(engine, roundKeys, chained, penultimateTweak, chained, decrypt: true);

        // Every source read is done, so the writes cannot clobber input still to be read.
        padded.Slice(0, tailLength).CopyTo(destination.Slice(tailOffset, tailLength));
        chained.CopyTo(destination.Slice(penultimateOffset, BlockBytes));

        CryptographicOperations.ZeroMemory(lastTweak);
        CryptographicOperations.ZeroMemory(padded);
        CryptographicOperations.ZeroMemory(chained);
    }

    // output = E or D (input ^ tweak) ^ tweak for one block. Input and output may be the same span.
    private static void ProcessBlock(
        BlockEngine engine,
        ReadOnlySpan<byte> roundKeys,
        ReadOnlySpan<byte> input,
        ReadOnlySpan<byte> tweak,
        Span<byte> output,
        bool decrypt)
    {
        Span<byte> block = stackalloc byte[BlockBytes];
        ByteXor.Xor(input, tweak, block);
        if (decrypt)
        {
            engine.DecryptBlocks(roundKeys, block, block);
        }
        else
        {
            engine.EncryptBlocks(roundKeys, block, block);
        }

        ByteXor.Xor(block, tweak, output);
        CryptographicOperations.ZeroMemory(block);
    }

    private static void InitialTweak(BlockEngine engine, ReadOnlySpan<byte> tweakRoundKeys, ulong dataUnitNumber, Span<byte> tweak)
    {
        Span<byte> unit = stackalloc byte[BlockBytes];
        BinaryPrimitives.WriteUInt64LittleEndian(unit, dataUnitNumber);
        engine.EncryptBlocks(tweakRoundKeys, unit, tweak);
    }

    // Multiplies by x in GF(2^128) on little-endian bytes. The reduction is 0x87 or 0, taken from the top bit by
    // negation, so the update has no branch on tweak bytes.
    private static void Double(Span<byte> tweak)
    {
        byte reduction = (byte)((0 - (tweak[^1] >> 7)) & 0x87);
        for (int i = tweak.Length - 1; i > 0; i--)
        {
            tweak[i] = (byte)((tweak[i] << 1) | (tweak[i - 1] >> 7));
        }

        tweak[0] = (byte)((tweak[0] << 1) ^ reduction);
    }
}
