using System.Security.Cryptography;
using MkvBlockCipher.Kernels;

namespace MkvBlockCipher.Modes;

// CCM over one block cipher, formatted as SP 800-38C Appendix A. The CBC-MAC runs over B0, the encoded associated data
// and the payload; the keystream starts at A1 and the tag mask is E(A0). Callers check lengths, the payload limit and overlap.
internal static class Ccm
{
    private const int BlockBytes = 16;

    // The MAC reads the plaintext before the keystream overwrites it, so in-place encryption authenticates the input.
    internal static void Encrypt(
        BlockEngine engine,
        ReadOnlySpan<byte> roundKeys,
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> plaintext,
        Span<byte> ciphertext,
        Span<byte> tag,
        ReadOnlySpan<byte> associatedData)
    {
        Span<byte> mac = stackalloc byte[BlockBytes];
        Span<byte> counter = stackalloc byte[BlockBytes];
        ComputeMac(engine, roundKeys, nonce, plaintext, tag.Length, associatedData, mac);
        FormatCounter(nonce, 1, counter);
        Ctr.Transform(engine, roundKeys, counter, plaintext, ciphertext);
        ComputeTag(engine, roundKeys, nonce, mac, tag);
        CryptographicOperations.ZeroMemory(mac);
        CryptographicOperations.ZeroMemory(counter);
    }

    // Decrypts first, then checks the tag over the recovered plaintext. Returns false, with plaintext holding the
    // unverified output, when the tag differs; the caller zeroes it.
    internal static bool Decrypt(
        BlockEngine engine,
        ReadOnlySpan<byte> roundKeys,
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> ciphertext,
        ReadOnlySpan<byte> tag,
        Span<byte> plaintext,
        ReadOnlySpan<byte> associatedData)
    {
        Span<byte> mac = stackalloc byte[BlockBytes];
        Span<byte> counter = stackalloc byte[BlockBytes];
        Span<byte> expectedTag = stackalloc byte[BlockBytes];
        FormatCounter(nonce, 1, counter);
        Ctr.Transform(engine, roundKeys, counter, ciphertext, plaintext);
        ComputeMac(engine, roundKeys, nonce, plaintext, tag.Length, associatedData, mac);
        ComputeTag(engine, roundKeys, nonce, mac, expectedTag.Slice(0, tag.Length));
        bool tagMatches = CryptographicOperations.FixedTimeEquals(expectedTag.Slice(0, tag.Length), tag);
        CryptographicOperations.ZeroMemory(mac);
        CryptographicOperations.ZeroMemory(counter);
        CryptographicOperations.ZeroMemory(expectedTag);
        return tagMatches;
    }

    // X_1 = E(B0), then the encoded AAD and the payload, each zero-padded to whole blocks.
    private static void ComputeMac(
        BlockEngine engine,
        ReadOnlySpan<byte> roundKeys,
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> payload,
        int tagLength,
        ReadOnlySpan<byte> associatedData,
        Span<byte> mac)
    {
        Span<byte> b0 = stackalloc byte[BlockBytes];
        Span<byte> block = stackalloc byte[BlockBytes];
        Span<byte> lengthPrefix = stackalloc byte[6];
        mac.Clear();
        CbcMacChain chain = new(engine, roundKeys, mac, block);

        FormatB0(nonce, payload.Length, tagLength, associatedData.Length > 0, b0);
        chain.Absorb(b0);
        if (associatedData.Length > 0)
        {
            int prefixLength = EncodeAssociatedDataLength(associatedData.Length, lengthPrefix);
            chain.Absorb(lengthPrefix.Slice(0, prefixLength));
            chain.Absorb(associatedData);
            chain.PadToBlock();
        }

        chain.Absorb(payload);
        chain.PadToBlock();

        CryptographicOperations.ZeroMemory(b0);
        CryptographicOperations.ZeroMemory(block);
    }

    // B0 = flags || nonce || payload length in q bytes. Flags: 64 when AAD is present, 8 * ((t - 2) / 2), then q - 1.
    private static void FormatB0(ReadOnlySpan<byte> nonce, long payloadLength, int tagLength, bool hasAssociatedData, Span<byte> b0)
    {
        int lengthBytes = 15 - nonce.Length;
        b0[0] = (byte)((hasAssociatedData ? 64 : 0) | 8 * ((tagLength - 2) / 2) | (lengthBytes - 1));
        nonce.CopyTo(b0.Slice(1));
        for (int i = 0; i < lengthBytes; i++)
        {
            b0[BlockBytes - 1 - i] = (byte)(payloadLength >> (8 * i));
        }
    }

    // SP 800-38C A.2.2: a length below 2^16 - 2^8 takes two bytes; otherwise 0xFF 0xFE and four bytes. An int length
    // cannot reach the eight-byte form, so it is not encoded.
    private static int EncodeAssociatedDataLength(int length, Span<byte> prefix)
    {
        if (length < 0xFF00)
        {
            prefix[0] = (byte)(length >> 8);
            prefix[1] = (byte)length;
            return 2;
        }

        prefix[0] = 0xFF;
        prefix[1] = 0xFE;
        prefix[2] = (byte)(length >> 24);
        prefix[3] = (byte)(length >> 16);
        prefix[4] = (byte)(length >> 8);
        prefix[5] = (byte)length;
        return 6;
    }

    // A_i = (q - 1) || nonce || i, with i big-endian in the last q bytes.
    private static void FormatCounter(ReadOnlySpan<byte> nonce, long index, Span<byte> counter)
    {
        int lengthBytes = 15 - nonce.Length;
        counter[0] = (byte)(lengthBytes - 1);
        nonce.CopyTo(counter.Slice(1));
        for (int i = 0; i < lengthBytes; i++)
        {
            counter[BlockBytes - 1 - i] = (byte)(index >> (8 * i));
        }
    }

    // Tag = MSB(tag.Length) of X XOR E(A_0). The caller passes a span of the tag length.
    private static void ComputeTag(
        BlockEngine engine,
        ReadOnlySpan<byte> roundKeys,
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> mac,
        Span<byte> tag)
    {
        Span<byte> counter = stackalloc byte[BlockBytes];
        Span<byte> mask = stackalloc byte[BlockBytes];
        FormatCounter(nonce, 0, counter);
        engine.EncryptBlocks(roundKeys, counter, mask);
        ByteXor.Xor(mac.Slice(0, tag.Length), mask.Slice(0, tag.Length), tag);
        CryptographicOperations.ZeroMemory(counter);
        CryptographicOperations.ZeroMemory(mask);
    }

    // Feeds bytes into the CBC-MAC chain. Each full block costs one engine call; a partial block is padded on PadToBlock.
    private ref struct CbcMacChain
    {
        private readonly BlockEngine _engine;
        private readonly ReadOnlySpan<byte> _roundKeys;
        private readonly Span<byte> _mac;
        private readonly Span<byte> _block;
        private int _filled;

        internal CbcMacChain(BlockEngine engine, ReadOnlySpan<byte> roundKeys, Span<byte> mac, Span<byte> block)
        {
            _engine = engine;
            _roundKeys = roundKeys;
            _mac = mac;
            _block = block;
        }

        internal void Absorb(ReadOnlySpan<byte> data)
        {
            while (!data.IsEmpty)
            {
                int take = Math.Min(BlockBytes - _filled, data.Length);
                data.Slice(0, take).CopyTo(_block.Slice(_filled));
                _filled += take;
                data = data.Slice(take);
                if (_filled == BlockBytes)
                {
                    Flush();
                }
            }
        }

        internal void PadToBlock()
        {
            if (_filled == 0)
            {
                return;
            }

            _block.Slice(_filled).Clear();
            Flush();
        }

        private void Flush()
        {
            ByteXor.Xor(_mac, _block, _mac);
            _engine.EncryptBlocks(_roundKeys, _mac, _mac);
            _filled = 0;
        }
    }
}
