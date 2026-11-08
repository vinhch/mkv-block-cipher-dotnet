using System.Buffers.Binary;
using System.Security.Cryptography;
using MkvBlockCipher.Modes;
using Xunit;
using static MkvBlockCipher.Tests.Modes.ModeTestSupport;

namespace MkvBlockCipher.Tests;

public sealed class MkvGcmTests
{
    private const int NonceBytes = 12;
    private const int MaxTagBytes = 16;
    private const int AssociatedDataLength = 13;
    private const byte Sentinel = 0xAA;

    // Frozen output: any change here breaks stored ciphertexts. Project-computed vector, generated once from the verified
    // GCM core; it is not a standard vector.
    private const string FrozenKeyHex = "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F";
    private const string FrozenNonceHex = "A0A1A2A3A4A5A6A7A8A9AAAB";
    private const string FrozenPlaintextHex =
        "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F2021222324252627";
    private const string FrozenAssociatedDataHex = "FFEEDDCCBBAA99887766554433";
    private const string FrozenCiphertextHex = "D906CC96CAC7CDED02FB626BC15A45D46018D2CFFC28F51FD79B422E07C5946F99E3C903D9D32CBC";
    private const string FrozenTagHex = "B332AAFAA23A645E5D9078A6805D5E2C";

    private static readonly byte[] SegmentNoncePrefix = { 0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6 };

    public static TheoryData<int, int> RoundTripCases()
    {
        TheoryData<int, int> cases = new();
        foreach (int plaintextLength in new[] { 0, 1, 16, 1000 })
        {
            foreach (int aadLength in new[] { 0, AssociatedDataLength })
            {
                cases.Add(plaintextLength, aadLength);
            }
        }

        return cases;
    }

    [Theory]
    [MemberData(nameof(RoundTripCases))]
    public void Round_trip(int plaintextLength, int aadLength)
    {
        using MkvGcm gcm = CreateGcm();
        byte[] nonce = SeededBytes(NonceBytes, 2);
        byte[] plaintext = SeededBytes(plaintextLength, 4);
        byte[] aad = SeededBytes(aadLength, 3);
        byte[] ciphertext = new byte[plaintextLength];
        byte[] tag = new byte[MaxTagBytes];

        gcm.Encrypt(nonce, plaintext, ciphertext, tag, aad);

        byte[] decrypted = new byte[plaintextLength];
        gcm.Decrypt(nonce, ciphertext, tag, decrypted, aad);
        Assert.Equal(plaintext, decrypted);
    }

    [Theory]
    [InlineData(16)]
    [InlineData(24)]
    [InlineData(32)]
    public void Round_trip_for_each_key_length(int keyLength)
    {
        using MkvGcm gcm = new(SeededBytes(keyLength, 5), MaxTagBytes);
        byte[] nonce = SeededBytes(NonceBytes, 2);
        byte[] plaintext = SeededBytes(40, 4);
        byte[] aad = SeededBytes(AssociatedDataLength, 3);
        byte[] ciphertext = new byte[plaintext.Length];
        byte[] tag = new byte[MaxTagBytes];

        gcm.Encrypt(nonce, plaintext, ciphertext, tag, aad);

        byte[] decrypted = new byte[plaintext.Length];
        gcm.Decrypt(nonce, ciphertext, tag, decrypted, aad);
        Assert.Equal(plaintext, decrypted);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(AssociatedDataLength)]
    public void Empty_plaintext_tag_only(int aadLength)
    {
        using MkvGcm gcm = CreateGcm();
        byte[] nonce = SeededBytes(NonceBytes, 2);
        byte[] aad = SeededBytes(aadLength, 3);
        byte[] tag = new byte[MaxTagBytes];

        gcm.Encrypt(nonce, ReadOnlySpan<byte>.Empty, Span<byte>.Empty, tag, aad);
        gcm.Decrypt(nonce, ReadOnlySpan<byte>.Empty, tag, Span<byte>.Empty, aad);

        byte[] badTag = (byte[])tag.Clone();
        badTag[0] ^= 1;
        Assert.Throws<CryptographicException>(() => gcm.Decrypt(nonce, ReadOnlySpan<byte>.Empty, badTag, Span<byte>.Empty, aad));
    }

    [Theory]
    [InlineData(1)]
    [InlineData(16)]
    [InlineData(1000)]
    public void In_place_round_trip(int length)
    {
        using MkvGcm gcm = CreateGcm();
        byte[] nonce = SeededBytes(NonceBytes, 2);
        byte[] aad = SeededBytes(AssociatedDataLength, 3);
        byte[] plaintext = SeededBytes(length, 4);
        byte[] ciphertext = new byte[length];
        byte[] tag = new byte[MaxTagBytes];
        gcm.Encrypt(nonce, plaintext, ciphertext, tag, aad);

        byte[] buffer = (byte[])plaintext.Clone();
        byte[] inPlaceTag = new byte[MaxTagBytes];
        gcm.Encrypt(nonce, buffer, buffer, inPlaceTag, aad);
        Assert.Equal(ciphertext, buffer);
        Assert.Equal(tag, inPlaceTag);

        gcm.Decrypt(nonce, buffer, inPlaceTag, buffer, aad);
        Assert.Equal(plaintext, buffer);
    }

    [Theory]
    [InlineData("tag", false)]
    [InlineData("tag", true)]
    [InlineData("ciphertext", false)]
    [InlineData("ciphertext", true)]
    [InlineData("aad", false)]
    [InlineData("aad", true)]
    [InlineData("nonce", false)]
    [InlineData("nonce", true)]
    public void Tampered_tag_ciphertext_aad_nonce_throws_and_zeroes(string target, bool inPlace)
    {
        using MkvGcm gcm = CreateGcm();
        byte[] nonce = SeededBytes(NonceBytes, 2);
        byte[] aad = SeededBytes(AssociatedDataLength, 3);
        byte[] plaintext = SeededBytes(40, 4);
        byte[] ciphertext = new byte[plaintext.Length];
        byte[] tag = new byte[MaxTagBytes];
        gcm.Encrypt(nonce, plaintext, ciphertext, tag, aad);

        switch (target)
        {
            case "tag":
                tag[0] ^= 1;
                break;
            case "ciphertext":
                ciphertext[0] ^= 1;
                break;
            case "aad":
                aad[0] ^= 1;
                break;
            case "nonce":
                nonce[0] ^= 1;
                break;
            default:
                Assert.Fail($"Unknown target {target}.");
                break;
        }

        byte[] destination = inPlace ? ciphertext : Enumerable.Repeat(Sentinel, plaintext.Length).ToArray();
        CryptographicException ex = Assert.Throws<CryptographicException>(
            () => gcm.Decrypt(nonce, ciphertext, tag, destination, aad));
        Assert.Equal(DecryptFailure.Message, ex.Message);
        Assert.Equal(new byte[plaintext.Length], destination);
    }

    [Theory]
    [InlineData(12)]
    [InlineData(13)]
    [InlineData(14)]
    [InlineData(15)]
    [InlineData(16)]
    public void Truncated_tag_sizes_12_to_16(int tagSize)
    {
        byte[] key = SeededBytes(16, 1);
        byte[] nonce = SeededBytes(NonceBytes, 2);
        byte[] aad = SeededBytes(AssociatedDataLength, 3);
        byte[] plaintext = SeededBytes(40, 4);

        using MkvGcm full = new(key, MaxTagBytes);
        byte[] ciphertext = new byte[plaintext.Length];
        byte[] fullTag = new byte[MaxTagBytes];
        full.Encrypt(nonce, plaintext, ciphertext, fullTag, aad);

        using MkvGcm gcm = new(key, tagSize);
        Assert.Equal(tagSize, gcm.TagSizeInBytes);
        byte[] tag = new byte[tagSize];
        byte[] truncatedCiphertext = new byte[plaintext.Length];
        gcm.Encrypt(nonce, plaintext, truncatedCiphertext, tag, aad);
        Assert.Equal(ciphertext, truncatedCiphertext);
        Assert.Equal(fullTag[..tagSize], tag);

        byte[] decrypted = new byte[plaintext.Length];
        gcm.Decrypt(nonce, ciphertext, tag, decrypted, aad);
        Assert.Equal(plaintext, decrypted);
    }

    [Fact]
    public void Wrong_output_or_tag_length_throws()
    {
        using MkvGcm gcm = CreateGcm(12);
        byte[] nonce = SeededBytes(NonceBytes, 2);
        byte[] plaintext = SeededBytes(16, 4);
        byte[] ciphertext = new byte[plaintext.Length];

        Assert.Throws<ArgumentException>(() => gcm.Encrypt(nonce, plaintext, ciphertext, new byte[13]));
        Assert.Throws<ArgumentException>(() => gcm.Encrypt(nonce, plaintext, new byte[15], new byte[12]));
        Assert.Throws<ArgumentException>(() => gcm.Decrypt(nonce, ciphertext, new byte[11], new byte[16]));
        Assert.Throws<ArgumentException>(() => gcm.Decrypt(nonce, ciphertext, new byte[12], new byte[17]));
    }

    [Fact]
    public void Overlapping_outputs_throws()
    {
        using MkvGcm gcm = CreateGcm();
        byte[] nonce = SeededBytes(NonceBytes, 2);
        byte[] aad = SeededBytes(AssociatedDataLength, 3);
        byte[] buffer = SeededBytes(64, 4);
        byte[] tag = new byte[MaxTagBytes];

        // Partial overlap of input and output, and an output that overlaps the associated data, are both refused.
        Assert.Throws<ArgumentException>(() => gcm.Encrypt(nonce, buffer.AsSpan(0, 32), buffer.AsSpan(8, 32), tag));
        Assert.Throws<ArgumentException>(() => gcm.Encrypt(nonce, buffer.AsSpan(0, 32), buffer.AsSpan(32, 32), buffer.AsSpan(0, 16), aad));
        Assert.Throws<ArgumentException>(() => gcm.Encrypt(nonce, buffer.AsSpan(0, 32), buffer.AsSpan(32, 32), tag, buffer.AsSpan(40, 13)));
        Assert.Throws<ArgumentException>(() => gcm.Decrypt(nonce, buffer.AsSpan(0, 32), tag, buffer.AsSpan(8, 32)));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(11)]
    [InlineData(13)]
    [InlineData(16)]
    public void Nonce_not_12_throws(int nonceLength)
    {
        using MkvGcm gcm = CreateGcm();
        byte[] nonce = new byte[nonceLength];
        byte[] plaintext = new byte[16];
        byte[] ciphertext = Enumerable.Repeat(Sentinel, plaintext.Length).ToArray();
        byte[] tag = new byte[MaxTagBytes];

        Assert.Throws<ArgumentException>(() => gcm.Encrypt(nonce, plaintext, ciphertext, tag));
        Assert.Throws<ArgumentException>(() => gcm.Decrypt(nonce, ciphertext, tag, plaintext));
        Assert.All(ciphertext, b => Assert.Equal(Sentinel, b));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(11)]
    [InlineData(17)]
    public void Tag_size_out_of_range_throws(int tagSize)
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => _ = new MkvGcm(SeededBytes(16, 1), tagSize));
    }

    [Fact]
    public void Key_length_64_throws()
    {
        ArgumentException ex = Assert.Throws<ArgumentException>(() => _ = new MkvGcm(new byte[64], MaxTagBytes));
        Assert.Equal("key", ex.ParamName);
    }

    [Fact]
    public void Concurrent_calls_agree()
    {
        using MkvGcm gcm = CreateGcm();
        byte[] nonce = SeededBytes(NonceBytes, 2);
        byte[] aad = SeededBytes(AssociatedDataLength, 3);
        byte[] plaintext = SeededBytes(1000, 4);
        byte[] expected = Seal(gcm, nonce, plaintext, aad);

        byte[][] results = new byte[64][];
        Parallel.For(0, results.Length, i => results[i] = Seal(gcm, nonce, plaintext, aad));

        Assert.All(results, result => Assert.Equal(expected, result));
    }

    [Fact]
    public void Disposed_throws()
    {
        MkvGcm gcm = CreateGcm();
        gcm.Dispose();
        gcm.Dispose();

        byte[] nonce = new byte[NonceBytes];
        byte[] buffer = new byte[16];
        byte[] tag = new byte[MaxTagBytes];
        Assert.Throws<ObjectDisposedException>(() => gcm.Encrypt(nonce, buffer, buffer, tag));
        Assert.Throws<ObjectDisposedException>(() => gcm.Decrypt(nonce, buffer, tag, buffer));
    }

    [Fact]
    public void Frozen_mkv_vector()
    {
        using MkvGcm gcm = new(Convert.FromHexString(FrozenKeyHex), MaxTagBytes);
        byte[] nonce = Convert.FromHexString(FrozenNonceHex);
        byte[] plaintext = Convert.FromHexString(FrozenPlaintextHex);
        byte[] aad = Convert.FromHexString(FrozenAssociatedDataHex);
        byte[] ciphertext = new byte[plaintext.Length];
        byte[] tag = new byte[MaxTagBytes];

        gcm.Encrypt(nonce, plaintext, ciphertext, tag, aad);
        Assert.Equal(FrozenCiphertextHex, Convert.ToHexString(ciphertext));
        Assert.Equal(FrozenTagHex, Convert.ToHexString(tag));

        byte[] decrypted = new byte[plaintext.Length];
        gcm.Decrypt(nonce, Convert.FromHexString(FrozenCiphertextHex), Convert.FromHexString(FrozenTagHex), decrypted, aad);
        Assert.Equal(plaintext, decrypted);
    }

    public static TheoryData<uint, bool> SegmentPositions()
    {
        TheoryData<uint, bool> cases = new();
        foreach (uint segmentIndex in new[] { 0u, 1u, uint.MaxValue })
        {
            foreach (bool isLastSegment in new[] { false, true })
            {
                cases.Add(segmentIndex, isLastSegment);
            }
        }

        return cases;
    }

    public static TheoryData<uint, bool, uint, bool> WrongSegmentArguments() =>
        new()
        {
            { 0u, false, 1u, false },
            { 1u, true, 2u, true },
            { 0u, false, 0u, true },
            { 1u, true, 1u, false },
        };

    [Theory]
    [MemberData(nameof(SegmentPositions))]
    public void EncryptSegment_MatchesEncryptWithBuiltNonce(uint segmentIndex, bool isLastSegment)
    {
        using MkvGcm gcm = CreateFrozenGcm();
        byte[] plaintext = SeededBytes(40, 4);
        byte[] aad = SeededBytes(AssociatedDataLength, 3);
        byte[] nonce = new byte[NonceBytes];
        SegmentNoncePrefix.CopyTo(nonce, 0);
        BinaryPrimitives.WriteUInt32BigEndian(nonce.AsSpan(MkvGcm.StreamNoncePrefixBytes), segmentIndex);
        nonce[NonceBytes - 1] = isLastSegment ? (byte)0x01 : (byte)0x00;

        byte[] expectedCiphertext = new byte[plaintext.Length];
        byte[] expectedTag = new byte[MaxTagBytes];
        gcm.Encrypt(nonce, plaintext, expectedCiphertext, expectedTag, aad);

        byte[] ciphertext = new byte[plaintext.Length];
        byte[] tag = new byte[MaxTagBytes];
        gcm.EncryptSegment(SegmentNoncePrefix, segmentIndex, isLastSegment, plaintext, ciphertext, tag, aad);
        Assert.Equal(expectedCiphertext, ciphertext);
        Assert.Equal(expectedTag, tag);
    }

    [Theory]
    [MemberData(nameof(SegmentPositions))]
    public void DecryptSegment_RoundTrips(uint segmentIndex, bool isLastSegment)
    {
        using MkvGcm gcm = CreateFrozenGcm();
        byte[] plaintext = SeededBytes(40, 4);
        byte[] aad = SeededBytes(AssociatedDataLength, 3);
        byte[] ciphertext = new byte[plaintext.Length];
        byte[] tag = new byte[MaxTagBytes];
        gcm.EncryptSegment(SegmentNoncePrefix, segmentIndex, isLastSegment, plaintext, ciphertext, tag, aad);

        byte[] decrypted = new byte[plaintext.Length];
        gcm.DecryptSegment(SegmentNoncePrefix, segmentIndex, isLastSegment, ciphertext, tag, decrypted, aad);
        Assert.Equal(plaintext, decrypted);
    }

    [Theory]
    [MemberData(nameof(WrongSegmentArguments))]
    public void DecryptSegment_WrongIndexOrFlag_Throws(
        uint segmentIndex,
        bool isLastSegment,
        uint wrongSegmentIndex,
        bool wrongLastFlag)
    {
        using MkvGcm gcm = CreateFrozenGcm();
        byte[] plaintext = SeededBytes(40, 4);
        byte[] aad = SeededBytes(AssociatedDataLength, 3);
        byte[] ciphertext = new byte[plaintext.Length];
        byte[] tag = new byte[MaxTagBytes];
        gcm.EncryptSegment(SegmentNoncePrefix, segmentIndex, isLastSegment, plaintext, ciphertext, tag, aad);

        byte[] destination = Enumerable.Repeat(Sentinel, plaintext.Length).ToArray();
        Assert.Throws<CryptographicException>(
            () => gcm.DecryptSegment(SegmentNoncePrefix, wrongSegmentIndex, wrongLastFlag, ciphertext, tag, destination, aad));
        Assert.Equal(new byte[plaintext.Length], destination);
    }

    [Theory]
    [InlineData(6)]
    [InlineData(8)]
    public void Segment_PrefixNotSevenBytes_Throws(int prefixLength)
    {
        using MkvGcm gcm = CreateFrozenGcm();
        byte[] prefix = new byte[prefixLength];
        byte[] buffer = new byte[16];
        byte[] output = new byte[16];
        byte[] tag = new byte[MaxTagBytes];

        ArgumentException encryptEx = Assert.Throws<ArgumentException>(
            () => gcm.EncryptSegment(prefix, 0, false, buffer, output, tag));
        Assert.Equal("noncePrefix", encryptEx.ParamName);

        ArgumentException decryptEx = Assert.Throws<ArgumentException>(
            () => gcm.DecryptSegment(prefix, 0, false, buffer, tag, output));
        Assert.Equal("noncePrefix", decryptEx.ParamName);
    }

    [Fact]
    public void Segment_AfterDispose_Throws()
    {
        MkvGcm gcm = CreateFrozenGcm();
        gcm.Dispose();

        byte[] buffer = new byte[16];
        byte[] tag = new byte[MaxTagBytes];
        Assert.Throws<ObjectDisposedException>(
            () => gcm.EncryptSegment(SegmentNoncePrefix, 0, false, buffer, buffer, tag));
        Assert.Throws<ObjectDisposedException>(
            () => gcm.DecryptSegment(SegmentNoncePrefix, 0, false, buffer, tag, buffer));
    }

    private static MkvGcm CreateGcm(int tagSize = MaxTagBytes) => new(SeededBytes(16, 1), tagSize);

    private static MkvGcm CreateFrozenGcm() => new(Convert.FromHexString(FrozenKeyHex), MaxTagBytes);

    private static byte[] Seal(MkvGcm gcm, byte[] nonce, byte[] plaintext, byte[] aad)
    {
        byte[] output = new byte[plaintext.Length + MaxTagBytes];
        gcm.Encrypt(nonce, plaintext, output.AsSpan(0, plaintext.Length), output.AsSpan(plaintext.Length), aad);
        return output;
    }
}
