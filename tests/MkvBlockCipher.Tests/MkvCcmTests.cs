using System.Security.Cryptography;
using MkvBlockCipher.Modes;
using Xunit;
using static MkvBlockCipher.Tests.Modes.ModeTestSupport;

namespace MkvBlockCipher.Tests;

public sealed class MkvCcmTests
{
    private const int MinNonceBytes = 7;
    private const int MaxNonceBytes = 13;
    private const int MaxTagBytes = 16;
    private const int AssociatedDataLength = 13;
    private const int MaxPayloadBytesForNonce13 = 65535;
    private const byte Sentinel = 0xAA;

    // Frozen output: any change here breaks stored ciphertexts. Project-computed vector, generated once from the verified
    // CCM core; it is not a standard vector.
    private const string FrozenKeyHex = "000102030405060708090A0B0C0D0E0F";
    private const string FrozenNonceHex = "A0A1A2A3A4A5A6A7A8A9AAABAC";
    private const string FrozenPlaintextHex =
        "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F2021222324252627";
    private const string FrozenAssociatedDataHex = "FFEEDDCCBBAA99887766554433";
    private const string FrozenCiphertextHex = "A1DBBF4CF9F1D10AA8659A8364039473D6EEE2760B4409993947EF80A0CA21A62862FC6BAADC404E";
    private const string FrozenTagHex = "1ECBA073CCE1F6E86DD9E47B418B9A8C";

    public static TheoryData<int, int> RoundTripCases()
    {
        TheoryData<int, int> cases = new();
        foreach (int nonceLength in new[] { MinNonceBytes, MaxNonceBytes })
        {
            foreach (int tagLength in new[] { 4, MaxTagBytes })
            {
                cases.Add(nonceLength, tagLength);
            }
        }

        return cases;
    }

    [Theory]
    [MemberData(nameof(RoundTripCases))]
    public void Round_trip(int nonceLength, int tagLength)
    {
        using MkvCcm ccm = CreateCcm();
        byte[] nonce = SeededBytes(nonceLength, 2);
        byte[] plaintext = SeededBytes(40, 4);
        byte[] aad = SeededBytes(AssociatedDataLength, 3);
        byte[] ciphertext = new byte[plaintext.Length];
        byte[] tag = new byte[tagLength];

        ccm.Encrypt(nonce, plaintext, ciphertext, tag, aad);

        byte[] decrypted = new byte[plaintext.Length];
        ccm.Decrypt(nonce, ciphertext, tag, decrypted, aad);
        Assert.Equal(plaintext, decrypted);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(AssociatedDataLength)]
    public void Empty_plaintext_tag_only(int aadLength)
    {
        using MkvCcm ccm = CreateCcm();
        byte[] nonce = SeededBytes(MaxNonceBytes, 2);
        byte[] aad = SeededBytes(aadLength, 3);
        byte[] tag = new byte[MaxTagBytes];

        ccm.Encrypt(nonce, ReadOnlySpan<byte>.Empty, Span<byte>.Empty, tag, aad);
        ccm.Decrypt(nonce, ReadOnlySpan<byte>.Empty, tag, Span<byte>.Empty, aad);

        byte[] badTag = (byte[])tag.Clone();
        badTag[0] ^= 1;
        Assert.Throws<CryptographicException>(() => ccm.Decrypt(nonce, ReadOnlySpan<byte>.Empty, badTag, Span<byte>.Empty, aad));
    }

    [Fact]
    public void Empty_aad()
    {
        using MkvCcm ccm = CreateCcm();
        byte[] nonce = SeededBytes(MaxNonceBytes, 2);
        byte[] plaintext = SeededBytes(40, 4);
        byte[] ciphertext = new byte[plaintext.Length];
        byte[] tag = new byte[MaxTagBytes];

        ccm.Encrypt(nonce, plaintext, ciphertext, tag);

        byte[] decrypted = new byte[plaintext.Length];
        ccm.Decrypt(nonce, ciphertext, tag, decrypted);
        Assert.Equal(plaintext, decrypted);
    }

    // The AAD length prefix changes form at 0xFF00 (65280). Both sides of the change must round trip.
    [Theory]
    [InlineData(0xFEFF)]
    [InlineData(0xFF00)]
    public void Aad_length_encoding_boundaries(int aadLength)
    {
        using MkvCcm ccm = CreateCcm();
        byte[] nonce = SeededBytes(MaxNonceBytes, 2);
        byte[] aad = SeededBytes(aadLength, 3);
        byte[] plaintext = SeededBytes(40, 4);
        byte[] ciphertext = new byte[plaintext.Length];
        byte[] tag = new byte[MaxTagBytes];

        ccm.Encrypt(nonce, plaintext, ciphertext, tag, aad);

        byte[] decrypted = new byte[plaintext.Length];
        ccm.Decrypt(nonce, ciphertext, tag, decrypted, aad);
        Assert.Equal(plaintext, decrypted);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(16)]
    [InlineData(1000)]
    public void In_place_round_trip(int length)
    {
        using MkvCcm ccm = CreateCcm();
        byte[] nonce = SeededBytes(MaxNonceBytes, 2);
        byte[] aad = SeededBytes(AssociatedDataLength, 3);
        byte[] plaintext = SeededBytes(length, 4);
        byte[] ciphertext = new byte[length];
        byte[] tag = new byte[MaxTagBytes];
        ccm.Encrypt(nonce, plaintext, ciphertext, tag, aad);

        // The tag is computed over the plaintext before the keystream overwrites it.
        byte[] buffer = (byte[])plaintext.Clone();
        byte[] inPlaceTag = new byte[MaxTagBytes];
        ccm.Encrypt(nonce, buffer, buffer, inPlaceTag, aad);
        Assert.Equal(ciphertext, buffer);
        Assert.Equal(tag, inPlaceTag);

        ccm.Decrypt(nonce, buffer, inPlaceTag, buffer, aad);
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
        using MkvCcm ccm = CreateCcm();
        byte[] nonce = SeededBytes(MaxNonceBytes, 2);
        byte[] aad = SeededBytes(AssociatedDataLength, 3);
        byte[] plaintext = SeededBytes(40, 4);
        byte[] ciphertext = new byte[plaintext.Length];
        byte[] tag = new byte[MaxTagBytes];
        ccm.Encrypt(nonce, plaintext, ciphertext, tag, aad);

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

        byte[] destination = inPlace ? ciphertext : Filled(plaintext.Length, Sentinel);
        CryptographicException ex = Assert.Throws<CryptographicException>(
            () => ccm.Decrypt(nonce, ciphertext, tag, destination, aad));
        Assert.Equal(DecryptFailure.Message, ex.Message);
        Assert.Equal(new byte[plaintext.Length], destination);
    }

    [Theory]
    [InlineData(3)]
    [InlineData(5)]
    [InlineData(7)]
    [InlineData(15)]
    [InlineData(17)]
    public void Odd_tag_length_throws(int tagLength)
    {
        using MkvCcm ccm = CreateCcm();
        byte[] nonce = SeededBytes(MaxNonceBytes, 2);
        byte[] plaintext = SeededBytes(16, 4);
        byte[] ciphertext = Filled(plaintext.Length, Sentinel);
        byte[] decrypted = Filled(plaintext.Length, Sentinel);
        byte[] tag = new byte[tagLength];

        AssertRejectsParameter("tag", () => ccm.Encrypt(nonce, plaintext, ciphertext, tag));
        AssertRejectsParameter("tag", () => ccm.Decrypt(nonce, ciphertext, tag, decrypted));
        Assert.All(ciphertext, b => Assert.Equal(Sentinel, b));
        Assert.All(decrypted, b => Assert.Equal(Sentinel, b));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(2)]
    [InlineData(18)]
    public void Tag_length_outside_4_to_16_throws(int tagLength)
    {
        using MkvCcm ccm = CreateCcm();
        byte[] nonce = SeededBytes(MaxNonceBytes, 2);
        byte[] plaintext = SeededBytes(16, 4);
        byte[] ciphertext = Filled(plaintext.Length, Sentinel);
        byte[] decrypted = Filled(plaintext.Length, Sentinel);
        byte[] tag = new byte[tagLength];

        AssertRejectsParameter("tag", () => ccm.Encrypt(nonce, plaintext, ciphertext, tag));
        AssertRejectsParameter("tag", () => ccm.Decrypt(nonce, ciphertext, tag, decrypted));
        Assert.All(ciphertext, b => Assert.Equal(Sentinel, b));
        Assert.All(decrypted, b => Assert.Equal(Sentinel, b));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(6)]
    [InlineData(14)]
    [InlineData(16)]
    public void Nonce_length_outside_7_to_13_throws(int nonceLength)
    {
        using MkvCcm ccm = CreateCcm();
        byte[] nonce = new byte[nonceLength];
        byte[] plaintext = new byte[16];
        byte[] ciphertext = Filled(plaintext.Length, Sentinel);
        byte[] tag = new byte[MaxTagBytes];

        AssertRejectsParameter("nonce", () => ccm.Encrypt(nonce, plaintext, ciphertext, tag));
        AssertRejectsParameter("nonce", () => ccm.Decrypt(nonce, ciphertext, tag, plaintext));
        Assert.All(ciphertext, b => Assert.Equal(Sentinel, b));
    }

    // For a 13-byte nonce, q = 2: the payload length must fit in two bytes.
    [Fact]
    public void Payload_at_q_limit_round_trips()
    {
        using MkvCcm ccm = CreateCcm();
        byte[] nonce = SeededBytes(MaxNonceBytes, 2);
        byte[] plaintext = SeededBytes(MaxPayloadBytesForNonce13, 4);
        byte[] ciphertext = new byte[plaintext.Length];
        byte[] tag = new byte[MaxTagBytes];

        ccm.Encrypt(nonce, plaintext, ciphertext, tag);

        byte[] decrypted = new byte[plaintext.Length];
        ccm.Decrypt(nonce, ciphertext, tag, decrypted);
        Assert.Equal(plaintext, decrypted);
    }

    [Fact]
    public void Payload_over_q_limit_throws()
    {
        using MkvCcm ccm = CreateCcm();
        byte[] nonce = SeededBytes(MaxNonceBytes, 2);
        byte[] plaintext = new byte[MaxPayloadBytesForNonce13 + 1];
        byte[] ciphertext = Filled(plaintext.Length, Sentinel);
        byte[] tag = new byte[MaxTagBytes];

        AssertRejectsParameter("plaintext", () => ccm.Encrypt(nonce, plaintext, ciphertext, tag));
        AssertRejectsParameter("ciphertext", () => ccm.Decrypt(nonce, ciphertext, tag, plaintext));
        Assert.All(ciphertext, b => Assert.Equal(Sentinel, b));
    }

    [Fact]
    public void Overlapping_outputs_throws()
    {
        using MkvCcm ccm = CreateCcm();
        byte[] nonce = SeededBytes(MaxNonceBytes, 2);
        byte[] aad = SeededBytes(AssociatedDataLength, 3);
        byte[] buffer = SeededBytes(64, 4);
        byte[] tag = new byte[MaxTagBytes];

        // Partial overlap of input and output, and an output that overlaps the associated data or the plaintext, are refused.
        Assert.Throws<ArgumentException>(() => ccm.Encrypt(nonce, buffer.AsSpan(0, 32), buffer.AsSpan(8, 32), tag));
        Assert.Throws<ArgumentException>(() => ccm.Encrypt(nonce, buffer.AsSpan(0, 32), buffer.AsSpan(32, 32), buffer.AsSpan(0, 16), aad));
        Assert.Throws<ArgumentException>(() => ccm.Encrypt(nonce, buffer.AsSpan(0, 32), buffer.AsSpan(32, 32), tag, buffer.AsSpan(40, 13)));
        Assert.Throws<ArgumentException>(() => ccm.Decrypt(nonce, buffer.AsSpan(0, 32), tag, buffer.AsSpan(8, 32)));
    }

    [Fact]
    public void Concurrent_calls_agree()
    {
        using MkvCcm ccm = CreateCcm();
        byte[] nonce = SeededBytes(MaxNonceBytes, 2);
        byte[] aad = SeededBytes(AssociatedDataLength, 3);
        byte[] plaintext = SeededBytes(1000, 4);
        byte[] expected = Seal(ccm, nonce, plaintext, aad);

        byte[][] results = new byte[64][];
        Parallel.For(0, results.Length, i => results[i] = Seal(ccm, nonce, plaintext, aad));

        Assert.All(results, result => Assert.Equal(expected, result));
    }

    [Fact]
    public void Key_length_64_throws()
    {
        ArgumentException ex = Assert.Throws<ArgumentException>(() => _ = new MkvCcm(new byte[64]));
        Assert.Equal("key", ex.ParamName);
    }

    [Fact]
    public void Disposed_throws()
    {
        MkvCcm ccm = CreateCcm();
        ccm.Dispose();
        ccm.Dispose();

        byte[] nonce = new byte[MaxNonceBytes];
        byte[] buffer = new byte[16];
        byte[] tag = new byte[MaxTagBytes];
        Assert.Throws<ObjectDisposedException>(() => ccm.Encrypt(nonce, buffer, buffer, tag));
        Assert.Throws<ObjectDisposedException>(() => ccm.Decrypt(nonce, buffer, tag, buffer));
    }

    [Fact]
    public void Frozen_mkv_vector()
    {
        using MkvCcm ccm = new(Convert.FromHexString(FrozenKeyHex));
        byte[] nonce = Convert.FromHexString(FrozenNonceHex);
        byte[] plaintext = Convert.FromHexString(FrozenPlaintextHex);
        byte[] aad = Convert.FromHexString(FrozenAssociatedDataHex);
        byte[] ciphertext = new byte[plaintext.Length];
        byte[] tag = new byte[MaxTagBytes];

        ccm.Encrypt(nonce, plaintext, ciphertext, tag, aad);
        Assert.Equal(FrozenCiphertextHex, Convert.ToHexString(ciphertext));
        Assert.Equal(FrozenTagHex, Convert.ToHexString(tag));

        byte[] decrypted = new byte[plaintext.Length];
        ccm.Decrypt(nonce, Convert.FromHexString(FrozenCiphertextHex), Convert.FromHexString(FrozenTagHex), decrypted, aad);
        Assert.Equal(plaintext, decrypted);
    }

    private static MkvCcm CreateCcm() => new(SeededBytes(16, 1));

    private static byte[] Seal(MkvCcm ccm, byte[] nonce, byte[] plaintext, byte[] aad)
    {
        byte[] output = new byte[plaintext.Length + MaxTagBytes];
        ccm.Encrypt(nonce, plaintext, output.AsSpan(0, plaintext.Length), output.AsSpan(plaintext.Length), aad);
        return output;
    }
}
