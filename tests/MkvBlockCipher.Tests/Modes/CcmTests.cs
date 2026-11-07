using System.Security.Cryptography;
using MkvBlockCipher.Modes;
using Xunit;
using static MkvBlockCipher.Tests.Modes.ModeTestSupport;

namespace MkvBlockCipher.Tests.Modes;

public sealed class CcmTests
{
    private const string SkipReason = "Needs AesCcm.";

    public static bool AesCcmSupported => AesCcm.IsSupported;

    // SP 800-38C Appendix C, examples 1-4, AES-128. Every example uses key 40 41 ... 4f, nonce 10 11 12 ..., payload
    // 20 21 22 ... and AAD 00 01 02 ... (mod 256). The expected value is the ciphertext followed by the encrypted tag.
    // Example 4 has 65536 bytes of AAD. In the PDF text layer, the C.2 output is printed under the C.3 heading.
    [Theory]
    // C.1: Nlen 56, Alen 64, Plen 32, Tlen 32.
    [InlineData(7, 4, 8, 4, "7162015b4dac255d")]
    // C.2: Nlen 64, Alen 128, Plen 128, Tlen 48.
    [InlineData(8, 6, 16, 16, "d2a1f0e051ea5f62081a7792073d593d1fc64fbfaccd")]
    // C.3: Nlen 96, Alen 160, Plen 192, Tlen 64.
    [InlineData(12, 8, 20, 24, "e3b201a9f5b71a7a9b1ceaeccd97e70b6176aad9a4428aa5484392fbc1b09951")]
    // C.4: Nlen 104, Alen 524288 bits, Plen 256, Tlen 112.
    [InlineData(
        13,
        14,
        65536,
        32,
        "69915dad1e84c6376a68c2967e4dab615ae0fd1faec44cc484828529463ccf72b4ac6bec93e8598e7f0dadbcea5b")]
    public void Core_matches_SP800_38C_examples(
        int nonceLength,
        int tagLength,
        int aadLength,
        int payloadLength,
        string expectedCiphertextAndTagHex)
    {
        AesTestEngine engine = new();
        byte[] key = Sequence(16, 0x40);
        byte[] nonce = Sequence(nonceLength, 0x10);
        byte[] aad = Sequence(aadLength, 0x00);
        byte[] plaintext = Sequence(payloadLength, 0x20);
        byte[] ciphertext = new byte[payloadLength];
        byte[] tag = new byte[tagLength];

        Ccm.Encrypt(engine, key, nonce, plaintext, ciphertext, tag, aad);
        byte[] ciphertextAndTag = [.. ciphertext, .. tag];
        Assert.Equal(Convert.FromHexString(expectedCiphertextAndTagHex), ciphertextAndTag);

        byte[] decrypted = new byte[payloadLength];
        Assert.True(Ccm.Decrypt(engine, key, nonce, ciphertext, tag, decrypted, aad));
        Assert.Equal(plaintext, decrypted);
    }

    // RFC 3610 section 8, packet vectors 1-3: AES-128, 13-octet nonce, 8-octet header (the AAD), 8-octet MAC. Copied from
    // the "Authenticated and Encrypted Output" of each packet. The tag is the last 8 octets of each output.
    [Theory]
    // Packet vector #1: payload 08 .. 1e (23 octets).
    [InlineData(
        "00000003020100A0A1A2A3A4A5",
        "0001020304050607",
        "08090A0B0C0D0E0F101112131415161718191A1B1C1D1E",
        "588C979A61C663D2F066D0C2C0F989806D5F6B61DAC384",
        "17E8D12CFDF926E0")]
    // Packet vector #2: payload 08 .. 1f (24 octets).
    [InlineData(
        "00000004030201A0A1A2A3A4A5",
        "0001020304050607",
        "08090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
        "72C91A36E135F8CF291CA894085C87E3CC15C439C9E43A3B",
        "A091D56E10400916")]
    // Packet vector #3: payload 08 .. 20 (25 octets).
    [InlineData(
        "00000005040302A0A1A2A3A4A5",
        "0001020304050607",
        "08090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F20",
        "51B1E5F44A197D1DA46B0F8E2D282AE871E838BB64DA859657",
        "4ADAA76FBD9FB0C5")]
    public void Core_matches_RFC3610_packet_vectors(
        string nonceHex,
        string aadHex,
        string plaintextHex,
        string ciphertextHex,
        string tagHex)
    {
        AesTestEngine engine = new();
        byte[] key = Convert.FromHexString("C0C1C2C3C4C5C6C7C8C9CACBCCCDCECF");
        byte[] nonce = Convert.FromHexString(nonceHex);
        byte[] aad = Convert.FromHexString(aadHex);
        byte[] plaintext = Convert.FromHexString(plaintextHex);
        byte[] ciphertext = new byte[plaintext.Length];
        byte[] tag = new byte[8];

        Ccm.Encrypt(engine, key, nonce, plaintext, ciphertext, tag, aad);
        Assert.Equal(Convert.FromHexString(ciphertextHex), ciphertext);
        Assert.Equal(Convert.FromHexString(tagHex), tag);

        byte[] decrypted = new byte[plaintext.Length];
        Assert.True(Ccm.Decrypt(engine, key, nonce, ciphertext, tag, decrypted, aad));
        Assert.Equal(plaintext, decrypted);
    }

    // The AAD length prefix changes form at 0xFF00: 0xFEFF is a 2-byte prefix, 0xFF00 is 0xFF 0xFE plus 4 bytes.
    [Theory(SkipUnless = nameof(AesCcmSupported), Skip = SkipReason)]
    [InlineData(0xFEFF)]
    [InlineData(0xFF00)]
    public void Core_matches_BCL_AesCcm_at_aad_thresholds(int aadLength)
    {
        byte[] key = SeededBytes(16, 1);
        byte[] nonce = SeededBytes(13, 2);
        byte[] aad = SeededBytes(aadLength, 3);
        byte[] plaintext = SeededBytes(40, 4);
        byte[] expectedCiphertext = new byte[plaintext.Length];
        byte[] expectedTag = new byte[16];
        using (AesCcm bcl = new(key))
        {
            bcl.Encrypt(nonce, plaintext, expectedCiphertext, expectedTag, aad);
        }

        byte[] ciphertext = new byte[plaintext.Length];
        byte[] tag = new byte[16];
        Ccm.Encrypt(new AesTestEngine(), key, nonce, plaintext, ciphertext, tag, aad);
        Assert.Equal(expectedCiphertext, ciphertext);
        Assert.Equal(expectedTag, tag);
    }

    private static byte[] Sequence(int length, byte start)
    {
        byte[] bytes = new byte[length];
        for (int i = 0; i < length; i++)
        {
            bytes[i] = (byte)(start + i);
        }

        return bytes;
    }
}
