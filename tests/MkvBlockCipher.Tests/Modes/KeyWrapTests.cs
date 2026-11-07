using System.Buffers.Binary;
using System.Security.Cryptography;
using MkvBlockCipher.Modes;
using Xunit;
using static MkvBlockCipher.Tests.Modes.ModeTestSupport;

namespace MkvBlockCipher.Tests.Modes;

public sealed class KeyWrapTests
{
    // RFC 3394 section 2.2.3: the KW initial value.
    private const string KwInitialValueHex = "A6A6A6A6A6A6A6A6";

    // RFC 3394 section 4.1 to 4.6, copied from the RFC Editor text of https://www.rfc-editor.org/rfc/rfc3394.
    [Theory]
    [InlineData(
        "000102030405060708090A0B0C0D0E0F",
        "00112233445566778899AABBCCDDEEFF",
        "1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5")]
    [InlineData(
        "000102030405060708090A0B0C0D0E0F1011121314151617",
        "00112233445566778899AABBCCDDEEFF",
        "96778B25AE6CA435F92B5B97C050AED2468AB8A17AD84E5D")]
    [InlineData(
        "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
        "00112233445566778899AABBCCDDEEFF",
        "64E8C3F9CE0F5BA263E9777905818A2A93C8191E7D6E8AE7")]
    [InlineData(
        "000102030405060708090A0B0C0D0E0F1011121314151617",
        "00112233445566778899AABBCCDDEEFF0001020304050607",
        "031D33264E15D33268F24EC260743EDCE1C6C7DDEE725A936BA814915C6762D2")]
    [InlineData(
        "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
        "00112233445566778899AABBCCDDEEFF0001020304050607",
        "A8F9BC1612C68B3FF6E6F4FBE30E71E4769C8B80A32CB8958CD5D17D6B254DA1")]
    [InlineData(
        "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
        "00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F",
        "28C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326CBC7F0E71A99F43BFB988B9B7A02DD21")]
    public void Kw_core_matches_RFC3394(string kek, string keyData, string wrapped)
    {
        byte[] data = Convert.FromHexString(keyData);
        byte[] output = new byte[data.Length + 8];

        KeyWrap.Wrap(new AesTestEngine(), Convert.FromHexString(kek), Convert.FromHexString(KwInitialValueHex), data, output);
        Assert.Equal(Convert.FromHexString(wrapped), output);

        byte[] recovered = new byte[data.Length];
        byte[] recoveredValue = new byte[8];
        Assert.True(KeyWrap.TryUnwrap(new AesTestEngine(), Convert.FromHexString(kek), output, recovered, recoveredValue));
        Assert.Equal(data, recovered);
        Assert.Equal(Convert.FromHexString(KwInitialValueHex), recoveredValue);
    }

    // RFC 5649 section 6: two examples with a 192-bit KEK, one longer than a semiblock and one that fits in one block.
    [Theory]
    [InlineData(
        "5840df6e29b02af1ab493b705bf16ea1ae8338f4dcc176a8",
        "c37b7e6492584340bed1220780894115 5068f738",
        "138bdeaa9b8fa7fc61f97742e72248ee5ae6ae5360d1ae6a5f54f373fa543b6a")]
    [InlineData(
        "5840df6e29b02af1ab493b705bf16ea1ae8338f4dcc176a8",
        "466f7250617369",
        "afbeb0f07dfbf5419200f2ccb50bb24f")]
    public void Kwp_core_matches_RFC5649(string kek, string keyData, string wrapped)
    {
        byte[] plaintext = Convert.FromHexString(keyData.Replace(" ", string.Empty));
        byte[] output = new byte[MkvCipher.GetKeyWrapPaddedLength(plaintext.Length)];

        KeyWrap.WrapPadded(new AesTestEngine(), Convert.FromHexString(kek), plaintext, output);
        Assert.Equal(Convert.FromHexString(wrapped), output);

        byte[] recovered = new byte[output.Length - 8];
        Assert.True(KeyWrap.TryUnwrapPadded(new AesTestEngine(), Convert.FromHexString(kek), output, recovered, out int length));
        Assert.Equal(plaintext, recovered[..length]);
    }

    [Fact]
    public void Kwp_core_matches_BCL_on_random_inputs()
    {
        byte[] key = SeededBytes(32, 11);
        using Aes aes = Aes.Create();
        aes.Key = key;

        for (int length = 1; length <= 70; length++)
        {
            byte[] plaintext = SeededBytes(length, length);
            byte[] output = new byte[MkvCipher.GetKeyWrapPaddedLength(length)];

            KeyWrap.WrapPadded(new AesTestEngine(), key, plaintext, output);

            Assert.Equal(aes.EncryptKeyWrapPadded(plaintext), output);
        }
    }

    [Theory]
    [MemberData(nameof(KwLengths))]
    public void In_place_round_trip_KW(int length)
    {
        using MkvCipher cipher = CreateCipher(MkvBlockSize.Mkv128);
        byte[] plaintext = SeededBytes(length, 5);
        byte[] buffer = new byte[length + 8];
        plaintext.CopyTo(buffer, 0);

        cipher.EncryptKeyWrap(buffer.AsSpan(0, length), buffer);
        Assert.Equal(cipher.EncryptKeyWrap(plaintext), buffer);

        Assert.Equal(length, cipher.DecryptKeyWrap(buffer, buffer));
        Assert.Equal(plaintext, buffer[..length]);
    }

    [Theory]
    [MemberData(nameof(PaddedLengths))]
    public void In_place_round_trip_KWP(int length)
    {
        using MkvCipher cipher = CreateCipher(MkvBlockSize.Mkv128);
        byte[] plaintext = SeededBytes(length, 6);
        byte[] buffer = new byte[MkvCipher.GetKeyWrapPaddedLength(length)];
        plaintext.CopyTo(buffer, 0);

        cipher.EncryptKeyWrapPadded(buffer.AsSpan(0, length), buffer);
        Assert.Equal(cipher.EncryptKeyWrapPadded(plaintext), buffer);

        Assert.Equal(length, cipher.DecryptKeyWrapPadded(buffer, buffer));
        Assert.Equal(plaintext, buffer[..length]);
    }

    [Theory]
    [InlineData(false, false)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public void Unwrap_tampered_throws_and_zeroes(bool padded, bool inPlace)
    {
        using MkvCipher cipher = CreateCipher(MkvBlockSize.Mkv128);
        byte[] plaintext = SeededBytes(24, 7);
        byte[] ciphertext = padded ? cipher.EncryptKeyWrapPadded(plaintext) : cipher.EncryptKeyWrap(plaintext);
        ciphertext[^1] ^= 0x01;
        int plaintextCapacity = ciphertext.Length - 8;
        byte[] destination = inPlace ? ciphertext : Filled(plaintextCapacity, 0xAA);

        CryptographicException exception = padded
            ? Assert.Throws<CryptographicException>(() => cipher.DecryptKeyWrapPadded(ciphertext, destination))
            : Assert.Throws<CryptographicException>(() => cipher.DecryptKeyWrap(ciphertext, destination));

        Assert.Equal(DecryptFailure.Message, exception.Message);
        Assert.Equal(new byte[plaintextCapacity], destination[..plaintextCapacity]);
    }

    [Theory]
    [InlineData(0u, 16, (byte)0)]
    [InlineData(8u, 16, (byte)0)]
    [InlineData(17u, 16, (byte)0)]
    [InlineData(9u, 16, (byte)1)]
    [InlineData(9u, 8, (byte)0)]
    [InlineData(3u, 8, (byte)1)]
    public void Kwp_bad_length_header_fails_generically(uint mli, int paddedLength, byte lastByte)
    {
        using MkvCipher cipher = CreateCipher(MkvBlockSize.Mkv128);
        byte[] padded = new byte[paddedLength];
        padded[^1] = lastByte;
        byte[] ciphertext = CraftPadded(cipher, 0xA65959A6u, mli, padded);

        CryptographicException exception = Assert.Throws<CryptographicException>(() => cipher.DecryptKeyWrapPadded(ciphertext));

        Assert.Equal(DecryptFailure.Message, exception.Message);
    }

    [Fact]
    public void Kwp_wrong_prefix_fails_generically()
    {
        using MkvCipher cipher = CreateCipher(MkvBlockSize.Mkv128);
        byte[] ciphertext = CraftPadded(cipher, 0xA65959A7u, 16, new byte[16]);

        CryptographicException exception = Assert.Throws<CryptographicException>(() => cipher.DecryptKeyWrapPadded(ciphertext));

        Assert.Equal(DecryptFailure.Message, exception.Message);
    }

    [Theory]
    [InlineData(9, 16)]
    [InlineData(16, 16)]
    [InlineData(1, 8)]
    [InlineData(8, 8)]
    public void Kwp_valid_header_boundaries_round_trip(int mli, int paddedLength)
    {
        using MkvCipher cipher = CreateCipher(MkvBlockSize.Mkv128);
        byte[] plaintext = SeededBytes(mli, 8);
        byte[] padded = new byte[paddedLength];
        plaintext.CopyTo(padded, 0);
        byte[] ciphertext = CraftPadded(cipher, 0xA65959A6u, (uint)mli, padded);

        Assert.Equal(plaintext, cipher.DecryptKeyWrapPadded(ciphertext));
    }

    [Fact]
    public void Mkv256_throws_InvalidOperation()
    {
        using MkvCipher cipher = CreateCipher(MkvBlockSize.Mkv256);
        byte[] input = SeededBytes(16, 1);
        byte[] destination = Filled(64, 0xAA);

        Assert.Throws<InvalidOperationException>(() => cipher.EncryptKeyWrap(input));
        Assert.Throws<InvalidOperationException>(() => cipher.EncryptKeyWrap(input, destination));
        Assert.Throws<InvalidOperationException>(() => cipher.DecryptKeyWrap(input));
        Assert.Throws<InvalidOperationException>(() => cipher.DecryptKeyWrap(input, destination));
        Assert.Throws<InvalidOperationException>(() => cipher.EncryptKeyWrapPadded(input));
        Assert.Throws<InvalidOperationException>(() => cipher.EncryptKeyWrapPadded(input, destination));
        Assert.Throws<InvalidOperationException>(() => cipher.DecryptKeyWrapPadded(input));
        Assert.Throws<InvalidOperationException>(() => cipher.DecryptKeyWrapPadded(input, destination));
        Assert.Throws<InvalidOperationException>(() => cipher.TryDecryptKeyWrapPadded(input, destination, out _));

        Assert.Equal(Filled(64, 0xAA), destination);
    }

    [Theory]
    [MemberData(nameof(KwLengths))]
    public void Round_trip_mkv128_KW(int length)
    {
        using MkvCipher cipher = CreateCipher(MkvBlockSize.Mkv128);
        byte[] plaintext = SeededBytes(length, length);

        byte[] wrapped = cipher.EncryptKeyWrap(plaintext);
        Assert.Equal(length + 8, wrapped.Length);

        byte[] destination = new byte[wrapped.Length];
        cipher.EncryptKeyWrap(plaintext, destination);
        Assert.Equal(wrapped, destination);
        Assert.Equal(plaintext, cipher.DecryptKeyWrap(wrapped));
    }

    [Theory]
    [MemberData(nameof(PaddedLengths))]
    public void Round_trip_mkv128_KWP(int length)
    {
        using MkvCipher cipher = CreateCipher(MkvBlockSize.Mkv128);
        byte[] plaintext = SeededBytes(length, length);

        byte[] wrapped = cipher.EncryptKeyWrapPadded(plaintext);
        Assert.Equal(MkvCipher.GetKeyWrapPaddedLength(length), wrapped.Length);

        byte[] destination = new byte[wrapped.Length];
        cipher.EncryptKeyWrapPadded(plaintext, destination);
        Assert.Equal(wrapped, destination);
        Assert.Equal(plaintext, cipher.DecryptKeyWrapPadded(wrapped));

        byte[] unwrapped = new byte[wrapped.Length];
        Assert.True(cipher.TryDecryptKeyWrapPadded(wrapped, unwrapped, out int bytesWritten));
        Assert.Equal(plaintext, unwrapped[..bytesWritten]);
    }

    [Fact]
    public void Disposed_throws()
    {
        MkvCipher cipher = CreateCipher(MkvBlockSize.Mkv128);
        cipher.Dispose();
        byte[] input = Filled(16, 1);
        byte[] wrapped = Filled(24, 2);
        byte[] destination = new byte[64];

        Assert.Throws<ObjectDisposedException>(() => cipher.EncryptKeyWrap(input));
        Assert.Throws<ObjectDisposedException>(() => cipher.EncryptKeyWrap(input, destination));
        Assert.Throws<ObjectDisposedException>(() => cipher.DecryptKeyWrap(wrapped));
        Assert.Throws<ObjectDisposedException>(() => cipher.DecryptKeyWrap(wrapped, destination));
        Assert.Throws<ObjectDisposedException>(() => cipher.EncryptKeyWrapPadded(input));
        Assert.Throws<ObjectDisposedException>(() => cipher.EncryptKeyWrapPadded(input, destination));
        Assert.Throws<ObjectDisposedException>(() => cipher.DecryptKeyWrapPadded(wrapped));
        Assert.Throws<ObjectDisposedException>(() => cipher.DecryptKeyWrapPadded(wrapped, destination));
        Assert.Throws<ObjectDisposedException>(() => cipher.TryDecryptKeyWrapPadded(wrapped, destination, out _));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(8)]
    [InlineData(17)]
    public void Kw_encrypt_rejects_bad_plaintext_length_without_writing(int length)
    {
        using MkvCipher cipher = CreateCipher(MkvBlockSize.Mkv128);
        byte[] destination = Filled(length + 8, 0xAA);

        Assert.Throws<ArgumentException>(() => cipher.EncryptKeyWrap(new byte[length], destination));

        Assert.Equal(Filled(length + 8, 0xAA), destination);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(8)]
    [InlineData(16)]
    [InlineData(25)]
    public void Kw_decrypt_rejects_bad_ciphertext_length_without_writing(int length)
    {
        using MkvCipher cipher = CreateCipher(MkvBlockSize.Mkv128);
        byte[] destination = Filled(64, 0xAA);

        Assert.Throws<ArgumentException>(() => cipher.DecryptKeyWrap(new byte[length]));
        Assert.Throws<ArgumentException>(() => cipher.DecryptKeyWrap(new byte[length], destination));

        Assert.Equal(Filled(64, 0xAA), destination);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(8)]
    [InlineData(17)]
    public void Kwp_decrypt_rejects_bad_ciphertext_length_without_writing(int length)
    {
        using MkvCipher cipher = CreateCipher(MkvBlockSize.Mkv128);
        byte[] destination = Filled(64, 0xAA);

        Assert.Throws<ArgumentException>(() => cipher.DecryptKeyWrapPadded(new byte[length]));
        Assert.Throws<ArgumentException>(() => cipher.DecryptKeyWrapPadded(new byte[length], destination));

        Assert.Equal(Filled(64, 0xAA), destination);
    }

    [Fact]
    public void Kwp_encrypt_rejects_empty_plaintext_and_wrong_destination_size()
    {
        using MkvCipher cipher = CreateCipher(MkvBlockSize.Mkv128);

        Assert.Throws<ArgumentException>(() => cipher.EncryptKeyWrapPadded(Array.Empty<byte>()));
        Assert.Throws<ArgumentException>(() => cipher.EncryptKeyWrapPadded(new byte[5], new byte[15]));
        Assert.Throws<ArgumentException>(() => cipher.EncryptKeyWrapPadded(new byte[5], new byte[17]));
    }

    [Fact]
    public void Short_destination_is_refused_without_writing()
    {
        using MkvCipher cipher = CreateCipher(MkvBlockSize.Mkv128);
        byte[] kw = cipher.EncryptKeyWrap(SeededBytes(24, 9));
        byte[] kwp = cipher.EncryptKeyWrapPadded(SeededBytes(20, 9));

        byte[] shortKw = Filled(kw.Length - 9, 0xAA);
        Assert.Throws<ArgumentException>(() => cipher.DecryptKeyWrap(kw, shortKw));
        Assert.Equal(Filled(kw.Length - 9, 0xAA), shortKw);

        byte[] shortKwp = Filled(kwp.Length - 9, 0xAA);
        Assert.False(cipher.TryDecryptKeyWrapPadded(kwp, shortKwp, out int bytesWritten));
        Assert.Equal(0, bytesWritten);
        Assert.Equal(Filled(kwp.Length - 9, 0xAA), shortKwp);
        Assert.Throws<ArgumentException>(() => cipher.DecryptKeyWrapPadded(kwp, shortKwp));
    }

    [Fact]
    public void Partial_overlap_is_refused()
    {
        using MkvCipher cipher = CreateCipher(MkvBlockSize.Mkv128);
        byte[] buffer = new byte[25];

        Assert.Throws<ArgumentException>(() => cipher.EncryptKeyWrap(buffer.AsSpan(1, 16), buffer.AsSpan(0, 24)));
        Assert.Throws<ArgumentException>(() => cipher.DecryptKeyWrapPadded(buffer.AsSpan(1, 16), buffer.AsSpan(0, 16)));
    }

    [Fact]
    public void GetKeyWrapPaddedLength_rejects_empty_plaintext()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => MkvCipher.GetKeyWrapPaddedLength(0));
    }

    [Theory]
    [InlineData(1, 16)]
    [InlineData(8, 16)]
    [InlineData(9, 24)]
    [InlineData(16, 24)]
    [InlineData(17, 32)]
    public void GetKeyWrapPaddedLength_rounds_up_to_semiblocks_plus_iv(int plaintextLength, int expected)
    {
        Assert.Equal(expected, MkvCipher.GetKeyWrapPaddedLength(plaintextLength));
    }

    // Project-computed: generated once from the verified KW and KWP core, then frozen. Do not regenerate unless a
    // correctness bug is found.
    [Theory]
    [InlineData(MkvEngine.ConstantTime)]
    [InlineData(MkvEngine.VariableTime)]
    public void Frozen_mkv_vectors(MkvEngine engine)
    {
        using MkvCipher cipher = new(MkvBlockSize.Mkv128, Convert.FromHexString(FrozenKeyHex), MkvRevision.Rev2025, engine);

        Assert.Equal(FrozenKwCiphertextHex, Convert.ToHexString(cipher.EncryptKeyWrap(Convert.FromHexString(FrozenKwPlaintextHex))));
        Assert.Equal(FrozenKwpCiphertextHex, Convert.ToHexString(cipher.EncryptKeyWrapPadded(Convert.FromHexString(FrozenKwpPlaintextHex))));
    }

    private const string FrozenKeyHex = "000102030405060708090A0B0C0D0E0F";
    private const string FrozenKwPlaintextHex = "00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F";
    private const string FrozenKwpPlaintextHex = "C37B7E6492584340BED1220780894115" + "5068F738";
    private const string FrozenKwCiphertextHex = "D03204C083FE4D373CB54EE7BF09B9EE4D609262B517BC95C00D8AB247721BC8F3B1497E09D00B96";
    private const string FrozenKwpCiphertextHex = "21F27E4C68F32868FEDB2AF6CD92F6AEF385E9652FD7D9799735AE7D779C4326";

    private static readonly int[] KwLengthValues = [16, 24, 32, 40];

    public static IEnumerable<object[]> KwLengths() => KwLengthValues.Select(length => new object[] { length });

    public static IEnumerable<object[]> PaddedLengths() => Enumerable.Range(1, 40).Select(length => new object[] { length });

    // Wraps padded data under a header the test chooses, so the integrity and length rules can be checked on both sides.
    private static byte[] CraftPadded(MkvCipher cipher, uint prefix, uint mli, byte[] padded)
    {
        byte[] header = new byte[8];
        BinaryPrimitives.WriteUInt32BigEndian(header, prefix);
        BinaryPrimitives.WriteUInt32BigEndian(header.AsSpan(4), mli);
        byte[] ciphertext = new byte[padded.Length + 8];

        if (padded.Length == 8)
        {
            byte[] block = header.Concat(padded).ToArray();
            cipher.Engine.EncryptBlocks(cipher.RoundKeys, block, ciphertext);
        }
        else
        {
            KeyWrap.Wrap(cipher.Engine, cipher.RoundKeys, header, padded, ciphertext);
        }

        return ciphertext;
    }
}
