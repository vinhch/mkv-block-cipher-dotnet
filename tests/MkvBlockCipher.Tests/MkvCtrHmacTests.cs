using System.Security.Cryptography;
using MkvBlockCipher.Modes;
using Xunit;
using static MkvBlockCipher.Tests.Modes.ModeTestSupport;

namespace MkvBlockCipher.Tests;

public sealed class MkvCtrHmacTests
{
    private const byte Sentinel = 0x5A;
    private const int KeyLength = 32;
    private const int PlaintextLength = 40;
    private const int AssociatedDataLength = 13;
    private const string DecryptFailure = "The data could not be decrypted.";

    // Frozen output: any change here breaks stored ciphertexts.
    private const string FrozenCiphertextHex = "E0ADDEBF5F0A205F8C5E712D5A69";
    private const string FrozenTagHex = "802C647B6290E7F9A1D87CAA783137A775B82C6267E2C3F8C26B6FA0B8FCF502";

    // The encrypt path works in chunks of this size (MkvCtrHmac.FusedChunkBytes). The lengths sit one byte either side of it.
    private const int ChunkBytes = 4096;

    public static TheoryData<MkvBlockSize, int, int> RoundTripCases()
    {
        TheoryData<MkvBlockSize, int, int> cases = new();
        foreach (MkvBlockSize blockSize in BlockSizes)
        {
            int blockBytes = BlockBytes(blockSize);
            foreach (int plaintextLength in new[] { 0, 1, blockBytes, 1000 })
            {
                foreach (int adLength in new[] { 0, AssociatedDataLength })
                {
                    cases.Add(blockSize, plaintextLength, adLength);
                }
            }
        }

        return cases;
    }

    [Theory]
    [MemberData(nameof(RoundTripCases))]
    public void Round_trip(MkvBlockSize blockSize, int plaintextLength, int adLength)
    {
        using MkvCtrHmac mac = Create(blockSize);
        byte[] nonce = SeededBytes(mac.NonceSizeBytes, 2);
        byte[] associatedData = SeededBytes(adLength, 3);
        byte[] plaintext = SeededBytes(plaintextLength, 4);
        byte[] ciphertext = new byte[plaintextLength];
        byte[] tag = new byte[MkvCtrHmac.TagSizeBytes];

        mac.Encrypt(nonce, plaintext, ciphertext, tag, associatedData);

        byte[] decrypted = new byte[plaintextLength];
        mac.Decrypt(nonce, ciphertext, tag, decrypted, associatedData);
        Assert.Equal(plaintext, decrypted);
    }

    [Theory]
    [InlineData(MkvBlockSize.Mkv128)]
    [InlineData(MkvBlockSize.Mkv256)]
    public void Empty_plaintext_and_ad_still_authenticates(MkvBlockSize blockSize)
    {
        using MkvCtrHmac mac = Create(blockSize);
        byte[] nonce = SeededBytes(mac.NonceSizeBytes, 2);
        byte[] tag = new byte[MkvCtrHmac.TagSizeBytes];
        byte[] flippedTag = new byte[MkvCtrHmac.TagSizeBytes];
        byte[] otherAd = [0x01];
        byte[] tagWithAd = new byte[MkvCtrHmac.TagSizeBytes];

        mac.Encrypt(nonce, ReadOnlySpan<byte>.Empty, Span<byte>.Empty, tag);
        mac.Decrypt(nonce, ReadOnlySpan<byte>.Empty, tag, Span<byte>.Empty);

        mac.Encrypt(nonce, ReadOnlySpan<byte>.Empty, Span<byte>.Empty, tagWithAd, otherAd);
        Assert.NotEqual(tag, tagWithAd);
        Assert.Throws<CryptographicException>(
            () => mac.Decrypt(nonce, ReadOnlySpan<byte>.Empty, tag, Span<byte>.Empty, otherAd));

        tag.CopyTo(flippedTag, 0);
        flippedTag[0] ^= 0x01;
        Assert.Throws<CryptographicException>(
            () => mac.Decrypt(nonce, ReadOnlySpan<byte>.Empty, flippedTag, Span<byte>.Empty));
    }

    [Theory]
    [InlineData(MkvBlockSize.Mkv128)]
    [InlineData(MkvBlockSize.Mkv256)]
    public void Any_single_bit_flip_fails(MkvBlockSize blockSize)
    {
        using MkvCtrHmac mac = Create(blockSize);
        byte[] nonce = SeededBytes(mac.NonceSizeBytes, 2);
        byte[] associatedData = SeededBytes(AssociatedDataLength, 3);
        byte[] plaintext = SeededBytes(PlaintextLength, 4);
        byte[] ciphertext = new byte[PlaintextLength];
        byte[] tag = new byte[MkvCtrHmac.TagSizeBytes];
        mac.Encrypt(nonce, plaintext, ciphertext, tag, associatedData);

        byte[][] fields = [nonce, associatedData, ciphertext, tag];
        string[] fieldNames = ["nonce", "associated data", "ciphertext", "tag"];
        byte[] output = new byte[PlaintextLength];
        for (int field = 0; field < fields.Length; field++)
        {
            for (int index = 0; index < fields[field].Length; index++)
            {
                for (int bit = 0; bit < 8; bit++)
                {
                    byte mask = (byte)(1 << bit);
                    fields[field][index] ^= mask;
                    Array.Fill(output, Sentinel);
                    Exception? error = Record.Exception(
                        () => mac.Decrypt(nonce, ciphertext, tag, output, associatedData));
                    fields[field][index] ^= mask;

                    string location = $"{fieldNames[field]} byte {index} bit {bit}";
                    Assert.True(error is CryptographicException failure && failure.Message == DecryptFailure, location);
                    Assert.Equal(new byte[PlaintextLength], output);
                }
            }
        }
    }

    [Fact]
    public void Default_revision_produces_frozen_vector()
    {
        using MkvCtrHmac mac = new(MkvBlockSize.Mkv128, FrozenKey());

        AssertEncryptsFrozenVector(mac);
    }

    [Fact]
    public void Frozen_vector()
    {
        using MkvCtrHmac mac = new(MkvBlockSize.Mkv128, FrozenKey(), Revision);

        AssertEncryptsFrozenVector(mac);

        byte[] nonce = new byte[12];
        byte[] plaintext = FrozenPlaintext();
        byte[] decrypted = new byte[plaintext.Length];
        mac.Decrypt(nonce, Convert.FromHexString(FrozenCiphertextHex), Convert.FromHexString(FrozenTagHex), decrypted);
        Assert.Equal(plaintext, decrypted);
    }

    [Theory]
    [InlineData(MkvBlockSize.Mkv128)]
    [InlineData(MkvBlockSize.Mkv256)]
    public void Wrong_key_nonce_tag_lengths_throw(MkvBlockSize blockSize)
    {
        foreach (int keyLength in new[] { 0, 16, KeyLength - 1, KeyLength + 1, 64 })
        {
            byte[] key = new byte[keyLength];
            AssertRejectsParameter("key", () => _ = new MkvCtrHmac(blockSize, key, Revision));
        }

        using MkvCtrHmac mac = Create(blockSize);
        byte[] plaintext = SeededBytes(PlaintextLength, 3);
        byte[] ciphertext = new byte[PlaintextLength];
        byte[] tag = new byte[MkvCtrHmac.TagSizeBytes];
        byte[] output = new byte[PlaintextLength];
        foreach (int nonceLength in new[] { mac.NonceSizeBytes - 1, mac.NonceSizeBytes + 1 })
        {
            byte[] nonce = new byte[nonceLength];
            AssertRejectsParameter("nonce", () => mac.Encrypt(nonce, plaintext, ciphertext, tag));
            AssertRejectsParameter("nonce", () => mac.Decrypt(nonce, ciphertext, tag, output));
        }

        byte[] validNonce = new byte[mac.NonceSizeBytes];
        foreach (int tagLength in new[] { MkvCtrHmac.TagSizeBytes - 1, MkvCtrHmac.TagSizeBytes + 1 })
        {
            byte[] wrongTag = new byte[tagLength];
            AssertRejectsParameter("tag", () => mac.Encrypt(validNonce, plaintext, ciphertext, wrongTag));
            AssertRejectsParameter("tag", () => mac.Decrypt(validNonce, ciphertext, wrongTag, output));
        }
    }

    [Theory]
    [InlineData(MkvBlockSize.Mkv128, PlaintextLength - 1)]
    [InlineData(MkvBlockSize.Mkv128, PlaintextLength + 1)]
    [InlineData(MkvBlockSize.Mkv256, PlaintextLength - 1)]
    [InlineData(MkvBlockSize.Mkv256, PlaintextLength + 1)]
    public void Ciphertext_length_must_equal_plaintext_length(MkvBlockSize blockSize, int otherLength)
    {
        using MkvCtrHmac mac = Create(blockSize);
        byte[] nonce = SeededBytes(mac.NonceSizeBytes, 2);
        byte[] plaintext = SeededBytes(PlaintextLength, 3);
        byte[] tag = new byte[MkvCtrHmac.TagSizeBytes];
        byte[] other = new byte[otherLength];

        AssertRejectsParameter("ciphertext", () => mac.Encrypt(nonce, plaintext, other, tag));
        AssertRejectsParameter("plaintext", () => mac.Decrypt(nonce, other, tag, plaintext));
    }

    [Theory]
    [InlineData(0, 1)]
    [InlineData(1, 0)]
    [InlineData(0, 8)]
    [InlineData(8, 0)]
    public void Partial_overlap_throws(int plaintextStart, int ciphertextStart)
    {
        using MkvCtrHmac mac = Create(MkvBlockSize.Mkv128);
        byte[] buffer = new byte[64];
        byte[] nonce = new byte[mac.NonceSizeBytes];
        byte[] tag = new byte[MkvCtrHmac.TagSizeBytes];

        ArgumentException exception = Assert.Throws<ArgumentException>(
            () => mac.Encrypt(nonce, buffer.AsSpan(plaintextStart, 32), buffer.AsSpan(ciphertextStart, 32), tag));

        Assert.Equal("ciphertext", exception.ParamName);
        Assert.Equal(new byte[64], buffer);
    }

    [Theory]
    [InlineData(MkvBlockSize.Mkv128)]
    [InlineData(MkvBlockSize.Mkv256)]
    public void In_place_round_trip(MkvBlockSize blockSize)
    {
        using MkvCtrHmac mac = Create(blockSize);
        byte[] nonce = SeededBytes(mac.NonceSizeBytes, 2);
        byte[] associatedData = SeededBytes(AssociatedDataLength, 3);
        byte[] plaintext = SeededBytes(PlaintextLength, 4);
        byte[] expectedCiphertext = new byte[PlaintextLength];
        byte[] expectedTag = new byte[MkvCtrHmac.TagSizeBytes];
        mac.Encrypt(nonce, plaintext, expectedCiphertext, expectedTag, associatedData);

        byte[] buffer = (byte[])plaintext.Clone();
        byte[] tag = new byte[MkvCtrHmac.TagSizeBytes];
        mac.Encrypt(nonce, buffer, buffer, tag, associatedData);
        Assert.Equal(expectedCiphertext, buffer);
        Assert.Equal(expectedTag, tag);

        mac.Decrypt(nonce, buffer, tag, buffer, associatedData);
        Assert.Equal(plaintext, buffer);
    }

    public static TheoryData<MkvBlockSize, int, int> ChunkBoundaryCases()
    {
        TheoryData<MkvBlockSize, int, int> cases = new();
        foreach (MkvBlockSize blockSize in BlockSizes)
        {
            foreach (int plaintextLength in new[] { 0, 1, ChunkBytes - 1, ChunkBytes, ChunkBytes + 1, 3 * ChunkBytes + 5 })
            {
                foreach (int adLength in new[] { 0, AssociatedDataLength })
                {
                    cases.Add(blockSize, plaintextLength, adLength);
                }
            }
        }

        return cases;
    }

    [Theory]
    [MemberData(nameof(ChunkBoundaryCases))]
    public void Fused_encrypt_matches_two_pass(MkvBlockSize blockSize, int plaintextLength, int adLength)
    {
        byte[] key = SeededBytes(KeyLength, 1);
        using MkvCtrHmac mac = new(blockSize, key, Revision);
        byte[] nonce = SeededBytes(mac.NonceSizeBytes, 2);
        byte[] associatedData = SeededBytes(adLength, 3);
        byte[] plaintext = SeededBytes(plaintextLength, 4);
        byte[] ciphertext = new byte[plaintextLength];
        byte[] tag = new byte[MkvCtrHmac.TagSizeBytes];

        mac.Encrypt(nonce, plaintext, ciphertext, tag, associatedData);

        Assert.Equal(TwoPassCiphertext(blockSize, key, nonce, plaintext), ciphertext);
        byte[] decrypted = new byte[plaintextLength];
        mac.Decrypt(nonce, ciphertext, tag, decrypted, associatedData);
        Assert.Equal(plaintext, decrypted);
    }

    [Theory]
    [MemberData(nameof(ChunkBoundaryCases))]
    public void Fused_encrypt_in_place(MkvBlockSize blockSize, int plaintextLength, int adLength)
    {
        using MkvCtrHmac mac = Create(blockSize);
        byte[] nonce = SeededBytes(mac.NonceSizeBytes, 2);
        byte[] associatedData = SeededBytes(adLength, 3);
        byte[] plaintext = SeededBytes(plaintextLength, 4);
        byte[] expectedCiphertext = new byte[plaintextLength];
        byte[] expectedTag = new byte[MkvCtrHmac.TagSizeBytes];
        mac.Encrypt(nonce, plaintext, expectedCiphertext, expectedTag, associatedData);

        byte[] buffer = (byte[])plaintext.Clone();
        byte[] tag = new byte[MkvCtrHmac.TagSizeBytes];
        mac.Encrypt(nonce, buffer, buffer, tag, associatedData);

        Assert.Equal(expectedCiphertext, buffer);
        Assert.Equal(expectedTag, tag);
    }

    [Fact]
    public void Output_aliasing_an_input_throws()
    {
        using MkvCtrHmac mac = Create(MkvBlockSize.Mkv128);
        byte[] nonce = new byte[mac.NonceSizeBytes];
        byte[] plaintext = SeededBytes(PlaintextLength, 3);
        byte[] tag = new byte[MkvCtrHmac.TagSizeBytes];
        byte[] ciphertext = new byte[PlaintextLength];
        byte[] shared = Filled(64, Sentinel);

        // The ciphertext is written before the associated data is read for the tag.
        ArgumentException overAssociatedData = Assert.Throws<ArgumentException>(
            () => mac.Encrypt(nonce, plaintext, shared.AsSpan(0, PlaintextLength), tag, shared.AsSpan(20, AssociatedDataLength)));
        Assert.Equal("ciphertext", overAssociatedData.ParamName);

        ArgumentException tagOverCiphertext = Assert.Throws<ArgumentException>(
            () => mac.Encrypt(nonce, plaintext, shared.AsSpan(16, PlaintextLength), shared.AsSpan(0, MkvCtrHmac.TagSizeBytes)));
        Assert.Equal("tag", tagOverCiphertext.ParamName);

        ArgumentException plaintextOverTag = Assert.Throws<ArgumentException>(
            () => mac.Decrypt(nonce, ciphertext, shared.AsSpan(0, MkvCtrHmac.TagSizeBytes), shared.AsSpan(16, PlaintextLength)));
        Assert.Equal("plaintext", plaintextOverTag.ParamName);

        Assert.Equal(Filled(64, Sentinel), shared);
    }

    [Fact]
    public void Encrypt_output_overlapping_an_input_throws()
    {
        using MkvCtrHmac mac = Create(MkvBlockSize.Mkv128);
        byte[] nonce = new byte[mac.NonceSizeBytes];
        byte[] plaintext = SeededBytes(PlaintextLength, 3);
        byte[] ciphertext = new byte[PlaintextLength];
        byte[] tag = new byte[MkvCtrHmac.TagSizeBytes];

        AssertAliasRejected("ciphertext", shared => mac.Encrypt(
            shared.AsSpan(0, mac.NonceSizeBytes), plaintext, shared.AsSpan(8, PlaintextLength), tag));
        AssertAliasRejected("tag", shared => mac.Encrypt(
            nonce, shared.AsSpan(0, PlaintextLength), ciphertext, shared.AsSpan(20, MkvCtrHmac.TagSizeBytes)));
        AssertAliasRejected("tag", shared => mac.Encrypt(
            shared.AsSpan(0, mac.NonceSizeBytes), plaintext, ciphertext, shared.AsSpan(4, MkvCtrHmac.TagSizeBytes)));
        AssertAliasRejected("tag", shared => mac.Encrypt(
            nonce, plaintext, ciphertext, shared.AsSpan(8, MkvCtrHmac.TagSizeBytes), shared.AsSpan(0, AssociatedDataLength)));
    }

    [Fact]
    public void Decrypt_output_overlapping_an_input_throws()
    {
        using MkvCtrHmac mac = Create(MkvBlockSize.Mkv128);
        byte[] nonce = new byte[mac.NonceSizeBytes];
        byte[] ciphertext = new byte[PlaintextLength];
        byte[] tag = new byte[MkvCtrHmac.TagSizeBytes];

        AssertAliasRejected("plaintext", shared => mac.Decrypt(
            shared.AsSpan(0, mac.NonceSizeBytes), ciphertext, tag, shared.AsSpan(8, PlaintextLength)));
        AssertAliasRejected("plaintext", shared => mac.Decrypt(
            nonce, ciphertext, tag, shared.AsSpan(10, PlaintextLength), shared.AsSpan(0, AssociatedDataLength)));
        AssertAliasRejected("plaintext", shared => mac.Decrypt(
            nonce, shared.AsSpan(0, PlaintextLength), tag, shared.AsSpan(8, PlaintextLength)));
    }

    [Fact]
    public void Rejected_encrypt_leaves_the_next_tag_unchanged()
    {
        using MkvCtrHmac mac = Create(MkvBlockSize.Mkv128);
        byte[] nonce = SeededBytes(mac.NonceSizeBytes, 2);
        byte[] associatedData = SeededBytes(AssociatedDataLength, 3);
        byte[] plaintext = SeededBytes(PlaintextLength, 4);
        byte[] ciphertext = new byte[PlaintextLength];
        byte[] expectedTag = new byte[MkvCtrHmac.TagSizeBytes];
        byte[] tag = new byte[MkvCtrHmac.TagSizeBytes];
        mac.Encrypt(nonce, plaintext, ciphertext, expectedTag, associatedData);

        byte[] shared = Filled(64, Sentinel);
        Assert.Throws<ArgumentException>(
            () => mac.Encrypt(nonce, plaintext, shared.AsSpan(0, PlaintextLength), tag, shared.AsSpan(20, AssociatedDataLength)));

        mac.Encrypt(nonce, plaintext, ciphertext, tag, associatedData);
        Assert.Equal(expectedTag, tag);
    }

    [Fact]
    public void Key_is_read_only_during_construction()
    {
        byte[] key = SeededBytes(KeyLength, 1);
        byte[] nonce = new byte[12];
        byte[] plaintext = SeededBytes(PlaintextLength, 3);
        byte[] expectedCiphertext = new byte[PlaintextLength];
        byte[] expectedTag = new byte[MkvCtrHmac.TagSizeBytes];
        using (MkvCtrHmac beforeMutation = new(MkvBlockSize.Mkv128, key, Revision))
        {
            beforeMutation.Encrypt(nonce, plaintext, expectedCiphertext, expectedTag);
        }

        using MkvCtrHmac mac = new(MkvBlockSize.Mkv128, key, Revision);
        Array.Fill(key, (byte)0xFF);
        byte[] ciphertext = new byte[PlaintextLength];
        byte[] tag = new byte[MkvCtrHmac.TagSizeBytes];

        mac.Encrypt(nonce, plaintext, ciphertext, tag);

        Assert.Equal(expectedCiphertext, ciphertext);
        Assert.Equal(expectedTag, tag);
    }

    [Theory]
    [InlineData(MkvBlockSize.Mkv128, 12)]
    [InlineData(MkvBlockSize.Mkv256, 28)]
    public void Nonce_size_is_block_size_minus_four(MkvBlockSize blockSize, int expectedNonceSize)
    {
        using MkvCtrHmac mac = Create(blockSize);

        Assert.Equal(expectedNonceSize, mac.NonceSizeBytes);
        Assert.Equal(32, MkvCtrHmac.TagSizeBytes);
    }

    [Fact]
    public void Undefined_enum_values_throw()
    {
        byte[] key = SeededBytes(KeyLength, 1);

        Assert.Throws<ArgumentOutOfRangeException>(() => new MkvCtrHmac((MkvBlockSize)2, key, Revision));
        Assert.Throws<ArgumentOutOfRangeException>(() => new MkvCtrHmac(MkvBlockSize.Mkv128, key, (MkvRevision)99));
        Assert.Throws<ArgumentOutOfRangeException>(() => new MkvCtrHmac(MkvBlockSize.Mkv128, key, Revision, (MkvEngine)99));
    }

    [Theory]
    [InlineData(16)]
    [InlineData(32)]
    public void Max_length_guard(int blockBytes)
    {
        long maxBytes = (long)uint.MaxValue * blockBytes;

        CtrHmacKeys.ThrowIfTooLong(maxBytes, blockBytes, "plaintext");
        ArgumentException exception = Assert.Throws<ArgumentException>(
            () => CtrHmacKeys.ThrowIfTooLong(maxBytes + 1, blockBytes, "plaintext"));
        Assert.Equal("plaintext", exception.ParamName);
    }

    [Theory]
    [InlineData(MkvBlockSize.Mkv128)]
    [InlineData(MkvBlockSize.Mkv256)]
    public void Throws_after_dispose(MkvBlockSize blockSize)
    {
        MkvCtrHmac mac = Create(blockSize);
        byte[] nonce = SeededBytes(mac.NonceSizeBytes, 2);
        byte[] data = SeededBytes(PlaintextLength, 3);
        byte[] tag = new byte[MkvCtrHmac.TagSizeBytes];
        mac.Dispose();

        Assert.Throws<ObjectDisposedException>(() => mac.Encrypt(nonce, data, new byte[PlaintextLength], tag));
        Assert.Throws<ObjectDisposedException>(() => mac.Decrypt(nonce, data, tag, new byte[PlaintextLength]));
    }

    [Fact]
    public void Dispose_twice_is_safe()
    {
        MkvCtrHmac mac = Create(MkvBlockSize.Mkv128);

        mac.Dispose();
        mac.Dispose();
    }

    private static MkvCtrHmac Create(MkvBlockSize blockSize) => new(blockSize, SeededBytes(KeyLength, 1), Revision);

    private static byte[] FrozenKey() => Enumerable.Range(0, KeyLength).Select(i => (byte)i).ToArray();

    private static byte[] FrozenPlaintext() => "MkvBlockCipher"u8.ToArray();

    private static void AssertEncryptsFrozenVector(MkvCtrHmac mac)
    {
        byte[] nonce = new byte[12];
        byte[] plaintext = FrozenPlaintext();
        byte[] ciphertext = new byte[plaintext.Length];
        byte[] tag = new byte[MkvCtrHmac.TagSizeBytes];

        mac.Encrypt(nonce, plaintext, ciphertext, tag);

        Assert.Equal(FrozenCiphertextHex, Convert.ToHexString(ciphertext));
        Assert.Equal(FrozenTagHex, Convert.ToHexString(tag));
    }

    // Reference for the encrypt path: plain CTR under the derived encryption key, counter = nonce || 00000001.
    private static byte[] TwoPassCiphertext(MkvBlockSize blockSize, byte[] key, byte[] nonce, byte[] plaintext)
    {
        int blockBytes = BlockBytes(blockSize);
        byte[] encKey = new byte[CtrHmacKeys.EncKeyBytes(blockBytes)];
        CtrHmacKeys.Derive(key, "enc", blockBytes, Revision, encKey);
        using MkvCipher cipher = new(blockSize, encKey, Revision);
        byte[] initialCounter = [.. nonce, 0x00, 0x00, 0x00, 0x01];
        return cipher.TransformCtr(initialCounter, plaintext);
    }

    // Output and input share one sentinel buffer, so the rejection must come before any write.
    private static void AssertAliasRejected(string paramName, Action<byte[]> call)
    {
        byte[] shared = Filled(64, Sentinel);
        ArgumentException exception = Assert.Throws<ArgumentException>(() => call(shared));
        Assert.Equal(paramName, exception.ParamName);
        Assert.Equal(Filled(64, Sentinel), shared);
    }
}
