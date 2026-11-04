using MkvBlockCipher.Tests.TestData;
using Xunit;

namespace MkvBlockCipher.Tests;

public sealed class MkvCipherBlockTests
{
    [Theory]
    [MemberData(nameof(KnownAnswerVectors.Published), MemberType = typeof(KnownAnswerVectors))]
    public void EncryptBlock_matches_published_vectors(
        MkvBlockSize blockSize, MkvRevision revision, string key, string plaintext, string ciphertext)
    {
        using MkvCipher cipher = new(blockSize, Convert.FromHexString(key), revision);

        Assert.Equal(ciphertext, Encrypt(cipher, Convert.FromHexString(plaintext)));
    }

    [Theory]
    [MemberData(nameof(KnownAnswerVectors.Published), MemberType = typeof(KnownAnswerVectors))]
    public void DecryptBlock_matches_published_vectors(
        MkvBlockSize blockSize, MkvRevision revision, string key, string plaintext, string ciphertext)
    {
        using MkvCipher cipher = new(blockSize, Convert.FromHexString(key), revision);
        byte[] decrypted = new byte[cipher.BlockSizeBytes];

        cipher.DecryptBlock(Convert.FromHexString(ciphertext), decrypted);

        Assert.Equal(plaintext, Convert.ToHexString(decrypted));
    }

    [Theory]
    [MemberData(nameof(KnownAnswerVectors.Published), MemberType = typeof(KnownAnswerVectors))]
    public void In_place_encrypt_and_decrypt_match_published_vectors(
        MkvBlockSize blockSize, MkvRevision revision, string key, string plaintext, string ciphertext)
    {
        using MkvCipher cipher = new(blockSize, Convert.FromHexString(key), revision);
        byte[] buffer = Convert.FromHexString(plaintext);

        cipher.EncryptBlock(buffer, buffer);
        Assert.Equal(ciphertext, Convert.ToHexString(buffer));

        cipher.DecryptBlock(buffer, buffer);
        Assert.Equal(plaintext, Convert.ToHexString(buffer));
    }

    [Theory]
    [MemberData(nameof(KnownAnswerVectors.Published), MemberType = typeof(KnownAnswerVectors))]
    public void VariableTime_matches_published_vectors(
        MkvBlockSize blockSize, MkvRevision revision, string key, string plaintext, string ciphertext)
    {
        using MkvCipher cipher = new(blockSize, Convert.FromHexString(key), revision, MkvEngine.VariableTime);
        byte[] decrypted = new byte[cipher.BlockSizeBytes];

        Assert.Equal(ciphertext, Encrypt(cipher, Convert.FromHexString(plaintext)));
        cipher.DecryptBlock(Convert.FromHexString(ciphertext), decrypted);
        Assert.Equal(plaintext, Convert.ToHexString(decrypted));
    }

    [Theory]
    [MemberData(nameof(Rev2025Cases))]
    public void Rev2025_matches_reference_on_every_engine(
        MkvBlockSize blockSize, string key, string plaintext, string ciphertext, MkvEngine engine)
    {
        using MkvCipher cipher = new(blockSize, Convert.FromHexString(key), MkvRevision.Rev2025, engine);
        byte[] decrypted = new byte[cipher.BlockSizeBytes];

        Assert.Equal(ciphertext, Encrypt(cipher, Convert.FromHexString(plaintext)));
        cipher.DecryptBlock(Convert.FromHexString(ciphertext), decrypted);
        Assert.Equal(plaintext, Convert.ToHexString(decrypted));
    }

    public static TheoryData<MkvBlockSize, string, string, string, MkvEngine> Rev2025Cases()
    {
        TheoryData<MkvBlockSize, string, string, string, MkvEngine> cases = new();
        foreach (TheoryDataRow<MkvBlockSize, string, string, string> row in Rev2025Vectors.Blocks)
        {
            (MkvBlockSize blockSize, string key, string plaintext, string ciphertext) = row.Data;
            foreach (MkvEngine engine in new[] { MkvEngine.ConstantTime, MkvEngine.VariableTime })
            {
                cases.Add(blockSize, key, plaintext, ciphertext, engine);
            }
        }

        return cases;
    }

    [Fact]
    public void Default_revision_is_Rev2026()
    {
        byte[] key = Convert.FromHexString(KnownAnswerVectors.Key16);
        byte[] plaintext = Convert.FromHexString(KnownAnswerVectors.Plaintext16);
        using MkvCipher defaulted = new(MkvBlockSize.Mkv128, key);
        using MkvCipher rev2026 = new(MkvBlockSize.Mkv128, key, MkvRevision.Rev2026);

        Assert.Equal(KnownAnswerVectors.Mkv128Rev2026Ciphertext, Encrypt(defaulted, plaintext));
        Assert.Equal(KnownAnswerVectors.Mkv128Rev2026Ciphertext, Encrypt(rev2026, plaintext));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(15)]
    [InlineData(17)]
    public void Wrong_key_length_throws(int keyLength)
    {
        AssertRejectsParameter("key", () => Construct(MkvBlockSize.Mkv128, new byte[keyLength]));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(16)]
    [InlineData(24)]
    [InlineData(33)]
    [InlineData(65)]
    public void Wrong_key_length_throws_for_Mkv256(int keyLength)
    {
        AssertRejectsParameter("key", () => Construct(MkvBlockSize.Mkv256, new byte[keyLength]));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(15)]
    [InlineData(17)]
    public void Wrong_block_length_throws(int length)
    {
        using MkvCipher cipher = new(MkvBlockSize.Mkv128, new byte[16]);
        byte[] odd = new byte[length];
        byte[] block = new byte[16];

        AssertRejectsParameter("source", () => cipher.EncryptBlock(odd, block));
        AssertRejectsParameter("destination", () => cipher.EncryptBlock(block, odd));
        AssertRejectsParameter("source", () => cipher.DecryptBlock(odd, block));
        AssertRejectsParameter("destination", () => cipher.DecryptBlock(block, odd));
    }

    [Theory]
    [InlineData(false, 0, 1)]
    [InlineData(false, 1, 0)]
    [InlineData(true, 0, 1)]
    [InlineData(true, 1, 0)]
    public void Partial_overlap_throws(bool decrypt, int sourceStart, int destinationStart)
    {
        using MkvCipher cipher = new(MkvBlockSize.Mkv128, new byte[16]);
        byte[] buffer = new byte[17];

        ArgumentException exception = Assert.Throws<ArgumentException>(
            () => Run(cipher, decrypt, buffer.AsSpan(sourceStart, 16), buffer.AsSpan(destinationStart, 16)));
        Assert.Equal("destination", exception.ParamName);
    }

    [Fact]
    public void Undefined_engine_value_throws()
    {
        Assert.Throws<ArgumentOutOfRangeException>(
            () => Construct(MkvBlockSize.Mkv128, new byte[16], MkvRevision.Rev2026, (MkvEngine)99));
    }

    [Fact]
    public void Caller_key_mutation_does_not_affect_cipher()
    {
        byte[] key = Convert.FromHexString(KnownAnswerVectors.Key16);
        using MkvCipher cipher = new(MkvBlockSize.Mkv128, key, MkvRevision.Rev2026);
        Array.Clear(key);

        Assert.Equal(
            KnownAnswerVectors.Mkv128Rev2026Ciphertext,
            Encrypt(cipher, Convert.FromHexString(KnownAnswerVectors.Plaintext16)));
    }

    [Fact]
    public void Methods_throw_after_dispose()
    {
        using MkvCipher cipher = new(MkvBlockSize.Mkv128, new byte[16]);
        byte[] block = new byte[16];
        cipher.Dispose();

        Assert.Throws<ObjectDisposedException>(() => cipher.EncryptBlock(block, block));
        Assert.Throws<ObjectDisposedException>(() => cipher.DecryptBlock(block, block));
    }

    [Fact]
    public void Dispose_twice_is_safe()
    {
        using MkvCipher cipher = new(MkvBlockSize.Mkv128, new byte[16]);
        cipher.Dispose();

        Assert.Null(Record.Exception(cipher.Dispose));
    }

    [Fact]
    public void Dispose_zeroes_round_keys()
    {
        using MkvCipher cipher = new(
            MkvBlockSize.Mkv128, Convert.FromHexString(KnownAnswerVectors.Key16), MkvRevision.Rev2026);
        byte[] before = cipher.RoundKeys.ToArray();
        Assert.NotEqual(new byte[before.Length], before);

        cipher.Dispose();

        Assert.Equal(new byte[before.Length], cipher.RoundKeys.ToArray());
    }

    private static string Encrypt(MkvCipher cipher, byte[] plaintext)
    {
        byte[] ciphertext = new byte[cipher.BlockSizeBytes];
        cipher.EncryptBlock(plaintext, ciphertext);
        return Convert.ToHexString(ciphertext);
    }

    private static void Construct(
        MkvBlockSize blockSize, byte[] key, MkvRevision revision = MkvRevision.Rev2026, MkvEngine engine = MkvEngine.ConstantTime)
    {
        using MkvCipher cipher = new(blockSize, key, revision, engine);
    }

    private static void Run(MkvCipher cipher, bool decrypt, ReadOnlySpan<byte> source, Span<byte> destination)
    {
        if (decrypt)
        {
            cipher.DecryptBlock(source, destination);
        }
        else
        {
            cipher.EncryptBlock(source, destination);
        }
    }

    private static void AssertRejectsParameter(string paramName, Action action)
    {
        ArgumentException exception = Assert.Throws<ArgumentException>(action);
        Assert.Equal(paramName, exception.ParamName);
    }
}
