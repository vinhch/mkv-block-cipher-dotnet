using MkvBlockCipher.Kernels;
using MkvBlockCipher.Primitives;
using MkvBlockCipher.Tests.TestData;
using Xunit;

namespace MkvBlockCipher.Tests.Primitives;

public sealed class KeyScheduleTests
{
    [Theory]
    [MemberData(nameof(RoundKeys.Published), MemberType = typeof(RoundKeys))]
    public void Expand_matches_published_round_keys(
        MkvBlockSize blockSize, MkvRevision revision, string key, string[] expected)
    {
        byte[] keyBytes = Convert.FromHexString(key);
        MkvParameters parameters = MkvParameters.Create(blockSize, keyBytes.Length, revision);
        int blockBytes = parameters.BlockBytes;
        int roundKeyCount = 2 * parameters.Rounds + 1;
        byte[] roundKeys = new byte[roundKeyCount * blockBytes];

        KeySchedule.Expand(new ScalarEngine(parameters), keyBytes, roundKeys);

        string[] actual = new string[roundKeyCount];
        for (int i = 0; i < roundKeyCount; i++)
        {
            actual[i] = Convert.ToHexString(roundKeys.AsSpan(i * blockBytes, blockBytes));
        }

        Assert.Equal(expected, actual);
    }

    [Theory]
    [InlineData(15)]
    [InlineData(17)]
    public void Expand_rejects_key_of_wrong_length(int keyLength)
    {
        ScalarEngine engine = new(MkvParameters.Create(MkvBlockSize.Mkv128, 16, MkvRevision.Rev2024));
        byte[] roundKeys = new byte[13 * 16];

        ArgumentException exception = Assert.Throws<ArgumentException>(
            () => KeySchedule.Expand(engine, new byte[keyLength], roundKeys));
        Assert.Equal("key", exception.ParamName);
    }

    [Theory]
    [InlineData(13 * 16 - 1)]
    [InlineData(13 * 16 + 1)]
    public void Expand_rejects_round_keys_of_wrong_length(int roundKeyLength)
    {
        ScalarEngine engine = new(MkvParameters.Create(MkvBlockSize.Mkv128, 16, MkvRevision.Rev2024));
        byte[] roundKeys = new byte[roundKeyLength];

        ArgumentException exception = Assert.Throws<ArgumentException>(
            () => KeySchedule.Expand(engine, new byte[16], roundKeys));
        Assert.Equal("roundKeys", exception.ParamName);
    }
}
