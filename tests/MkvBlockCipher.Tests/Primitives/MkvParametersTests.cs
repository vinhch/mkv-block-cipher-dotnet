using MkvBlockCipher.Primitives;
using Xunit;

namespace MkvBlockCipher.Tests.Primitives;

public sealed class MkvParametersTests
{
    [Theory]
    [InlineData(MkvBlockSize.Mkv128, 16, MkvRevision.Rev2024, 16, 4, 6)]
    [InlineData(MkvBlockSize.Mkv128, 24, MkvRevision.Rev2024, 16, 4, 7)]
    [InlineData(MkvBlockSize.Mkv128, 32, MkvRevision.Rev2024, 16, 4, 8)]
    [InlineData(MkvBlockSize.Mkv128, 16, MkvRevision.Rev2026, 16, 4, 7)]
    [InlineData(MkvBlockSize.Mkv128, 24, MkvRevision.Rev2026, 16, 4, 8)]
    [InlineData(MkvBlockSize.Mkv128, 32, MkvRevision.Rev2026, 16, 4, 9)]
    [InlineData(MkvBlockSize.Mkv256, 32, MkvRevision.Rev2024, 32, 8, 6)]
    [InlineData(MkvBlockSize.Mkv256, 48, MkvRevision.Rev2024, 32, 8, 7)]
    [InlineData(MkvBlockSize.Mkv256, 64, MkvRevision.Rev2024, 32, 8, 8)]
    [InlineData(MkvBlockSize.Mkv256, 32, MkvRevision.Rev2026, 32, 8, 7)]
    [InlineData(MkvBlockSize.Mkv256, 48, MkvRevision.Rev2026, 32, 8, 8)]
    [InlineData(MkvBlockSize.Mkv256, 64, MkvRevision.Rev2026, 32, 8, 9)]
    public void Parameters_rounds_table(
        MkvBlockSize blockSize, int keyBytes, MkvRevision revision, int blockBytes, int wordBytes, int rounds)
    {
        MkvParameters actual = MkvParameters.Create(blockSize, keyBytes, revision);

        Assert.Equal(new MkvParameters(blockBytes, wordBytes, keyBytes, rounds), actual);
    }

    [Theory]
    [InlineData(MkvBlockSize.Mkv128, 0)]
    [InlineData(MkvBlockSize.Mkv128, -1)]
    [InlineData(MkvBlockSize.Mkv128, 17)]
    [InlineData(MkvBlockSize.Mkv128, 64)]
    [InlineData(MkvBlockSize.Mkv256, 16)]
    public void Create_invalid_key_length_throws(MkvBlockSize blockSize, int keyBytes)
    {
        Assert.Throws<ArgumentException>(() => MkvParameters.Create(blockSize, keyBytes, MkvRevision.Rev2026));
    }

    [Theory]
    [InlineData((MkvBlockSize)2, MkvRevision.Rev2026)]
    [InlineData(MkvBlockSize.Mkv128, (MkvRevision)2)]
    public void Create_undefined_enum_value_throws(MkvBlockSize blockSize, MkvRevision revision)
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => MkvParameters.Create(blockSize, 16, revision));
    }
}
