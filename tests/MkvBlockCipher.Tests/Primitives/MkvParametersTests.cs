using MkvBlockCipher.Primitives;
using Xunit;

namespace MkvBlockCipher.Tests.Primitives;

public sealed class MkvParametersTests
{
    [Theory]
    [InlineData(MkvBlockSize.Mkv128, 16, MkvRevision.Rev2024, 16, 4, 6, 0, false)]
    [InlineData(MkvBlockSize.Mkv128, 24, MkvRevision.Rev2024, 16, 4, 7, 0, false)]
    [InlineData(MkvBlockSize.Mkv128, 32, MkvRevision.Rev2024, 16, 4, 8, 0, false)]
    [InlineData(MkvBlockSize.Mkv128, 16, MkvRevision.Rev2026, 16, 4, 7, 0, false)]
    [InlineData(MkvBlockSize.Mkv128, 24, MkvRevision.Rev2026, 16, 4, 8, 0, false)]
    [InlineData(MkvBlockSize.Mkv128, 32, MkvRevision.Rev2026, 16, 4, 9, 0, false)]
    [InlineData(MkvBlockSize.Mkv128, 16, MkvRevision.Rev2025, 16, 4, 7, 1, true)]
    [InlineData(MkvBlockSize.Mkv128, 24, MkvRevision.Rev2025, 16, 4, 8, 1, true)]
    [InlineData(MkvBlockSize.Mkv128, 32, MkvRevision.Rev2025, 16, 4, 9, 1, true)]
    [InlineData(MkvBlockSize.Mkv256, 32, MkvRevision.Rev2024, 32, 8, 6, 0, false)]
    [InlineData(MkvBlockSize.Mkv256, 48, MkvRevision.Rev2024, 32, 8, 7, 0, false)]
    [InlineData(MkvBlockSize.Mkv256, 64, MkvRevision.Rev2024, 32, 8, 8, 0, false)]
    [InlineData(MkvBlockSize.Mkv256, 32, MkvRevision.Rev2026, 32, 8, 7, 0, false)]
    [InlineData(MkvBlockSize.Mkv256, 48, MkvRevision.Rev2026, 32, 8, 8, 0, false)]
    [InlineData(MkvBlockSize.Mkv256, 64, MkvRevision.Rev2026, 32, 8, 9, 0, false)]
    [InlineData(MkvBlockSize.Mkv256, 32, MkvRevision.Rev2025, 32, 8, 7, 2, true)]
    [InlineData(MkvBlockSize.Mkv256, 48, MkvRevision.Rev2025, 32, 8, 8, 2, true)]
    [InlineData(MkvBlockSize.Mkv256, 64, MkvRevision.Rev2025, 32, 8, 9, 2, true)]
    public void Parameters_rounds_table(
        MkvBlockSize blockSize,
        int keyBytes,
        MkvRevision revision,
        int blockBytes,
        int wordBytes,
        int rounds,
        int rotationStepBytes,
        bool usesRoundConstants)
    {
        MkvParameters actual = MkvParameters.Create(blockSize, keyBytes, revision);

        Assert.Equal(
            new MkvParameters(blockBytes, wordBytes, keyBytes, rounds, rotationStepBytes, usesRoundConstants),
            actual);
    }

    [Theory]
    [InlineData(MkvBlockSize.Mkv128, 0, MkvRevision.Rev2026)]
    [InlineData(MkvBlockSize.Mkv128, -1, MkvRevision.Rev2026)]
    [InlineData(MkvBlockSize.Mkv128, 17, MkvRevision.Rev2026)]
    [InlineData(MkvBlockSize.Mkv128, 64, MkvRevision.Rev2026)]
    [InlineData(MkvBlockSize.Mkv256, 16, MkvRevision.Rev2026)]
    [InlineData(MkvBlockSize.Mkv128, 0, MkvRevision.Rev2025)]
    [InlineData(MkvBlockSize.Mkv128, -1, MkvRevision.Rev2025)]
    [InlineData(MkvBlockSize.Mkv128, 17, MkvRevision.Rev2025)]
    [InlineData(MkvBlockSize.Mkv128, 64, MkvRevision.Rev2025)]
    [InlineData(MkvBlockSize.Mkv256, 16, MkvRevision.Rev2025)]
    public void Create_invalid_key_length_throws(MkvBlockSize blockSize, int keyBytes, MkvRevision revision)
    {
        Assert.Throws<ArgumentException>(() => MkvParameters.Create(blockSize, keyBytes, revision));
    }

    [Theory]
    [InlineData((MkvBlockSize)2, MkvRevision.Rev2026)]
    [InlineData(MkvBlockSize.Mkv128, (MkvRevision)99)]
    public void Create_undefined_enum_value_throws(MkvBlockSize blockSize, MkvRevision revision)
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => MkvParameters.Create(blockSize, 16, revision));
    }
}
