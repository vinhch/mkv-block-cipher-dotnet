namespace MkvBlockCipher.Primitives;

// RotationStepBytes: word i is rotated left by i * RotationStepBytes in MixWords, 0 for no rotation.
// UsesRoundConstants: the key schedule keys its counter blocks with RoundConstants instead of zeros.
internal readonly record struct MkvParameters(
    int BlockBytes, int WordBytes, int KeyBytes, int Rounds, int RotationStepBytes, bool UsesRoundConstants)
{
    internal static MkvParameters Create(
        MkvBlockSize blockSize, int keyLength, MkvRevision revision, string keyParamName = "keyLength")
    {
        if (!Enum.IsDefined(blockSize))
        {
            throw new ArgumentOutOfRangeException(nameof(blockSize));
        }

        if (!Enum.IsDefined(revision))
        {
            throw new ArgumentOutOfRangeException(nameof(revision));
        }

        int blockBytes = blockSize == MkvBlockSize.Mkv128 ? 16 : 32;

        // A block is four words of equal size.
        int wordBytes = blockBytes / 4;

        int rounds = (blockSize, keyLength, revision) switch
        {
            (MkvBlockSize.Mkv128, 16, MkvRevision.Rev2024) => 6,
            (MkvBlockSize.Mkv128, 24, MkvRevision.Rev2024) => 7,
            (MkvBlockSize.Mkv128, 32, MkvRevision.Rev2024) => 8,
            (MkvBlockSize.Mkv256, 32, MkvRevision.Rev2024) => 6,
            (MkvBlockSize.Mkv256, 48, MkvRevision.Rev2024) => 7,
            (MkvBlockSize.Mkv256, 64, MkvRevision.Rev2024) => 8,
            (MkvBlockSize.Mkv128, 16, MkvRevision.Rev2026) => 7,
            (MkvBlockSize.Mkv128, 24, MkvRevision.Rev2026) => 8,
            (MkvBlockSize.Mkv128, 32, MkvRevision.Rev2026) => 9,
            (MkvBlockSize.Mkv256, 32, MkvRevision.Rev2026) => 7,
            (MkvBlockSize.Mkv256, 48, MkvRevision.Rev2026) => 8,
            (MkvBlockSize.Mkv256, 64, MkvRevision.Rev2026) => 9,
            (MkvBlockSize.Mkv128, 16, MkvRevision.Rev2025) => 7,
            (MkvBlockSize.Mkv128, 24, MkvRevision.Rev2025) => 8,
            (MkvBlockSize.Mkv128, 32, MkvRevision.Rev2025) => 9,
            (MkvBlockSize.Mkv256, 32, MkvRevision.Rev2025) => 7,
            (MkvBlockSize.Mkv256, 48, MkvRevision.Rev2025) => 8,
            (MkvBlockSize.Mkv256, 64, MkvRevision.Rev2025) => 9,
            _ => throw new ArgumentException("Key length is not valid for the block size.", keyParamName),
        };

        bool isRev2025 = revision == MkvRevision.Rev2025;
        int rotationStepBytes = isRev2025 ? wordBytes / 4 : 0;
        return new MkvParameters(blockBytes, wordBytes, keyLength, rounds, rotationStepBytes, isRev2025);
    }
}
