namespace MkvBlockCipher.Primitives;

internal readonly record struct MkvParameters(int BlockBytes, int WordBytes, int KeyBytes, int Rounds)
{
    internal static MkvParameters Create(MkvBlockSize blockSize, int keyLength, MkvRevision revision)
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
            _ => throw new ArgumentException("Key length is not valid for the block size.", nameof(keyLength)),
        };

        return new MkvParameters(blockBytes, wordBytes, keyLength, rounds);
    }
}
