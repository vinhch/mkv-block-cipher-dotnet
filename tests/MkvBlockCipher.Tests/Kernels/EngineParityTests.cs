using MkvBlockCipher.Kernels;
using MkvBlockCipher.Kernels.X64;
using MkvBlockCipher.Primitives;
using Xunit;

namespace MkvBlockCipher.Tests.Kernels;

public sealed class EngineParityTests
{
    private const string Avx512SkipReason = "Needs the AVX-512 engine, which this machine lacks.";

    private static readonly MkvRevision[] Revisions = [MkvRevision.Rev2024, MkvRevision.Rev2025];

    private static readonly (MkvBlockSize BlockSize, int KeyLength)[] KeyLengths =
    [
        (MkvBlockSize.Mkv128, 16),
        (MkvBlockSize.Mkv128, 24),
        (MkvBlockSize.Mkv128, 32),
        (MkvBlockSize.Mkv256, 32),
        (MkvBlockSize.Mkv256, 48),
        (MkvBlockSize.Mkv256, 64),
    ];

    public static bool Avx512Supported => X64Avx512Engine.IsSupported;

    public static TheoryData<MkvRevision, MkvBlockSize, int, string> EngineCases()
    {
        TheoryData<MkvRevision, MkvBlockSize, int, string> cases = new();
        foreach (MkvRevision revision in Revisions)
        {
            foreach ((MkvBlockSize blockSize, int keyLength) in KeyLengths)
            {
                MkvParameters parameters = MkvParameters.Create(blockSize, keyLength, revision);
                foreach (BlockEngine engine in EngineFactory.AllSupported(parameters))
                {
                    cases.Add(revision, blockSize, keyLength, engine.GetType().Name);
                }
            }
        }

        return cases;
    }

    [Theory]
    [MemberData(nameof(EngineCases))]
    public void Engines_match_scalar(MkvRevision revision, MkvBlockSize blockSize, int keyLength, string engineName)
    {
        Subject subject = Subject.Create(revision, blockSize, keyLength, engineName);
        Random random = new(1);

        AssertBlocksMatch(subject, random, inPlace: false);
        AssertRoundsMatch(subject, random);
    }

    [Theory]
    [MemberData(nameof(EngineCases))]
    public void Engines_support_in_place(MkvRevision revision, MkvBlockSize blockSize, int keyLength, string engineName)
    {
        Subject subject = Subject.Create(revision, blockSize, keyLength, engineName);
        Random random = new(2);

        AssertBlocksMatch(subject, random, inPlace: true);
        AssertRoundsMatch(subject, random);
    }

    // A tail of TailBatchThreshold - 1 blocks runs one block at a time; TailBatchThreshold blocks runs as a padded batch.
    [Theory(SkipUnless = nameof(Avx512Supported), Skip = Avx512SkipReason)]
    [InlineData(MkvBlockSize.Mkv128, 16, X64Avx512Engine.TailBatchThreshold - 1)]
    [InlineData(MkvBlockSize.Mkv128, 16, X64Avx512Engine.TailBatchThreshold)]
    [InlineData(MkvBlockSize.Mkv256, 32, X64Avx512Engine.TailBatchThreshold - 1)]
    [InlineData(MkvBlockSize.Mkv256, 32, X64Avx512Engine.TailBatchThreshold)]
    public void Avx512_tail_around_threshold_matches_scalar(MkvBlockSize blockSize, int keyLength, int tailBlocks)
    {
        Subject subject = Subject.Create(MkvRevision.Rev2025, blockSize, keyLength, nameof(X64Avx512Engine));
        int[] blockCounts = [subject.Engine.BatchBlocks + tailBlocks];

        AssertBlocksMatch(subject, new Random(3), inPlace: false, blockCounts);
        AssertBlocksMatch(subject, new Random(4), inPlace: true, blockCounts);
    }

    // Empty input, one block, the batch boundary on both sides, and a run of several batches with a tail.
    private static IEnumerable<int> BlockCounts(int batch)
    {
        yield return 0;
        yield return 1;
        if (batch > 1)
        {
            yield return batch - 1;
        }

        yield return batch;
        yield return batch + 1;
        yield return 3 * batch + 5;
    }

    private static void AssertBlocksMatch(Subject subject, Random random, bool inPlace) =>
        AssertBlocksMatch(subject, random, inPlace, BlockCounts(subject.Engine.BatchBlocks));

    private static void AssertBlocksMatch(Subject subject, Random random, bool inPlace, IEnumerable<int> blockCounts)
    {
        int blockBytes = subject.Parameters.BlockBytes;
        foreach (int blocks in blockCounts)
        {
            byte[] plaintext = RandomBytes(random, blocks * blockBytes);
            byte[] expectedCiphertext = new byte[plaintext.Length];
            subject.Reference.EncryptBlocks(subject.RoundKeys, plaintext, expectedCiphertext);

            byte[] ciphertext = new byte[plaintext.Length];
            plaintext.CopyTo(ciphertext, 0);
            subject.Engine.EncryptBlocks(subject.RoundKeys, inPlace ? ciphertext : plaintext, ciphertext);
            Assert.Equal(expectedCiphertext, ciphertext);

            byte[] decrypted = (byte[])expectedCiphertext.Clone();
            subject.Engine.DecryptBlocks(subject.RoundKeys, inPlace ? decrypted : expectedCiphertext, decrypted);
            Assert.Equal(plaintext, decrypted);
        }
    }

    private static void AssertRoundsMatch(Subject subject, Random random)
    {
        int blockBytes = subject.Parameters.BlockBytes;
        for (int i = 0; i < 32; i++)
        {
            byte[] state = RandomBytes(random, blockBytes);
            byte[] k0 = RandomBytes(random, blockBytes);
            byte[] k1 = RandomBytes(random, blockBytes);
            byte[] expected = (byte[])state.Clone();
            byte[] actual = (byte[])state.Clone();

            subject.Reference.Round(expected, k0, k1);
            subject.Engine.Round(actual, k0, k1);
            Assert.Equal(expected, actual);

            subject.Reference.InverseRound(expected, k0, k1);
            subject.Engine.InverseRound(actual, k0, k1);
            Assert.Equal(expected, actual);
            Assert.Equal(state, actual);
        }
    }

    private static byte[] RandomBytes(Random random, int length)
    {
        byte[] bytes = new byte[length];
        random.NextBytes(bytes);
        return bytes;
    }

    private sealed record Subject(MkvParameters Parameters, ScalarEngine Reference, BlockEngine Engine, byte[] RoundKeys)
    {
        // Round keys come from the key schedule run on each engine, so the schedule is checked for parity too.
        internal static Subject Create(MkvRevision revision, MkvBlockSize blockSize, int keyLength, string engineName)
        {
            MkvParameters parameters = MkvParameters.Create(blockSize, keyLength, revision);
            ScalarEngine reference = new(parameters);
            BlockEngine engine = EngineFactory.AllSupported(parameters).Single(e => e.GetType().Name == engineName);

            Random random = new(keyLength);
            byte[] key = RandomBytes(random, keyLength);
            int roundKeyBytes = (2 * parameters.Rounds + 1) * parameters.BlockBytes;
            byte[] expectedRoundKeys = new byte[roundKeyBytes];
            byte[] roundKeys = new byte[roundKeyBytes];
            KeySchedule.Expand(reference, key, expectedRoundKeys);
            KeySchedule.Expand(engine, key, roundKeys);
            Assert.Equal(expectedRoundKeys, roundKeys);

            return new Subject(parameters, reference, engine, roundKeys);
        }
    }
}
