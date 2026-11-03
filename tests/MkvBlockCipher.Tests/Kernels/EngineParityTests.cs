using MkvBlockCipher.Kernels;
using MkvBlockCipher.Primitives;
using Xunit;

namespace MkvBlockCipher.Tests.Kernels;

public sealed class EngineParityTests
{
    private const MkvRevision Revision = MkvRevision.Rev2026;

    private static readonly (MkvBlockSize BlockSize, int KeyLength)[] KeyLengths =
    [
        (MkvBlockSize.Mkv128, 16),
        (MkvBlockSize.Mkv128, 24),
        (MkvBlockSize.Mkv128, 32),
        (MkvBlockSize.Mkv256, 32),
        (MkvBlockSize.Mkv256, 48),
        (MkvBlockSize.Mkv256, 64),
    ];

    public static TheoryData<MkvBlockSize, int, string> EngineCases()
    {
        TheoryData<MkvBlockSize, int, string> cases = new();
        foreach ((MkvBlockSize blockSize, int keyLength) in KeyLengths)
        {
            MkvParameters parameters = MkvParameters.Create(blockSize, keyLength, Revision);
            foreach (BlockEngine engine in EngineFactory.AllSupported(parameters))
            {
                cases.Add(blockSize, keyLength, engine.GetType().Name);
            }
        }

        return cases;
    }

    [Theory]
    [MemberData(nameof(EngineCases))]
    public void Engines_match_scalar(MkvBlockSize blockSize, int keyLength, string engineName)
    {
        Subject subject = Subject.Create(blockSize, keyLength, engineName);
        Random random = new(1);

        AssertBlocksMatch(subject, random, inPlace: false);
        AssertRoundsMatch(subject, random);
    }

    [Theory]
    [MemberData(nameof(EngineCases))]
    public void Engines_support_in_place(MkvBlockSize blockSize, int keyLength, string engineName)
    {
        Subject subject = Subject.Create(blockSize, keyLength, engineName);
        Random random = new(2);

        AssertBlocksMatch(subject, random, inPlace: true);
        AssertRoundsMatch(subject, random);
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

    private static void AssertBlocksMatch(Subject subject, Random random, bool inPlace)
    {
        int blockBytes = subject.Parameters.BlockBytes;
        foreach (int blocks in BlockCounts(subject.Engine.BatchBlocks))
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
        internal static Subject Create(MkvBlockSize blockSize, int keyLength, string engineName)
        {
            MkvParameters parameters = MkvParameters.Create(blockSize, keyLength, Revision);
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
