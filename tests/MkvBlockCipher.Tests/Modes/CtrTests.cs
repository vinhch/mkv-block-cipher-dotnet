using System.Numerics;
using MkvBlockCipher.Kernels;
using MkvBlockCipher.Modes;
using MkvBlockCipher.Primitives;
using Xunit;

namespace MkvBlockCipher.Tests.Modes;

public sealed class CtrTests
{
    private const MkvRevision Revision = MkvRevision.Rev2026;
    private const byte Sentinel = 0x5A;

    // Widest batch of the supported engines.
    private const int WidestBatchBlocks = 32;

    private static readonly MkvBlockSize[] BlockSizes = [MkvBlockSize.Mkv128, MkvBlockSize.Mkv256];

    public static TheoryData<MkvBlockSize, int> RoundTripCases()
    {
        TheoryData<MkvBlockSize, int> cases = new();
        foreach (MkvBlockSize blockSize in BlockSizes)
        {
            int blockBytes = BlockBytes(blockSize);
            int maxBlocks = 3 * WidestBatchBlocks + 5;
            for (int blocks = 0; blocks <= maxBlocks; blocks++)
            {
                cases.Add(blockSize, blocks * blockBytes);
                cases.Add(blockSize, blocks * blockBytes + blockBytes - 1);
            }
        }

        return cases;
    }

    public static TheoryData<MkvBlockSize, int> WrongCounterCases()
    {
        TheoryData<MkvBlockSize, int> cases = new();
        foreach (MkvBlockSize blockSize in BlockSizes)
        {
            int blockBytes = BlockBytes(blockSize);
            cases.Add(blockSize, 0);
            cases.Add(blockSize, blockBytes - 1);
            cases.Add(blockSize, blockBytes + 1);
        }

        return cases;
    }

    public static TheoryData<MkvBlockSize, int> KeystreamIndexCases()
    {
        TheoryData<MkvBlockSize, int> cases = new();
        foreach (MkvBlockSize blockSize in BlockSizes)
        {
            foreach (int index in new[] { 0, 1, 255, 256 })
            {
                cases.Add(blockSize, index);
            }
        }

        return cases;
    }

    public static TheoryData<MkvBlockSize, string> EngineCases()
    {
        TheoryData<MkvBlockSize, string> cases = new();
        foreach (MkvBlockSize blockSize in BlockSizes)
        {
            MkvParameters parameters = MkvParameters.Create(blockSize, BlockBytes(blockSize), Revision);
            foreach (BlockEngine engine in EngineFactory.AllSupported(parameters))
            {
                cases.Add(blockSize, engine.GetType().Name);
            }
        }

        return cases;
    }

    [Theory]
    [MemberData(nameof(RoundTripCases))]
    public void Round_trip_lengths(MkvBlockSize blockSize, int length)
    {
        using MkvCipher cipher = Create(blockSize);
        byte[] counter = SeededBytes(BlockBytes(blockSize), 2);
        byte[] plaintext = SeededBytes(length, 3);

        byte[] ciphertext = cipher.TransformCtr(counter, plaintext);

        Assert.Equal(length, ciphertext.Length);
        Assert.Equal(plaintext, cipher.TransformCtr(counter, ciphertext));
    }

    [Theory]
    [InlineData(MkvBlockSize.Mkv128)]
    [InlineData(MkvBlockSize.Mkv256)]
    public void Empty_source_writes_nothing(MkvBlockSize blockSize)
    {
        using MkvCipher cipher = Create(blockSize);
        byte[] counter = Filled(BlockBytes(blockSize), 0xFF);
        byte[] destination = Filled(8, Sentinel);

        cipher.TransformCtr(counter, ReadOnlySpan<byte>.Empty, destination);

        Assert.Equal(Filled(8, Sentinel), destination);
        Assert.Empty(cipher.TransformCtr(counter, Array.Empty<byte>()));
    }

    [Theory]
    [MemberData(nameof(KeystreamIndexCases))]
    public void Keystream_block_i_equals_EncryptBlock_of_counter_plus_i(MkvBlockSize blockSize, int index)
    {
        using MkvCipher cipher = Create(blockSize);
        int blockBytes = BlockBytes(blockSize);
        byte[] counter = SeededBytes(blockBytes, 2);
        // Low byte at all-ones, so adding index > 0 carries into the byte above.
        counter[^1] = 0xFF;

        byte[] keystream = cipher.TransformCtr(counter, new byte[(index + 1) * blockBytes]);

        Assert.Equal(EncryptOneBlock(cipher, CounterPlus(counter, index)), keystream[(index * blockBytes)..]);
    }

    [Theory]
    [InlineData(MkvBlockSize.Mkv128)]
    [InlineData(MkvBlockSize.Mkv256)]
    public void Batch_boundaries_match_block_by_block_reference(MkvBlockSize blockSize)
    {
        using MkvCipher cipher = Create(blockSize);
        int blockBytes = BlockBytes(blockSize);
        // Low byte near all-ones, so the longer counts carry into the byte above.
        byte[] counter = SeededBytes(blockBytes, 2);
        counter[^1] = 0xF0;
        foreach (int blocks in BatchBoundaryBlockCounts(cipher.Engine.BatchBlocks))
        {
            byte[] plaintext = SeededBytes(PartialLengthFor(blocks, blockBytes), 3);
            byte[] keystream = ReferenceKeystream(cipher, counter, blocks);

            Assert.Equal(Xor(plaintext, keystream[..plaintext.Length]), cipher.TransformCtr(counter, plaintext));
        }
    }

    [Theory]
    [MemberData(nameof(EngineCases))]
    public void Every_engine_gives_the_same_keystream(MkvBlockSize blockSize, string engineName)
    {
        using MkvCipher cipher = Create(blockSize);
        int blockBytes = BlockBytes(blockSize);
        MkvParameters parameters = MkvParameters.Create(blockSize, blockBytes, Revision);
        BlockEngine engine = EngineFactory.AllSupported(parameters).Single(e => e.GetType().Name == engineName);
        BlockEngine reference = new ScalarEngine(parameters);
        byte[] roundKeys = cipher.RoundKeys.ToArray();
        byte[] counter = SeededBytes(blockBytes, 2);
        foreach (int blocks in BatchBoundaryBlockCounts(engine.BatchBlocks))
        {
            byte[] plaintext = SeededBytes(PartialLengthFor(blocks, blockBytes), 3);
            byte[] expected = new byte[plaintext.Length];
            byte[] actual = new byte[plaintext.Length];
            Ctr.Transform(reference, roundKeys, counter, plaintext, expected);
            Ctr.Transform(engine, roundKeys, counter, plaintext, actual);
            Assert.Equal(expected, actual);
        }
    }

    [Theory]
    [InlineData(MkvBlockSize.Mkv128)]
    [InlineData(MkvBlockSize.Mkv256)]
    public void Counter_wrap_throws(MkvBlockSize blockSize)
    {
        using MkvCipher cipher = Create(blockSize);
        int blockBytes = BlockBytes(blockSize);
        byte[] counter = Filled(blockBytes, 0xFF);
        byte[] destination = Filled(2 * blockBytes, Sentinel);

        AssertRejectsParameter("source", () => cipher.TransformCtr(counter, new byte[2 * blockBytes], destination));
        Assert.Equal(Filled(2 * blockBytes, Sentinel), destination);
        AssertRejectsParameter("source", () => cipher.TransformCtr(counter, new byte[2 * blockBytes]));
    }

    [Theory]
    [InlineData(MkvBlockSize.Mkv128)]
    [InlineData(MkvBlockSize.Mkv256)]
    public void Single_block_at_all_ones_succeeds(MkvBlockSize blockSize)
    {
        using MkvCipher cipher = Create(blockSize);
        byte[] counter = Filled(BlockBytes(blockSize), 0xFF);

        Assert.Equal(
            EncryptOneBlock(cipher, counter),
            cipher.TransformCtr(counter, new byte[BlockBytes(blockSize)]));
    }

    [Theory]
    [InlineData(MkvBlockSize.Mkv128)]
    [InlineData(MkvBlockSize.Mkv256)]
    public void Last_counter_at_all_ones_is_allowed_and_one_more_block_wraps(MkvBlockSize blockSize)
    {
        using MkvCipher cipher = Create(blockSize);
        int blockBytes = BlockBytes(blockSize);
        int blocks = cipher.Engine.BatchBlocks + 9;
        byte[] counter = Encode(AllOnes(blockBytes) - (blocks - 1), blockBytes);
        byte[] plaintext = SeededBytes(blocks * blockBytes - 3, 3);
        byte[] keystream = ReferenceKeystream(cipher, counter, blocks);

        Assert.Equal(Xor(plaintext, keystream[..plaintext.Length]), cipher.TransformCtr(counter, plaintext));

        byte[] longer = SeededBytes((blocks + 1) * blockBytes - 3, 3);
        byte[] destination = Filled(longer.Length, Sentinel);
        AssertRejectsParameter("source", () => cipher.TransformCtr(counter, longer, destination));
        Assert.Equal(Filled(longer.Length, Sentinel), destination);
    }

    [Theory]
    [InlineData(MkvBlockSize.Mkv128)]
    [InlineData(MkvBlockSize.Mkv256)]
    public void Counter_with_zero_last_byte_reaches_all_ones_at_256_blocks(MkvBlockSize blockSize)
    {
        using MkvCipher cipher = Create(blockSize);
        int blockBytes = BlockBytes(blockSize);
        // All-ones except a zero last byte: block 255 is all-ones, and block 256 would wrap past it.
        byte[] counter = Filled(blockBytes, 0xFF);
        counter[^1] = 0x00;
        byte[] plaintext = SeededBytes(256 * blockBytes, 3);
        byte[] keystream = ReferenceKeystream(cipher, counter, 256);

        Assert.Equal(Xor(plaintext, keystream), cipher.TransformCtr(counter, plaintext));
    }

    [Theory]
    [InlineData(MkvBlockSize.Mkv128)]
    [InlineData(MkvBlockSize.Mkv256)]
    public void Counter_with_zero_last_byte_wraps_at_257_blocks(MkvBlockSize blockSize)
    {
        using MkvCipher cipher = Create(blockSize);
        int blockBytes = BlockBytes(blockSize);
        byte[] counter = Filled(blockBytes, 0xFF);
        counter[^1] = 0x00;
        byte[] plaintext = new byte[257 * blockBytes];
        byte[] destination = Filled(plaintext.Length, Sentinel);

        AssertRejectsParameter("source", () => cipher.TransformCtr(counter, plaintext, destination));
        Assert.Equal(Filled(plaintext.Length, Sentinel), destination);
    }

    [Theory]
    [InlineData(MkvBlockSize.Mkv128)]
    [InlineData(MkvBlockSize.Mkv256)]
    public void In_place_matches_out_of_place(MkvBlockSize blockSize)
    {
        using MkvCipher cipher = Create(blockSize);
        int blockBytes = BlockBytes(blockSize);
        byte[] counter = SeededBytes(blockBytes, 2);
        foreach (int blocks in BatchBoundaryBlockCounts(cipher.Engine.BatchBlocks))
        {
            int length = PartialLengthFor(blocks, blockBytes);
            byte[] plaintext = SeededBytes(length, 3);
            byte[] expected = cipher.TransformCtr(counter, plaintext);
            byte[] buffer = Filled(length + 7, Sentinel);
            plaintext.CopyTo(buffer, 0);

            cipher.TransformCtr(counter, buffer.AsSpan(0, length), buffer);

            Assert.Equal(expected, buffer[..length]);
            Assert.Equal(Filled(7, Sentinel), buffer[length..]);
        }
    }

    [Theory]
    [InlineData(0, 1)]
    [InlineData(1, 0)]
    [InlineData(0, 8)]
    [InlineData(8, 0)]
    public void Partial_overlap_throws(int sourceStart, int destinationStart)
    {
        using MkvCipher cipher = Create(MkvBlockSize.Mkv128);
        byte[] buffer = new byte[64];

        ArgumentException exception = Assert.Throws<ArgumentException>(() => cipher.TransformCtr(
            new byte[16], buffer.AsSpan(sourceStart, 32), buffer.AsSpan(destinationStart, 32)));

        Assert.Equal("destination", exception.ParamName);
        Assert.Equal(new byte[64], buffer);
    }

    [Fact]
    public void Adjacent_buffers_are_accepted()
    {
        using MkvCipher cipher = Create(MkvBlockSize.Mkv128);
        byte[] counter = SeededBytes(16, 2);
        byte[] buffer = new byte[80];
        byte[] plaintext = SeededBytes(40, 3);
        plaintext.CopyTo(buffer, 0);
        byte[] expected = cipher.TransformCtr(counter, plaintext);

        cipher.TransformCtr(counter, buffer.AsSpan(0, 40), buffer.AsSpan(40));

        Assert.Equal(expected, buffer[40..]);
    }

    [Theory]
    [InlineData(MkvBlockSize.Mkv128)]
    [InlineData(MkvBlockSize.Mkv256)]
    public void Destination_tail_beyond_source_is_untouched(MkvBlockSize blockSize)
    {
        using MkvCipher cipher = Create(blockSize);
        byte[] counter = SeededBytes(BlockBytes(blockSize), 2);
        byte[] plaintext = SeededBytes(BlockBytes(blockSize) + 3, 3);
        byte[] destination = Filled(plaintext.Length + 9, Sentinel);

        cipher.TransformCtr(counter, plaintext, destination);

        Assert.Equal(cipher.TransformCtr(counter, plaintext), destination[..plaintext.Length]);
        Assert.Equal(Filled(9, Sentinel), destination[plaintext.Length..]);
    }

    [Theory]
    [InlineData(MkvBlockSize.Mkv128)]
    [InlineData(MkvBlockSize.Mkv256)]
    public void Destination_shorter_than_source_throws(MkvBlockSize blockSize)
    {
        using MkvCipher cipher = Create(blockSize);
        byte[] counter = SeededBytes(BlockBytes(blockSize), 2);
        byte[] plaintext = SeededBytes(BlockBytes(blockSize) + 3, 3);
        byte[] destination = Filled(plaintext.Length - 1, Sentinel);

        AssertRejectsParameter("destination", () => cipher.TransformCtr(counter, plaintext, destination));
        Assert.Equal(Filled(plaintext.Length - 1, Sentinel), destination);
    }

    [Theory]
    [MemberData(nameof(WrongCounterCases))]
    public void Wrong_counter_length_throws(MkvBlockSize blockSize, int counterLength)
    {
        using MkvCipher cipher = Create(blockSize);
        byte[] counter = new byte[counterLength];
        byte[] plaintext = SeededBytes(BlockBytes(blockSize), 3);
        byte[] destination = new byte[plaintext.Length];

        AssertRejectsParameter("initialCounter", () => cipher.TransformCtr(counter, plaintext, destination));
        AssertRejectsParameter("initialCounter", () => cipher.TransformCtr(counter, plaintext));
    }

    [Fact]
    public void Ctr_methods_throw_after_dispose()
    {
        using MkvCipher cipher = Create(MkvBlockSize.Mkv128);
        byte[] counter = new byte[16];
        byte[] data = new byte[32];
        cipher.Dispose();

        Assert.Throws<ObjectDisposedException>(() => cipher.TransformCtr(counter, data, new byte[32]));
        Assert.Throws<ObjectDisposedException>(() => cipher.TransformCtr(counter, data));
    }

    private static int BlockBytes(MkvBlockSize blockSize) => blockSize == MkvBlockSize.Mkv128 ? 16 : 32;

    private static MkvCipher Create(MkvBlockSize blockSize) =>
        new(blockSize, SeededBytes(BlockBytes(blockSize), 1), Revision);

    // Block counts around the batch boundary, then several batches with a tail.
    private static IEnumerable<int> BatchBoundaryBlockCounts(int batch)
    {
        yield return 1;
        if (batch > 1)
        {
            yield return batch - 1;
        }

        yield return batch;
        yield return batch + 1;
        yield return 3 * batch + 5;
    }

    // Half a block short, so the last block is partial.
    private static int PartialLengthFor(int blocks, int blockBytes) => blocks * blockBytes - blockBytes / 2;

    private static byte[] ReferenceKeystream(MkvCipher cipher, byte[] counter, int blocks)
    {
        int blockBytes = cipher.BlockSizeBytes;
        byte[] keystream = new byte[blocks * blockBytes];
        for (int i = 0; i < blocks; i++)
        {
            cipher.EncryptBlock(CounterPlus(counter, i), keystream.AsSpan(i * blockBytes, blockBytes));
        }

        return keystream;
    }

    private static byte[] CounterPlus(byte[] counter, int offset) =>
        Encode(new BigInteger(counter, isUnsigned: true, isBigEndian: true) + offset, counter.Length);

    private static BigInteger AllOnes(int blockBytes) => BigInteger.Pow(2, 8 * blockBytes) - 1;

    private static byte[] Encode(BigInteger value, int length)
    {
        byte[] raw = value.ToByteArray(isUnsigned: true, isBigEndian: true);
        byte[] bytes = new byte[length];
        raw.CopyTo(bytes, length - raw.Length);
        return bytes;
    }

    private static byte[] EncryptOneBlock(MkvCipher cipher, byte[] block)
    {
        byte[] output = new byte[block.Length];
        cipher.EncryptBlock(block, output);
        return output;
    }

    private static byte[] Filled(int length, byte value) => Enumerable.Repeat(value, length).ToArray();

    private static byte[] Xor(byte[] left, byte[] right) => left.Zip(right, (a, b) => (byte)(a ^ b)).ToArray();

    private static byte[] SeededBytes(int length, int seed)
    {
        byte[] bytes = new byte[length];
        new Random(seed).NextBytes(bytes);
        return bytes;
    }

    private static void AssertRejectsParameter(string paramName, Action action)
    {
        ArgumentException exception = Assert.Throws<ArgumentException>(action);
        Assert.Equal(paramName, exception.ParamName);
    }
}
