using MkvBlockCipher.Kernels;
using MkvBlockCipher.Primitives;
using Xunit;

namespace MkvBlockCipher.Tests.Modes;

internal static class ModeTestSupport
{
    public const MkvRevision Revision = MkvRevision.Rev2025;

    public static readonly MkvBlockSize[] BlockSizes = [MkvBlockSize.Mkv128, MkvBlockSize.Mkv256];

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

    public static TheoryData<MkvBlockSize, int> WrongLengthCases()
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

    public static int BlockBytes(MkvBlockSize blockSize) => blockSize == MkvBlockSize.Mkv128 ? 16 : 32;

    public static MkvCipher CreateCipher(MkvBlockSize blockSize) =>
        new(blockSize, SeededBytes(BlockBytes(blockSize), 1), Revision);

    // Block counts around the batch boundary, then several batches with a tail.
    public static IEnumerable<int> BatchBoundaryBlockCounts(int batch)
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

    // Half a block short: CTR ends on a partial block, and PKCS7 pads CBC up to `blocks` whole blocks.
    public static int PlaintextLengthFor(int blocks, int blockBytes) => blocks * blockBytes - blockBytes / 2;

    public static byte[] EncryptOneBlock(MkvCipher cipher, byte[] block)
    {
        byte[] output = new byte[block.Length];
        cipher.EncryptBlock(block, output);
        return output;
    }

    // Padding written out directly, so the reference does not depend on the code under test.
    public static byte[] PadReference(byte[] plaintext, int blockBytes)
    {
        int paddedLength = (plaintext.Length / blockBytes + 1) * blockBytes;
        byte[] padded = new byte[paddedLength];
        plaintext.CopyTo(padded, 0);
        Array.Fill(padded, (byte)(paddedLength - plaintext.Length), plaintext.Length, paddedLength - plaintext.Length);
        return padded;
    }

    public static byte[] ReferenceEncrypt(MkvCipher cipher, byte[] padded, byte[] iv)
    {
        int blockBytes = cipher.BlockSizeBytes;
        byte[] ciphertext = new byte[padded.Length];
        byte[] previous = iv;
        for (int offset = 0; offset < padded.Length; offset += blockBytes)
        {
            byte[] block = Xor(padded[offset..(offset + blockBytes)], previous);
            cipher.EncryptBlock(block, ciphertext.AsSpan(offset, blockBytes));
            previous = ciphertext[offset..(offset + blockBytes)];
        }

        return ciphertext;
    }

    public static byte[] Filled(int length, byte value) => Enumerable.Repeat(value, length).ToArray();

    public static byte[] Xor(byte[] left, byte[] right) => left.Zip(right, (a, b) => (byte)(a ^ b)).ToArray();

    public static byte[] SeededBytes(int length, int seed)
    {
        byte[] bytes = new byte[length];
        new Random(seed).NextBytes(bytes);
        return bytes;
    }

    public static void AssertRejectsParameter(string paramName, Action action)
    {
        ArgumentException exception = Assert.Throws<ArgumentException>(action);
        Assert.Equal(paramName, exception.ParamName);
    }
}
