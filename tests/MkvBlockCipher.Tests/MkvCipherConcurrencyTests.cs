using Xunit;
using static MkvBlockCipher.Tests.Modes.ModeTestSupport;

namespace MkvBlockCipher.Tests;

public sealed class MkvCipherConcurrencyTests
{
    private const int BlockCount = 4;
    private const int Calls = 2_000;

    [Theory]
    [InlineData(MkvBlockSize.Mkv128)]
    [InlineData(MkvBlockSize.Mkv256)]
    public void Concurrent_calls_agree(MkvBlockSize blockSize)
    {
        using MkvCipher cipher = CreateCipher(blockSize);
        int blockBytes = BlockBytes(blockSize);
        byte[] iv = SeededBytes(blockBytes, 2);
        byte[] counter = SeededBytes(blockBytes, 3);
        byte[] plaintext = SeededBytes(BlockCount * blockBytes - blockBytes / 2, 4);

        byte[] expectedBlock = new byte[blockBytes];
        cipher.EncryptBlock(plaintext.AsSpan(0, blockBytes), expectedBlock);
        byte[] expectedCbc = cipher.EncryptCbc(plaintext, iv);
        byte[] expectedCtr = cipher.TransformCtr(counter, plaintext);

        Parallel.For(0, Calls, call =>
        {
            switch (call % 3)
            {
                case 0:
                    byte[] block = new byte[blockBytes];
                    cipher.EncryptBlock(plaintext.AsSpan(0, blockBytes), block);
                    Assert.Equal(expectedBlock, block);
                    break;
                case 1:
                    Assert.Equal(expectedCbc, cipher.EncryptCbc(plaintext, iv));
                    Assert.Equal(plaintext, cipher.DecryptCbc(expectedCbc, iv));
                    break;
                default:
                    Assert.Equal(expectedCtr, cipher.TransformCtr(counter, plaintext));
                    break;
            }
        });
    }

    [Fact]
    public void Concurrent_key_wrap_agrees()
    {
        using MkvCipher cipher = new(MkvBlockSize.Mkv128, SeededBytes(16, 1));
        byte[] key = SeededBytes(32, 5);
        byte[] expected = cipher.EncryptKeyWrap(key);

        Parallel.For(0, Calls, _ =>
        {
            Assert.Equal(expected, cipher.EncryptKeyWrap(key));
            Assert.Equal(key, cipher.DecryptKeyWrap(expected));
        });
    }
}
