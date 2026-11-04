using MkvBlockCipher.Kernels;
using Xunit;
using static MkvBlockCipher.Tests.Modes.ModeTestSupport;

namespace MkvBlockCipher.Tests.Kernels;

public sealed class ByteSliceTests
{
    // On x64 the 32-lane shapes take the vector path. (1, 16) and (3, 32) always take the scalar loops.
    [Theory]
    [InlineData(32, 16)]
    [InlineData(32, 32)]
    [InlineData(16, 16)]
    [InlineData(16, 32)]
    [InlineData(1, 16)]
    [InlineData(3, 32)]
    public void Vector_transpose_matches_scalar(int lanes, int blockBytes)
    {
        int length = lanes * blockBytes;
        byte[] blocks = SeededBytes(length, 1);
        byte[] expectedSliced = new byte[length];
        ByteSlice.GatherScalar(blocks, blockBytes, expectedSliced);

        byte[] sliced = new byte[length];
        ByteSlice.Gather(blocks, blockBytes, sliced);
        Assert.Equal(expectedSliced, sliced);

        byte[] restored = new byte[length];
        ByteSlice.Scatter(sliced, blockBytes, restored);
        Assert.Equal(blocks, restored);

        byte[] slicedInput = SeededBytes(length, 2);
        byte[] expectedBlocks = new byte[length];
        ByteSlice.ScatterScalar(slicedInput, blockBytes, expectedBlocks);
        byte[] scattered = new byte[length];
        ByteSlice.Scatter(slicedInput, blockBytes, scattered);
        Assert.Equal(expectedBlocks, scattered);
    }

    // Spans that are not exactly lanes * blockBytes long take the scalar loops.
    [Theory]
    [InlineData(0, 0)]
    [InlineData(512, 513)]
    [InlineData(513, 513)]
    public void Mismatched_spans_match_scalar(int blocksLength, int slicedLength)
    {
        const int blockBytes = 16;
        byte[] blocks = SeededBytes(blocksLength, 1);
        byte[] expectedSliced = new byte[slicedLength];
        ByteSlice.GatherScalar(blocks, blockBytes, expectedSliced);

        byte[] sliced = new byte[slicedLength];
        ByteSlice.Gather(blocks, blockBytes, sliced);
        Assert.Equal(expectedSliced, sliced);

        byte[] expectedBlocks = new byte[blocksLength];
        ByteSlice.ScatterScalar(sliced, blockBytes, expectedBlocks);
        byte[] scattered = new byte[blocksLength];
        ByteSlice.Scatter(sliced, blockBytes, scattered);
        Assert.Equal(expectedBlocks, scattered);
    }
}
