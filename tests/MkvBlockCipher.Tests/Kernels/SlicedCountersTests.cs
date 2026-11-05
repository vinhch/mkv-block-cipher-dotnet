using MkvBlockCipher.Kernels;
using MkvBlockCipher.Modes;
using MkvBlockCipher.Tests.Modes;
using Xunit;
using static MkvBlockCipher.Tests.Modes.ModeTestSupport;

namespace MkvBlockCipher.Tests.Kernels;

public sealed class SlicedCountersTests
{
    private const byte Sentinel = 0xA5;

    public static TheoryData<int, int, CarryShape, long> FillCases()
    {
        TheoryData<int, int, CarryShape, long> cases = new();
        foreach (int blockBytes in new[] { 16, 32 })
        {
            foreach (int lanes in new[] { 16, 32 })
            {
                foreach (CarryShape shape in Enum.GetValues<CarryShape>())
                {
                    // The last index straddles 2^40 inside the batch.
                    foreach (long firstIndex in new[] { 0L, 1L << 40, (1L << 40) - 8 })
                    {
                        cases.Add(blockBytes, lanes, shape, firstIndex);
                    }
                }
            }
        }

        return cases;
    }

    [Theory]
    [MemberData(nameof(FillCases))]
    public void SlicedCounters_match_fill_then_gather(int blockBytes, int lanes, CarryShape shape, long firstIndex)
    {
        byte[] initial = CarryCounter(blockBytes, shape);
        byte[] blocks = new byte[lanes * blockBytes];
        CounterBlock.Fill(blocks, initial, firstIndex);
        byte[] expected = new byte[blocks.Length];
        ByteSlice.Gather(blocks, blockBytes, expected);

        // Every byte must be written, so the sentinel must not survive.
        byte[] sliced = Filled(blocks.Length, Sentinel);
        SlicedCounters.Fill(initial, firstIndex, lanes, sliced);

        Assert.Equal(expected, sliced);
    }
}
