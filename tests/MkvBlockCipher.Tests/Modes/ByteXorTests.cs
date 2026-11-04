using MkvBlockCipher.Modes;
using Xunit;
using static MkvBlockCipher.Tests.Modes.ModeTestSupport;

namespace MkvBlockCipher.Tests.Modes;

public sealed class ByteXorTests
{
    private const byte Sentinel = 0x5A;

    // Each length is its own case: 0 and the scalar tail, one 128-bit step, 256-bit steps with a 128-bit step and a tail after them.
    public static TheoryData<int> Lengths()
    {
        TheoryData<int> lengths = new();
        for (int length = 0; length <= 2 * 32 + 1; length++)
        {
            lengths.Add(length);
        }

        return lengths;
    }

    public static TheoryData<int, int, int, string> MismatchedLengthCases()
    {
        return new TheoryData<int, int, int, string>
        {
            { 16, 15, 16, "right" },
            { 16, 17, 16, "right" },
            { 16, 16, 15, "destination" },
            { 16, 16, 17, "destination" },
        };
    }

    [Theory]
    [MemberData(nameof(Lengths))]
    public void Xor_matches_scalar_for_every_length(int length)
    {
        byte[] left = SeededBytes(length, 1);
        byte[] right = SeededBytes(length, 2);
        byte[] expected = Xor(left, right);

        byte[] destination = new byte[length];
        ByteXor.Xor(left, right, destination);
        Assert.Equal(expected, destination);

        byte[] intoLeft = (byte[])left.Clone();
        ByteXor.Xor(intoLeft, right, intoLeft);
        Assert.Equal(expected, intoLeft);

        byte[] intoRight = (byte[])right.Clone();
        ByteXor.Xor(left, intoRight, intoRight);
        Assert.Equal(expected, intoRight);
    }

    [Theory]
    [MemberData(nameof(MismatchedLengthCases))]
    public void Xor_rejects_mismatched_lengths(int leftLength, int rightLength, int destinationLength, string paramName)
    {
        byte[] left = SeededBytes(leftLength, 1);
        byte[] right = SeededBytes(rightLength, 2);
        byte[] destination = Filled(destinationLength, Sentinel);

        AssertRejectsParameter(paramName, () => ByteXor.Xor(left, right, destination));
        Assert.Equal(Filled(destinationLength, Sentinel), destination);
    }
}
