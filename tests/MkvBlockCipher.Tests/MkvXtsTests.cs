using Xunit;
using static MkvBlockCipher.Tests.Modes.ModeTestSupport;

namespace MkvBlockCipher.Tests;

public sealed class MkvXtsTests
{
    private const int BlockBytes = 16;
    private const int MaxDataBytes = 1 << 24;

    public static TheoryData<int> InPlaceLengths()
    {
        TheoryData<int> cases = new();
        for (int length = BlockBytes; length <= 2 * BlockBytes + 1; length++)
        {
            cases.Add(length);
        }

        cases.Add(4096);
        return cases;
    }

    [Theory]
    [MemberData(nameof(InPlaceLengths))]
    public void In_place_round_trip(int length)
    {
        using MkvXts xts = new(SeededBytes(32, 1));
        byte[] plaintext = SeededBytes(length, 2);
        byte[] expected = new byte[length];
        xts.Encrypt(7, plaintext, expected);

        byte[] buffer = plaintext.ToArray();
        xts.Encrypt(7, buffer, buffer);
        Assert.Equal(expected, buffer);

        xts.Decrypt(7, buffer, buffer);
        Assert.Equal(plaintext, buffer);
    }

    // Frozen output, computed by this implementation and not a published vector. Any change here breaks stored sectors.
    private const string FrozenCiphertext =
        "641B9D179E91E83E416EB357807291B13CBB082FBC22B6A609957A4774FA9AD10D4FF02F1F2C49E03BF82D3F2827147A8443C38382C7B76928DABF80719CB8A6" +
        "62E52AD629A5E3AAF4D8E01FF0281269CC5F923C818BC1D00576B130365131929143A681743835454B5D1C537B8395EBA30BF722189951DE9142E11F8190BCF0" +
        "FA9D6693D628CD879BB13104E527EED7610315933EE9F950C7C51B80ABD3DAFCACFBD1878862DFCE9A85BBBC02DCD0D8822C24361DC95AD5BBA32591B51E5F6F" +
        "51906608B3C85F20B6C8EF189C43B87F2E6C3FD16D974598D49311C740AFB1FD3B994944E2B2316960B84F05D749893E18C8B82172E8E92C71322180819BBEFF" +
        "5ED649E90BB4AE666A39C4E55BC1602EDC4FF6345151933F806A1B51B9B1E48D0CA1BDD91158955EB14FAA47DD63C187C95D00F9CA893B1924DBD8A3FCCB9E70" +
        "DF0BEC47EF02214C403F342964CD35F25669532727420483FDF09E426FF0BB861F872DD5C9A9C776009136DD01B5B827B9AA317EE9CE7FBD14BDA76B2EB6267D" +
        "B492F6102728C5767A755515B13546DB2C497282F937F4BBA78F03127FA504058CD4CC1BCBFAE90C46C14AB8F97BF0C57FD8C715C99485CC57611AAC23B8E314" +
        "7960FF4366CF7C1FD07228F1D42118379322BF5B15F5F984542E24482CF03D6310D86F1674B546877D283D2CCAFCF053660E5A1BFBD847F82D0857DE86E815DE";

    [Fact]
    public void Frozen_mkv_vector()
    {
        using MkvXts xts = new(SeededBytes(32, 3));
        byte[] plaintext = SeededBytes(512, 4);
        byte[] ciphertext = new byte[512];

        xts.Encrypt(0x0123456789ABCDEF, plaintext, ciphertext);
        Assert.Equal(FrozenCiphertext, Convert.ToHexString(ciphertext));
    }

    [Theory]
    [InlineData(MkvEngine.VariableTime)]
    public void Engine_choice_does_not_change_output(MkvEngine engine)
    {
        byte[] key = SeededBytes(64, 21);
        byte[] plaintext = SeededBytes(87, 22);
        using MkvXts reference = new(key);
        using MkvXts other = new(key, engine: engine);
        byte[] expected = new byte[87];
        byte[] actual = new byte[87];

        reference.Encrypt(5, plaintext, expected);
        other.Encrypt(5, plaintext, actual);
        Assert.Equal(expected, actual);
    }

    [Fact]
    public void Key_halves_equal_throws()
    {
        byte[] half = SeededBytes(16, 5);
        byte[] key = [.. half, .. half];
        Assert.Throws<ArgumentException>(() => new MkvXts(key));

        byte[] wideHalf = SeededBytes(32, 6);
        byte[] wideKey = [.. wideHalf, .. wideHalf];
        Assert.Throws<ArgumentException>(() => new MkvXts(wideKey));
    }

    [Fact]
    public void Key_length_48_throws()
    {
        Assert.Throws<ArgumentException>(() => new MkvXts(SeededBytes(48, 7)));
    }

    [Fact]
    public void Length_15_throws()
    {
        using MkvXts xts = new(SeededBytes(32, 8));
        byte[] buffer = new byte[15];

        Assert.Throws<ArgumentException>(() => xts.Encrypt(1, buffer, new byte[15]));
        Assert.Throws<ArgumentException>(() => xts.Decrypt(1, buffer, new byte[15]));
    }

    [Fact]
    public void Length_above_2_pow_20_blocks_throws()
    {
        using MkvXts xts = new(SeededBytes(32, 9));
        byte[] plaintext = SeededBytes(MaxDataBytes + BlockBytes, 10);
        byte[] ciphertext = new byte[plaintext.Length];

        Assert.Throws<ArgumentException>(() => xts.Encrypt(1, plaintext, ciphertext));
        Assert.False(ciphertext.AsSpan().ContainsAnyExcept((byte)0));
    }

    [Fact]
    public void Length_2_pow_20_blocks_is_accepted()
    {
        using MkvXts xts = new(SeededBytes(32, 11));
        byte[] plaintext = SeededBytes(MaxDataBytes, 12);
        byte[] ciphertext = new byte[plaintext.Length];
        byte[] decrypted = new byte[plaintext.Length];

        xts.Encrypt(1, plaintext, ciphertext);
        xts.Decrypt(1, ciphertext, decrypted);
        Assert.Equal(plaintext, decrypted);
    }

    [Fact]
    public void Destination_length_mismatch_throws()
    {
        using MkvXts xts = new(SeededBytes(32, 13));
        byte[] plaintext = SeededBytes(32, 14);

        Assert.Throws<ArgumentException>(() => xts.Encrypt(1, plaintext, new byte[31]));
        Assert.Throws<ArgumentException>(() => xts.Decrypt(1, plaintext, new byte[33]));
    }

    [Fact]
    public void Partial_overlap_throws()
    {
        using MkvXts xts = new(SeededBytes(32, 15));
        byte[] buffer = SeededBytes(48, 16);

        Assert.Throws<ArgumentException>(() => xts.Encrypt(1, buffer.AsSpan(0, 32), buffer.AsSpan(8, 32)));
        Assert.Throws<ArgumentException>(() => xts.Decrypt(1, buffer.AsSpan(0, 32), buffer.AsSpan(8, 32)));
    }

    [Fact]
    public void Different_unit_numbers_differ()
    {
        using MkvXts xts = new(SeededBytes(32, 17));
        byte[] plaintext = SeededBytes(64, 18);
        byte[] first = new byte[64];
        byte[] second = new byte[64];
        byte[] repeat = new byte[64];

        xts.Encrypt(0, plaintext, first);
        xts.Encrypt(1, plaintext, second);
        xts.Encrypt(0, plaintext, repeat);

        Assert.NotEqual(first, second);
        Assert.Equal(first, repeat);
    }

    [Fact]
    public void Disposed_throws()
    {
        MkvXts xts = new(SeededBytes(32, 19));
        byte[] plaintext = SeededBytes(32, 20);
        byte[] buffer = new byte[32];
        xts.Dispose();
        xts.Dispose();

        Assert.Throws<ObjectDisposedException>(() => xts.Encrypt(1, plaintext, buffer));
        Assert.Throws<ObjectDisposedException>(() => xts.Decrypt(1, plaintext, buffer));
    }

    [Fact]
    public void Concurrent_calls_agree()
    {
        using MkvXts xts = new(SeededBytes(32, 21));
        byte[] plaintext = SeededBytes(4096, 22);
        byte[] expected = new byte[plaintext.Length];
        xts.Encrypt(7, plaintext, expected);

        Parallel.For(0, 200, call =>
        {
            byte[] output = new byte[plaintext.Length];
            if (call % 2 == 0)
            {
                xts.Encrypt(7, plaintext, output);
                Assert.Equal(expected, output);
            }
            else
            {
                xts.Decrypt(7, expected, output);
                Assert.Equal(plaintext, output);
            }
        });
    }
}
