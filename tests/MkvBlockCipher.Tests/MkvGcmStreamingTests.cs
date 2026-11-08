using System.Security.Cryptography;
using Xunit;

namespace MkvBlockCipher.Tests;

public sealed class MkvGcmStreamingTests
{
    public enum CallPath
    {
        Sync,
        Async,
    }

    private const string FrozenKeyHex = "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F";

    // Frozen output: any change here breaks stored streams. Project-computed vector, generated once from the verified
    // streaming core; it is not a standard vector.
    private const string FrozenStreamCiphertextHex =
        "1BDF2968CF4A46F608FCEF4E5C325322DF0E4B6073EFD1091296C5057F717CAB4D14575ACBBAB21CD881EF42CF01704FB3C63D72213E2D20AD5EC3BA4F31636AAEB19B24198F73280E3D7BDABD23187CA99C3423248CEB574449AD31BD8C75BDEFAAEDCC632499147B6B8BE01BDDEFDB04DEECB7DD82E1EC";

    private const int SegmentBytes = 16;
    private const int LargeSegmentBytes = 32;
    private const int TagBytes = 16;
    private const int ShortTagBytes = 12;
    private const int WireSegmentBytes = SegmentBytes + TagBytes;
    private const int MultiSegmentLength = 56;

    private static readonly byte[] NoncePrefixA = [0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6];
    private static readonly byte[] NoncePrefixB = [0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6];
    private static readonly byte[] NoncePrefixA5 = [0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA7];
    private static readonly byte[] AssociatedData1 = "file-1"u8.ToArray();
    private static readonly byte[] AssociatedData2 = "file-2"u8.ToArray();

    public static TheoryData<CallPath> CallPaths => new(Enum.GetValues<CallPath>());

    public static MatrixTheoryData<CallPath, int> SmallLengths => new(Enum.GetValues<CallPath>(), [0, 1, 15, 16, 17, 48, 55]);

    public static MatrixTheoryData<CallPath, int> DefaultSegmentLengths =>
        new(Enum.GetValues<CallPath>(), [0, 65535, 65536, 65537, 196608, 196615]);

    public static MatrixTheoryData<CallPath, int> ShortAndFullFinalLengths => new(Enum.GetValues<CallPath>(), [48, 56]);

    public static MatrixTheoryData<CallPath, int> CompositionLengths => new(Enum.GetValues<CallPath>(), [0, 16, 32, 56]);

    [Theory]
    [MemberData(nameof(SmallLengths))]
    public void RoundTrip_Lengths(CallPath path, int plaintextLength) => AssertRoundTrip(path, plaintextLength, SegmentBytes);

    [Theory]
    [MemberData(nameof(DefaultSegmentLengths))]
    public void RoundTrip_DefaultSegmentSize(CallPath path, int plaintextLength) =>
        AssertRoundTrip(path, plaintextLength, MkvGcmStreaming.DefaultSegmentSizeBytes);

    [Theory]
    [MemberData(nameof(CallPaths))]
    public void Encrypt_EmptyInput_WritesOneTag(CallPath path)
    {
        using MkvGcm gcm = CreateGcm();

        byte[] ciphertext = EncryptAll(path, gcm, NoncePrefixA, Array.Empty<byte>(), SegmentBytes, default);

        Assert.Equal(TagBytes, ciphertext.Length);
    }

    [Theory]
    [MemberData(nameof(CallPaths))]
    public void Encrypt_ExactMultiple_EndsInFullFinalSegment(CallPath path)
    {
        using MkvGcm gcm = CreateGcm();

        byte[] ciphertext = EncryptAll(path, gcm, NoncePrefixA, Pattern(32, 1), SegmentBytes, default);

        Assert.Equal(2 * WireSegmentBytes, ciphertext.Length);
    }

    [Theory]
    [MemberData(nameof(CallPaths))]
    public void Decrypt_TruncatedAtEveryOffset_Throws(CallPath path)
    {
        using MkvGcm gcm = CreateGcm();
        byte[] ciphertext = EncryptAll(path, gcm, NoncePrefixA, Pattern(MultiSegmentLength, 2), SegmentBytes, default);

        for (int length = 0; length < ciphertext.Length; length++)
        {
            byte[] truncated = ciphertext.AsSpan(0, length).ToArray();
            Assert.Throws<CryptographicException>(() =>
            {
                DecryptAll(path, gcm, NoncePrefixA, truncated, SegmentBytes, default);
            });
        }
    }

    [Theory]
    [MemberData(nameof(ShortAndFullFinalLengths))]
    public void Decrypt_AppendedByte_Throws(CallPath path, int plaintextLength)
    {
        using MkvGcm gcm = CreateGcm();
        byte[] ciphertext = EncryptAll(path, gcm, NoncePrefixA, Pattern(plaintextLength, 3), SegmentBytes, default);
        byte[] appended = [.. ciphertext, 0x00];

        Assert.Throws<CryptographicException>(() =>
        {
            DecryptAll(path, gcm, NoncePrefixA, appended, SegmentBytes, default);
        });
    }

    [Theory]
    [MemberData(nameof(CallPaths))]
    public void Decrypt_SwappedSegments_Throws(CallPath path)
    {
        using MkvGcm gcm = CreateGcm();
        byte[] ciphertext = EncryptAll(path, gcm, NoncePrefixA, Pattern(MultiSegmentLength, 4), SegmentBytes, default);
        byte[] swapped = [.. ciphertext[WireSegmentBytes..(2 * WireSegmentBytes)], .. ciphertext[..WireSegmentBytes], .. ciphertext[(2 * WireSegmentBytes)..]];

        Assert.Throws<CryptographicException>(() =>
        {
            DecryptAll(path, gcm, NoncePrefixA, swapped, SegmentBytes, default);
        });
    }

    [Theory]
    [MemberData(nameof(CallPaths))]
    public void Decrypt_DroppedSegment_Throws(CallPath path)
    {
        using MkvGcm gcm = CreateGcm();
        byte[] ciphertext = EncryptAll(path, gcm, NoncePrefixA, Pattern(MultiSegmentLength, 5), SegmentBytes, default);
        byte[] dropped = [.. ciphertext[..WireSegmentBytes], .. ciphertext[(2 * WireSegmentBytes)..]];

        Assert.Throws<CryptographicException>(() =>
        {
            DecryptAll(path, gcm, NoncePrefixA, dropped, SegmentBytes, default);
        });
    }

    [Theory]
    [MemberData(nameof(CallPaths))]
    public void Decrypt_DuplicatedSegment_Throws(CallPath path)
    {
        using MkvGcm gcm = CreateGcm();
        byte[] ciphertext = EncryptAll(path, gcm, NoncePrefixA, Pattern(MultiSegmentLength, 6), SegmentBytes, default);
        byte[] duplicated = [.. ciphertext[..WireSegmentBytes], .. ciphertext];

        Assert.Throws<CryptographicException>(() =>
        {
            DecryptAll(path, gcm, NoncePrefixA, duplicated, SegmentBytes, default);
        });
    }

    [Theory]
    [MemberData(nameof(CallPaths))]
    public void Decrypt_FlippedBit_Throws(CallPath path)
    {
        using MkvGcm gcm = CreateGcm();
        byte[] ciphertext = EncryptAll(path, gcm, NoncePrefixA, Pattern(MultiSegmentLength, 7), SegmentBytes, default);
        int segmentCount = SegmentCount(MultiSegmentLength, SegmentBytes);

        for (int segment = 0; segment < segmentCount; segment++)
        {
            byte[] flipped = (byte[])ciphertext.Clone();
            flipped[segment * WireSegmentBytes] ^= 0x01;

            Assert.Throws<CryptographicException>(() =>
            {
                DecryptAll(path, gcm, NoncePrefixA, flipped, SegmentBytes, default);
            });
        }
    }

    [Theory]
    [MemberData(nameof(CallPaths))]
    public void Decrypt_WrongAssociatedData_Throws(CallPath path)
    {
        using MkvGcm gcm = CreateGcm();
        byte[] ciphertext = EncryptAll(path, gcm, NoncePrefixA, Pattern(MultiSegmentLength, 8), SegmentBytes, AssociatedData1);
        using MemoryStream source = new(ciphertext);
        using RecordingStream destination = new();

        Assert.Throws<CryptographicException>(() =>
        {
            DecryptInto(path, gcm, NoncePrefixA, source, destination, SegmentBytes, AssociatedData2, 0);
        });
        Assert.Equal(0, destination.WriteCalls);
    }

    [Theory]
    [MemberData(nameof(CallPaths))]
    public void Decrypt_SplicedFromOtherPrefix_Throws(CallPath path)
    {
        using MkvGcm gcm = CreateGcm();
        byte[] plaintext = Pattern(MultiSegmentLength, 9);
        byte[] ciphertext = EncryptAll(path, gcm, NoncePrefixA, plaintext, SegmentBytes, default);
        byte[] other = BuildStream(gcm, NoncePrefixB, plaintext, SegmentBytes, default);
        byte[] spliced = [.. ciphertext[..WireSegmentBytes], .. other[WireSegmentBytes..(2 * WireSegmentBytes)], .. ciphertext[(2 * WireSegmentBytes)..]];

        Assert.Throws<CryptographicException>(() =>
        {
            DecryptAll(path, gcm, NoncePrefixA, spliced, SegmentBytes, default);
        });
    }

    [Theory]
    [MemberData(nameof(CallPaths))]
    public void Decrypt_Failure_WritesNoPlaintextOfFailingSegment(CallPath path)
    {
        using MkvGcm gcm = CreateGcm();
        byte[] plaintext = Pattern(MultiSegmentLength, 10);
        byte[] ciphertext = EncryptAll(path, gcm, NoncePrefixA, plaintext, SegmentBytes, default);
        ciphertext[2 * WireSegmentBytes] ^= 0x01;
        using MemoryStream source = new(ciphertext);
        using RecordingStream destination = new();

        Assert.Throws<CryptographicException>(() =>
        {
            DecryptInto(path, gcm, NoncePrefixA, source, destination, SegmentBytes, default, 0);
        });
        Assert.Equal(plaintext[..(2 * SegmentBytes)], destination.Written);
    }

    [Theory]
    [MemberData(nameof(CallPaths))]
    public void Decrypt_SegmentSizeMismatch(CallPath path)
    {
        using MkvGcm gcm = CreateGcm();
        byte[] ciphertext = EncryptAll(path, gcm, NoncePrefixA, Pattern(MultiSegmentLength, 11), SegmentBytes, default);
        byte[] shortMessage = Pattern(10, 12);
        byte[] shortCiphertext = EncryptAll(path, gcm, NoncePrefixA, shortMessage, SegmentBytes, default);

        Assert.Throws<CryptographicException>(() =>
        {
            DecryptAll(path, gcm, NoncePrefixA, ciphertext, LargeSegmentBytes, default);
        });
        Assert.Equal(shortMessage, DecryptAll(path, gcm, NoncePrefixA, shortCiphertext, LargeSegmentBytes, default));
    }

    [Theory]
    [MemberData(nameof(CallPaths))]
    public void Decrypt_DestinationThrows_StopsAndPropagates(CallPath path)
    {
        using MkvGcm gcm = CreateGcm();
        byte[] plaintext = Pattern(MultiSegmentLength, 13);
        byte[] ciphertext = EncryptAll(path, gcm, NoncePrefixA, plaintext, SegmentBytes, default);
        using MemoryStream source = new(ciphertext);
        using RecordingStream destination = new(failOnWrite: 2);

        Assert.Throws<IOException>(() =>
        {
            DecryptInto(path, gcm, NoncePrefixA, source, destination, SegmentBytes, default, 0);
        });
        Assert.Equal(plaintext[..SegmentBytes], destination.Written);
    }

    [Theory]
    [MemberData(nameof(CallPaths))]
    public void ShortReads(CallPath path)
    {
        using MkvGcm gcm = CreateGcm();
        byte[] plaintext = Pattern(MultiSegmentLength, 14);

        byte[] fromMemory = EncryptAll(path, gcm, NoncePrefixA, plaintext, SegmentBytes, AssociatedData1);
        byte[] fromTrickle = EncryptAll(path, gcm, NoncePrefixA, new TrickleStream(plaintext), SegmentBytes, AssociatedData1);
        Assert.Equal(fromMemory, fromTrickle);

        byte[] decrypted = DecryptAll(path, gcm, NoncePrefixA, new TrickleStream(fromMemory), SegmentBytes, AssociatedData1);
        Assert.Equal(plaintext, decrypted);
    }

    [Theory]
    [MemberData(nameof(CompositionLengths))]
    public void Encrypt_MatchesSegmentComposition(CallPath path, int plaintextLength)
    {
        using MkvGcm gcm = CreateGcm();
        byte[] plaintext = Pattern(plaintextLength, 15);

        byte[] actual = EncryptAll(path, gcm, NoncePrefixA, plaintext, SegmentBytes, AssociatedData1);

        Assert.Equal(BuildStream(gcm, NoncePrefixA, plaintext, SegmentBytes, AssociatedData1), actual);
    }

    [Theory]
    [MemberData(nameof(CallPaths))]
    public void Decrypt_EmptyFinalAtNonZeroIndex_Throws(CallPath path)
    {
        using MkvGcm gcm = CreateGcm();
        byte[] firstSegment = Pattern(SegmentBytes, 16);
        byte[] stream = [.. SealSegment(gcm, NoncePrefixA, 0, false, firstSegment, default),
            .. SealSegment(gcm, NoncePrefixA, 1, true, ReadOnlySpan<byte>.Empty, default)];
        using MemoryStream source = new(stream);
        using RecordingStream destination = new();

        Assert.Throws<CryptographicException>(() =>
        {
            DecryptInto(path, gcm, NoncePrefixA, source, destination, SegmentBytes, default, 0);
        });
        Assert.Equal(firstSegment, destination.Written);
    }

    [Theory]
    [MemberData(nameof(CallPaths))]
    public void Decrypt_FinalAtLastIndex_Succeeds(CallPath path)
    {
        using MkvGcm gcm = CreateGcm();
        byte[] plaintext = Pattern(10, 17);
        byte[] stream = SealSegment(gcm, NoncePrefixA, uint.MaxValue, true, plaintext, default);

        Assert.Equal(plaintext, DecryptAll(path, gcm, NoncePrefixA, stream, SegmentBytes, default, uint.MaxValue));
    }

    [Theory]
    [MemberData(nameof(CallPaths))]
    public void Streams_NotDisposed_FlushedOnce(CallPath path)
    {
        using MkvGcm gcm = CreateGcm();
        using MemoryStream source = new(Pattern(MultiSegmentLength, 18));
        using RecordingStream encrypted = new();

        EncryptInto(path, gcm, NoncePrefixA, source, encrypted, SegmentBytes, default, 0);

        Assert.False(encrypted.Disposed);
        Assert.Equal(1, encrypted.Flushes);
        Assert.True(source.CanRead);

        using MemoryStream cipherSource = new(encrypted.Written);
        using RecordingStream decrypted = new();

        DecryptInto(path, gcm, NoncePrefixA, cipherSource, decrypted, SegmentBytes, default, 0);

        Assert.False(decrypted.Disposed);
        Assert.Equal(1, decrypted.Flushes);
        Assert.True(cipherSource.CanRead);
    }

    [Fact]
    public void Encrypt_MatchesFrozenVector()
    {
        using MkvGcm gcm = CreateGcm();
        byte[] plaintext = Enumerable.Range(0, MultiSegmentLength).Select(i => (byte)i).ToArray();
        using MemoryStream source = new(plaintext);
        using MemoryStream destination = new();

        MkvGcmStreaming.Encrypt(gcm, NoncePrefixA, source, destination, SegmentBytes);

        byte[] ciphertext = destination.ToArray();
        Assert.Equal(FrozenStreamCiphertextHex, Convert.ToHexString(ciphertext));
        Assert.Equal(plaintext, DecryptAll(CallPath.Sync, gcm, NoncePrefixA, ciphertext, SegmentBytes, default));
    }

    [Theory]
    [MemberData(nameof(CallPaths))]
    public void Encrypt_IsDeterministicPerKeyAndPrefix(CallPath path)
    {
        using MkvGcm gcm = CreateGcm();
        byte[] plaintext = Pattern(MultiSegmentLength, 19);

        byte[] first = EncryptAll(path, gcm, NoncePrefixA, plaintext, SegmentBytes, default);
        byte[] second = EncryptAll(path, gcm, NoncePrefixA, plaintext, SegmentBytes, default);
        byte[] otherPrefix = EncryptAll(path, gcm, NoncePrefixA5, plaintext, SegmentBytes, default);

        Assert.Equal(first, second);
        Assert.NotEqual(first, otherPrefix);
    }

    [Theory]
    [MemberData(nameof(CallPaths))]
    public void Encrypt_NonFinalAtLastIndex_Throws(CallPath path)
    {
        using MkvGcm gcm = CreateGcm();
        using MemoryStream source = new(Pattern(17, 20));
        using RecordingStream destination = new();

        Assert.Throws<ArgumentException>(() =>
        {
            EncryptInto(path, gcm, NoncePrefixA, source, destination, SegmentBytes, default, uint.MaxValue);
        });
        Assert.Equal(0, destination.WriteCalls);
    }

    [Theory]
    [MemberData(nameof(CallPaths))]
    public void Encrypt_FinalAtLastIndex_Succeeds(CallPath path)
    {
        using MkvGcm gcm = CreateGcm();
        byte[] plaintext = Pattern(SegmentBytes, 21);

        byte[] ciphertext = EncryptAll(path, gcm, NoncePrefixA, plaintext, SegmentBytes, default, uint.MaxValue);

        Assert.Equal(SealSegment(gcm, NoncePrefixA, uint.MaxValue, true, plaintext, default), ciphertext);
    }

    [Theory]
    [MemberData(nameof(CallPaths))]
    public void Decrypt_NonFinalAtLastIndex_Throws(CallPath path)
    {
        using MkvGcm gcm = CreateGcm();
        byte[] nonFinal = SealSegment(gcm, NoncePrefixA, uint.MaxValue, false, Pattern(SegmentBytes, 22), default);
        byte[] final = SealSegment(gcm, NoncePrefixA, 0, true, Pattern(5, 23), default);
        byte[] stream = [.. nonFinal, .. final];
        using MemoryStream source = new(stream);
        using RecordingStream destination = new();

        Assert.Throws<CryptographicException>(() =>
        {
            DecryptInto(path, gcm, NoncePrefixA, source, destination, SegmentBytes, default, uint.MaxValue);
        });
        Assert.Equal(0, destination.WriteCalls);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(17)]
    [InlineData(MultiSegmentLength)]
    public void Async_MatchesSync(int plaintextLength)
    {
        using MkvGcm gcm = CreateGcm();
        byte[] plaintext = Pattern(plaintextLength, 28);

        byte[] sync = EncryptAll(CallPath.Sync, gcm, NoncePrefixA, plaintext, SegmentBytes, AssociatedData1);
        byte[] async = EncryptAll(CallPath.Async, gcm, NoncePrefixA, plaintext, SegmentBytes, AssociatedData1);

        Assert.Equal(sync, async);
    }

    [Fact]
    public async Task DecryptAsync_CancelledAfterFirstSegment()
    {
        using MkvGcm gcm = CreateGcm();
        byte[] plaintext = Pattern(MultiSegmentLength, 29);
        byte[] ciphertext = EncryptAll(CallPath.Sync, gcm, NoncePrefixA, plaintext, SegmentBytes, default);
        using MemoryStream source = new(ciphertext);
        using CancellationTokenSource cancellation = new();
        using RecordingStream destination = new(cancelOnFirstWrite: cancellation);

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            MkvGcmStreaming.DecryptAsync(gcm, NoncePrefixA, source, destination, SegmentBytes, default, cancellation.Token).AsTask());

        Assert.Equal(plaintext[..SegmentBytes], destination.Written);
    }

    [Fact]
    public async Task PublicAsync_RoundTripsWithAssociatedData()
    {
        using MkvGcm gcm = CreateGcm();
        byte[] plaintext = Pattern(MultiSegmentLength, 31);
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;

        using MemoryStream asyncSource = new(plaintext);
        using MemoryStream asyncDestination = new();
        await MkvGcmStreaming.EncryptAsync(gcm, NoncePrefixA, asyncSource, asyncDestination, SegmentBytes, AssociatedData1, cancellationToken);
        byte[] ciphertext = asyncDestination.ToArray();

        using MemoryStream syncSource = new(plaintext);
        using MemoryStream syncDestination = new();
        MkvGcmStreaming.Encrypt(gcm, NoncePrefixA, syncSource, syncDestination, SegmentBytes, AssociatedData1);
        Assert.Equal(syncDestination.ToArray(), ciphertext);

        using MemoryStream decryptSource = new(ciphertext);
        using MemoryStream decrypted = new();
        await MkvGcmStreaming.DecryptAsync(gcm, NoncePrefixA, decryptSource, decrypted, SegmentBytes, AssociatedData1, cancellationToken);
        Assert.Equal(plaintext, decrypted.ToArray());

        using MemoryStream wrongSource = new(ciphertext);
        using MemoryStream wrongDestination = new();
        await Assert.ThrowsAsync<CryptographicException>(() =>
            MkvGcmStreaming.DecryptAsync(gcm, NoncePrefixA, wrongSource, wrongDestination, SegmentBytes, AssociatedData2, cancellationToken).AsTask());
    }

    [Fact]
    public void EncryptAsync_ArgumentsValidatedSynchronously()
    {
        using MkvGcm gcm = CreateGcm();
        using MemoryStream source = new(Pattern(32, 30));
        using RecordingStream destination = new();

        Assert.Throws<ArgumentOutOfRangeException>(() => { _ = MkvGcmStreaming.EncryptAsync(gcm, NoncePrefixA, source, destination, SegmentBytes - 1, cancellationToken: TestContext.Current.CancellationToken).AsTask(); });

        Assert.Equal(0L, source.Position);
        Assert.Equal(0, destination.WriteCalls);
    }

    [Fact]
    public async Task Disposed_EmptySource_ThrowsObjectDisposedBeforeIo()
    {
        MkvGcm gcm = CreateGcm();
        gcm.Dispose();
        using MemoryStream source = new();
        using RecordingStream destination = new();
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;

        Assert.Throws<ObjectDisposedException>(() => MkvGcmStreaming.Encrypt(gcm, NoncePrefixA, source, destination));
        Assert.Throws<ObjectDisposedException>(() => MkvGcmStreaming.Decrypt(gcm, NoncePrefixA, source, destination));
        await Assert.ThrowsAsync<ObjectDisposedException>(() =>
            MkvGcmStreaming.EncryptAsync(gcm, NoncePrefixA, source, destination, cancellationToken: cancellationToken).AsTask());
        await Assert.ThrowsAsync<ObjectDisposedException>(() =>
            MkvGcmStreaming.DecryptAsync(gcm, NoncePrefixA, source, destination, cancellationToken: cancellationToken).AsTask());

        Assert.Equal(0L, source.Position);
        Assert.Equal(0, destination.WriteCalls);
    }

    [Theory]
    [MemberData(nameof(CallPaths))]
    public void Encrypt_DestinationThrows_StopsAndPropagates(CallPath path)
    {
        using MkvGcm gcm = CreateGcm();
        byte[] plaintext = Pattern(MultiSegmentLength, 40);
        using MemoryStream source = new(plaintext);
        using RecordingStream destination = new(failOnWrite: 2);

        Assert.Throws<IOException>(() =>
        {
            EncryptInto(path, gcm, NoncePrefixA, source, destination, SegmentBytes, default, 0);
        });
        Assert.Equal(SealSegment(gcm, NoncePrefixA, 0, false, plaintext.AsSpan(0, SegmentBytes), default), destination.Written);
    }

    [Theory]
    [MemberData(nameof(CallPaths))]
    public void Encrypt_SourceThrows_WritesOnlyCompleteSegments(CallPath path)
    {
        using MkvGcm gcm = CreateGcm();
        byte[] plaintext = Pattern(MultiSegmentLength, 41);
        // Fails after 8 bytes of segment 2, which holds plaintext bytes 32 to 47.
        using FaultingStream source = new(plaintext, failAfter: 2 * SegmentBytes + SegmentBytes / 2);
        using RecordingStream destination = new();

        Assert.Throws<IOException>(() =>
        {
            EncryptInto(path, gcm, NoncePrefixA, source, destination, SegmentBytes, default, 0);
        });
        byte[] expected =
        [
            .. SealSegment(gcm, NoncePrefixA, 0, false, plaintext.AsSpan(0, SegmentBytes), default),
            .. SealSegment(gcm, NoncePrefixA, 1, false, plaintext.AsSpan(SegmentBytes, SegmentBytes), default),
        ];
        Assert.Equal(expected, destination.Written);
    }

    [Theory]
    [MemberData(nameof(CallPaths))]
    public void Decrypt_SourceThrows_WritesOnlyCompleteSegments(CallPath path)
    {
        using MkvGcm gcm = CreateGcm();
        byte[] plaintext = Pattern(MultiSegmentLength, 42);
        byte[] ciphertext = EncryptAll(CallPath.Sync, gcm, NoncePrefixA, plaintext, SegmentBytes, default);
        // Fails after 16 bytes of wire segment 2, which holds wire bytes 64 to 95.
        using FaultingStream source = new(ciphertext, failAfter: 2 * WireSegmentBytes + SegmentBytes);
        using RecordingStream destination = new();

        Assert.Throws<IOException>(() =>
        {
            DecryptInto(path, gcm, NoncePrefixA, source, destination, SegmentBytes, default, 0);
        });
        Assert.Equal(plaintext[..(2 * SegmentBytes)], destination.Written);
    }

    [Fact]
    public async Task EncryptAsync_CancelledAfterFirstSegment()
    {
        using MkvGcm gcm = CreateGcm();
        byte[] plaintext = Pattern(MultiSegmentLength, 43);
        using MemoryStream source = new(plaintext);
        using CancellationTokenSource cancellation = new();
        using RecordingStream destination = new(cancelOnFirstWrite: cancellation);

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            MkvGcmStreaming.EncryptAsync(gcm, NoncePrefixA, source, destination, SegmentBytes, default, cancellation.Token).AsTask());

        Assert.Equal(SealSegment(gcm, NoncePrefixA, 0, false, plaintext.AsSpan(0, SegmentBytes), default), destination.Written);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Cancelled_BeforeFirstSegment_WritesNothing(bool decrypt)
    {
        using MkvGcm gcm = CreateGcm();
        byte[] plaintext = Pattern(MultiSegmentLength, 44);
        byte[] ciphertext = EncryptAll(CallPath.Sync, gcm, NoncePrefixA, plaintext, SegmentBytes, default);
        using MemoryStream source = new(decrypt ? ciphertext : plaintext);
        using RecordingStream destination = new();
        using CancellationTokenSource cancellation = new();
        cancellation.Cancel();

        Func<ValueTask> run = decrypt
            ? () => MkvGcmStreaming.DecryptAsync(gcm, NoncePrefixA, source, destination, SegmentBytes, default, cancellation.Token)
            : () => MkvGcmStreaming.EncryptAsync(gcm, NoncePrefixA, source, destination, SegmentBytes, default, cancellation.Token);
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => run().AsTask());

        Assert.Equal(0L, source.Position);
        Assert.Equal(0, destination.WriteCalls);
    }

    [Theory]
    [MemberData(nameof(CallPaths))]
    public void Decrypt_TruncatedAtEveryOffset_FullFinalSegment(CallPath path)
    {
        using MkvGcm gcm = CreateGcm();
        byte[] ciphertext = EncryptAll(path, gcm, NoncePrefixA, Pattern(3 * SegmentBytes, 45), SegmentBytes, default);

        for (int length = 0; length < ciphertext.Length; length++)
        {
            byte[] truncated = ciphertext.AsSpan(0, length).ToArray();
            Assert.Throws<CryptographicException>(() =>
            {
                DecryptAll(path, gcm, NoncePrefixA, truncated, SegmentBytes, default);
            });
        }
    }

    [Theory]
    [MemberData(nameof(CallPaths))]
    public void RoundTrip_TagSize12(CallPath path)
    {
        using MkvGcm gcm = new(Convert.FromHexString(FrozenKeyHex), ShortTagBytes);
        byte[] plaintext = Pattern(MultiSegmentLength, 46);

        byte[] ciphertext = EncryptAll(path, gcm, NoncePrefixA, plaintext, SegmentBytes, default);

        Assert.Equal(plaintext.Length + ShortTagBytes * SegmentCount(plaintext.Length, SegmentBytes), ciphertext.Length);
        Assert.Equal(plaintext, DecryptAll(path, gcm, NoncePrefixA, ciphertext, SegmentBytes, default));
    }

    [Theory]
    [MemberData(nameof(CallPaths))]
    public void Decrypt_TagSize16Stream_UnderTagSize12_Throws(CallPath path)
    {
        using MkvGcm gcm16 = CreateGcm();
        using MkvGcm gcm12 = new(Convert.FromHexString(FrozenKeyHex), ShortTagBytes);
        byte[] ciphertext = EncryptAll(path, gcm16, NoncePrefixA, Pattern(MultiSegmentLength, 47), SegmentBytes, default);

        Assert.Throws<CryptographicException>(() =>
        {
            DecryptAll(path, gcm12, NoncePrefixA, ciphertext, SegmentBytes, default);
        });
    }

    [Fact]
    public void Arguments_SegmentSizeOutOfRange_Throws()
    {
        using MkvGcm gcm = CreateGcm();
        foreach (int segmentBytes in new[] { SegmentBytes - 1, MkvGcmStreaming.MaxSegmentSizeBytes + 1 })
        {
            using MemoryStream source = new(Pattern(32, 24));
            using RecordingStream destination = new();

            Assert.Throws<ArgumentOutOfRangeException>(() =>
                MkvGcmStreaming.Encrypt(gcm, NoncePrefixA, source, destination, segmentBytes));
            Assert.Throws<ArgumentOutOfRangeException>(() =>
                MkvGcmStreaming.Decrypt(gcm, NoncePrefixA, source, destination, segmentBytes));

            Assert.Equal(0L, source.Position);
            Assert.Equal(0, destination.WriteCalls);
        }
    }

    [Fact]
    public void Arguments_PrefixNotSevenBytes_Throws()
    {
        using MkvGcm gcm = CreateGcm();
        byte[] shortPrefix = NoncePrefixA[..6];
        using MemoryStream source = new(Pattern(32, 25));
        using RecordingStream destination = new();

        Assert.Throws<ArgumentException>(() => MkvGcmStreaming.Encrypt(gcm, shortPrefix, source, destination));
        Assert.Throws<ArgumentException>(() => MkvGcmStreaming.Decrypt(gcm, shortPrefix, source, destination));

        Assert.Equal(0L, source.Position);
        Assert.Equal(0, destination.WriteCalls);
    }

    [Fact]
    public void Arguments_NullStreamOrGcm_Throws()
    {
        using MkvGcm gcm = CreateGcm();
        using MemoryStream source = new(Pattern(32, 26));
        using RecordingStream destination = new();

        Assert.Throws<ArgumentNullException>(() => MkvGcmStreaming.Encrypt(null!, NoncePrefixA, source, destination));
        Assert.Throws<ArgumentNullException>(() => MkvGcmStreaming.Encrypt(gcm, NoncePrefixA, null!, destination));
        Assert.Throws<ArgumentNullException>(() => MkvGcmStreaming.Encrypt(gcm, NoncePrefixA, source, null!));
        Assert.Throws<ArgumentNullException>(() => MkvGcmStreaming.Decrypt(null!, NoncePrefixA, source, destination));
        Assert.Throws<ArgumentNullException>(() => MkvGcmStreaming.Decrypt(gcm, NoncePrefixA, null!, destination));
        Assert.Throws<ArgumentNullException>(() => MkvGcmStreaming.Decrypt(gcm, NoncePrefixA, source, null!));

        Assert.Equal(0L, source.Position);
        Assert.Equal(0, destination.WriteCalls);
    }

    [Fact]
    public void Arguments_UnreadableSourceOrUnwritableDestination_Throws()
    {
        using MkvGcm gcm = CreateGcm();
        using RecordingStream unreadable = new();
        using MemoryStream readOnly = new(new byte[32], writable: false);
        using MemoryStream source = new(Pattern(32, 27));
        using RecordingStream destination = new();

        Assert.Throws<ArgumentException>(() => MkvGcmStreaming.Encrypt(gcm, NoncePrefixA, unreadable, destination));
        Assert.Throws<ArgumentException>(() => MkvGcmStreaming.Decrypt(gcm, NoncePrefixA, unreadable, destination));
        Assert.Throws<ArgumentException>(() => MkvGcmStreaming.Encrypt(gcm, NoncePrefixA, source, readOnly));
        Assert.Throws<ArgumentException>(() => MkvGcmStreaming.Decrypt(gcm, NoncePrefixA, source, readOnly));

        Assert.Equal(0L, source.Position);
        Assert.Equal(0, destination.WriteCalls);
    }

    private static MkvGcm CreateGcm() => new(Convert.FromHexString(FrozenKeyHex), TagBytes);

    private static void AssertRoundTrip(CallPath path, int plaintextLength, int segmentBytes)
    {
        using MkvGcm gcm = CreateGcm();
        byte[] plaintext = Pattern(plaintextLength, 1);

        byte[] ciphertext = EncryptAll(path, gcm, NoncePrefixA, plaintext, segmentBytes, default);

        Assert.Equal(plaintextLength + TagBytes * SegmentCount(plaintextLength, segmentBytes), ciphertext.Length);
        Assert.Equal(plaintext, DecryptAll(path, gcm, NoncePrefixA, ciphertext, segmentBytes, default));
    }

    private static byte[] Pattern(int length, int salt)
    {
        byte[] data = new byte[length];
        for (int i = 0; i < length; i++)
        {
            data[i] = (byte)(i * 7 + salt);
        }

        return data;
    }

    private static int SegmentCount(int plaintextLength, int segmentBytes) =>
        Math.Max(1, (plaintextLength + segmentBytes - 1) / segmentBytes);

    // One segment as the spec defines it: ciphertext then tag, built from the segment API only.
    private static byte[] SealSegment(
        MkvGcm gcm, ReadOnlySpan<byte> noncePrefix, uint segmentIndex, bool isLastSegment,
        ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> associatedData)
    {
        byte[] segment = new byte[plaintext.Length + TagBytes];
        gcm.EncryptSegment(noncePrefix, segmentIndex, isLastSegment, plaintext,
            segment.AsSpan(0, plaintext.Length), segment.AsSpan(plaintext.Length), associatedData);
        return segment;
    }

    private static byte[] BuildStream(
        MkvGcm gcm, ReadOnlySpan<byte> noncePrefix, ReadOnlySpan<byte> plaintext, int segmentBytes,
        ReadOnlySpan<byte> associatedData)
    {
        int count = SegmentCount(plaintext.Length, segmentBytes);
        List<byte> stream = [];
        for (int i = 0; i < count; i++)
        {
            int start = i * segmentBytes;
            int length = Math.Min(segmentBytes, plaintext.Length - start);
            stream.AddRange(SealSegment(gcm, noncePrefix, (uint)i, i == count - 1, plaintext.Slice(start, length), associatedData));
        }

        return stream.ToArray();
    }

    private static byte[] EncryptAll(
        CallPath path, MkvGcm gcm, ReadOnlyMemory<byte> noncePrefix, byte[] plaintext, int segmentBytes,
        ReadOnlyMemory<byte> associatedData, uint firstSegmentIndex = 0)
    {
        using MemoryStream source = new(plaintext);
        return EncryptAll(path, gcm, noncePrefix, source, segmentBytes, associatedData, firstSegmentIndex);
    }

    private static byte[] EncryptAll(
        CallPath path, MkvGcm gcm, ReadOnlyMemory<byte> noncePrefix, Stream source, int segmentBytes,
        ReadOnlyMemory<byte> associatedData, uint firstSegmentIndex = 0)
    {
        using MemoryStream destination = new();
        EncryptInto(path, gcm, noncePrefix, source, destination, segmentBytes, associatedData, firstSegmentIndex);
        return destination.ToArray();
    }

    private static byte[] DecryptAll(
        CallPath path, MkvGcm gcm, ReadOnlyMemory<byte> noncePrefix, byte[] ciphertext, int segmentBytes,
        ReadOnlyMemory<byte> associatedData, uint firstSegmentIndex = 0)
    {
        using MemoryStream source = new(ciphertext);
        return DecryptAll(path, gcm, noncePrefix, source, segmentBytes, associatedData, firstSegmentIndex);
    }

    private static byte[] DecryptAll(
        CallPath path, MkvGcm gcm, ReadOnlyMemory<byte> noncePrefix, Stream source, int segmentBytes,
        ReadOnlyMemory<byte> associatedData, uint firstSegmentIndex = 0)
    {
        using MemoryStream destination = new();
        DecryptInto(path, gcm, noncePrefix, source, destination, segmentBytes, associatedData, firstSegmentIndex);
        return destination.ToArray();
    }

    private static void EncryptInto(
        CallPath path, MkvGcm gcm, ReadOnlyMemory<byte> noncePrefix, Stream source, Stream destination, int segmentBytes,
        ReadOnlyMemory<byte> associatedData, uint firstSegmentIndex)
    {
        switch (path)
        {
            case CallPath.Sync:
                MkvGcmStreaming.EncryptCore(gcm, noncePrefix.Span, source, destination, segmentBytes, associatedData.Span, firstSegmentIndex);
                break;
            case CallPath.Async:
                MkvGcmStreaming.EncryptCoreAsync(gcm, noncePrefix, source, destination, segmentBytes, associatedData, firstSegmentIndex, CancellationToken.None)
                    .AsTask().GetAwaiter().GetResult();
                break;
            default:
                throw new ArgumentOutOfRangeException(nameof(path), path, null);
        }
    }

    private static void DecryptInto(
        CallPath path, MkvGcm gcm, ReadOnlyMemory<byte> noncePrefix, Stream source, Stream destination, int segmentBytes,
        ReadOnlyMemory<byte> associatedData, uint firstSegmentIndex)
    {
        switch (path)
        {
            case CallPath.Sync:
                MkvGcmStreaming.DecryptCore(gcm, noncePrefix.Span, source, destination, segmentBytes, associatedData.Span, firstSegmentIndex);
                break;
            case CallPath.Async:
                MkvGcmStreaming.DecryptCoreAsync(gcm, noncePrefix, source, destination, segmentBytes, associatedData, firstSegmentIndex, CancellationToken.None)
                    .AsTask().GetAwaiter().GetResult();
                break;
            default:
                throw new ArgumentOutOfRangeException(nameof(path), path, null);
        }
    }
}
