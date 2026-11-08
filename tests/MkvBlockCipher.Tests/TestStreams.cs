namespace MkvBlockCipher.Tests;

// Reads from data until failAfter bytes have been returned, then throws IOException on the next read.
internal sealed class FaultingStream : Stream
{
    private readonly byte[] _data;
    private readonly int _failAfter;
    private int _position;

    public FaultingStream(byte[] data, int failAfter)
    {
        _data = data;
        _failAfter = failAfter;
    }

    public override bool CanRead => true;

    public override bool CanSeek => false;

    public override bool CanWrite => false;

    public override long Length => throw new NotSupportedException();

    public override long Position
    {
        get => throw new NotSupportedException();
        set => throw new NotSupportedException();
    }

    public override void Flush()
    {
    }

    public override int Read(Span<byte> buffer)
    {
        if (_position == _failAfter)
        {
            throw new IOException("Injected read failure.");
        }

        int available = Math.Min(_failAfter, _data.Length) - _position;
        if (buffer.Length == 0 || available <= 0)
        {
            return 0;
        }

        int count = Math.Min(buffer.Length, available);
        _data.AsSpan(_position, count).CopyTo(buffer);
        _position += count;
        return count;
    }

    public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default) =>
        ValueTask.FromResult(Read(buffer.Span));

    public override int Read(byte[] buffer, int offset, int count) => Read(buffer.AsSpan(offset, count));

    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

    public override void SetLength(long value) => throw new NotSupportedException();

    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
}

// Returns at most one byte per Read, so every reader has to loop over short reads.
internal sealed class TrickleStream : Stream
{
    private readonly byte[] _data;
    private int _position;

    public TrickleStream(byte[] data) => _data = data;

    public override bool CanRead => true;

    public override bool CanSeek => false;

    public override bool CanWrite => false;

    public override long Length => throw new NotSupportedException();

    public override long Position
    {
        get => throw new NotSupportedException();
        set => throw new NotSupportedException();
    }

    public override void Flush()
    {
    }

    public override int Read(Span<byte> buffer)
    {
        if (buffer.Length == 0 || _position == _data.Length)
        {
            return 0;
        }

        buffer[0] = _data[_position];
        _position++;
        return 1;
    }

    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

    public override void SetLength(long value) => throw new NotSupportedException();

    public override int Read(byte[] buffer, int offset, int count) => Read(buffer.AsSpan(offset, count));

    public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default) =>
        ValueTask.FromResult(Read(buffer.Span));

    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
}

// Keeps the bytes of every Write that succeeds. WriteCalls counts every attempt. The write numbered failOnWrite
// (1-based) throws IOException and records nothing; 0 never throws. cancelOnFirstWrite is cancelled after the first
// successful write.
internal sealed class RecordingStream : Stream
{
    private readonly int _failOnWrite;
    private readonly CancellationTokenSource? _cancelOnFirstWrite;
    private readonly List<byte> _written = [];

    public RecordingStream(int failOnWrite = 0, CancellationTokenSource? cancelOnFirstWrite = null)
    {
        _failOnWrite = failOnWrite;
        _cancelOnFirstWrite = cancelOnFirstWrite;
    }

    public int WriteCalls { get; private set; }

    public int Flushes { get; private set; }

    public bool Disposed { get; private set; }

    public byte[] Written => _written.ToArray();

    public override bool CanRead => false;

    public override bool CanSeek => false;

    public override bool CanWrite => true;

    public override long Length => throw new NotSupportedException();

    public override long Position
    {
        get => throw new NotSupportedException();
        set => throw new NotSupportedException();
    }

    public override void Flush() => Flushes++;

    public override Task FlushAsync(CancellationToken cancellationToken)
    {
        Flush();
        return Task.CompletedTask;
    }

    public override int Read(Span<byte> buffer) => throw new NotSupportedException();

    public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();

    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

    public override void SetLength(long value) => throw new NotSupportedException();

    public override void Write(ReadOnlySpan<byte> buffer)
    {
        WriteCalls++;
        if (WriteCalls == _failOnWrite)
        {
            throw new IOException("Injected write failure.");
        }

        _written.AddRange(buffer.ToArray());
        if (WriteCalls == 1)
        {
            _cancelOnFirstWrite?.Cancel();
        }
    }

    public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
    {
        Write(buffer.Span);
        return ValueTask.CompletedTask;
    }

    public override void Write(byte[] buffer, int offset, int count) => Write(buffer.AsSpan(offset, count));

    protected override void Dispose(bool disposing)
    {
        Disposed = true;
        base.Dispose(disposing);
    }
}
