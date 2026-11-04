using System.Security.Cryptography;
using BenchmarkDotNet.Attributes;

namespace MkvBlockCipher.Benchmarks;

// Runs only under --cold, so it carries no job attribute. The timed call covers construction, one transform and disposal.
public class ColdStartBenchmarks
{
    private byte[] _key = null!;
    private byte[] _counter = null!;
    private byte[] _source = null!;
    private byte[] _destination = null!;

    [GlobalSetup]
    public void Setup()
    {
        // Mkv128 takes a 32-byte key and 16-byte counter blocks.
        _key = RandomNumberGenerator.GetBytes(32);
        _counter = RandomNumberGenerator.GetBytes(16);
        _source = RandomNumberGenerator.GetBytes(1024);
        _destination = new byte[1024];
    }

    [Benchmark]
    public void FirstCtr1KiB()
    {
        using MkvCipher cipher = new(MkvBlockSize.Mkv128, _key);
        cipher.TransformCtr(_counter, _source, _destination);
    }
}
