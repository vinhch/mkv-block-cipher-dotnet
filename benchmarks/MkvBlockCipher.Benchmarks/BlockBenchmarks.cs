using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using BenchmarkDotNet.Attributes;

namespace MkvBlockCipher.Benchmarks;

// One block per call, so the Size axis does not apply here.
[MemoryDiagnoser]
[SuppressMessage("Design", "CA1001", Justification = "BenchmarkDotNet runs the GlobalCleanup method, which disposes the cipher.")]
public class BlockBenchmarks
{
    private MkvCipher _cipher = null!;
    private byte[] _source = null!;
    private byte[] _destination = null!;

    [Params(MkvBlockSize.Mkv128, MkvBlockSize.Mkv256)]
    public MkvBlockSize BlockSize { get; set; }

    [GlobalSetup]
    public void Setup()
    {
        // 32 bytes is a valid key for both block sizes.
        _cipher = new MkvCipher(BlockSize, RandomNumberGenerator.GetBytes(32));
        _source = RandomNumberGenerator.GetBytes(_cipher.BlockSizeBytes);
        _destination = new byte[_cipher.BlockSizeBytes];
    }

    [GlobalCleanup]
    public void Cleanup() => _cipher.Dispose();

    [Benchmark]
    public void EncryptBlock() => _cipher.EncryptBlock(_source, _destination);
}
