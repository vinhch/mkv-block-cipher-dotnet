using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using BenchmarkDotNet.Attributes;

namespace MkvBlockCipher.Benchmarks;

// MkvGcm and MkvXts are MKV-128 only, so they have no block size parameter. Setup builds the key and buffers, so the timed calls run only the mode.
[MemoryDiagnoser]
[SuppressMessage("Design", "CA1001", Justification = "BenchmarkDotNet runs the GlobalCleanup method, which disposes both instances.")]
public class Mkv128ModeBenchmarks
{
    private MkvGcm _gcm = null!;
    private MkvXts _xts = null!;
    private byte[] _plaintext = null!;
    private byte[] _nonce = null!;
    private byte[] _tag = null!;
    private byte[] _gcmCiphertext = null!;
    private byte[] _xtsCiphertext = null!;

    [ParamsSource(nameof(EngineValues))]
    public MkvEngine Engine { get; set; }

    [ParamsSource(nameof(SizeValues))]
    public int Size { get; set; }

    public static IEnumerable<MkvEngine> EngineValues => BenchSettings.Engines;

    // Same sizes as ModeBenchmarks. Every size is a multiple of 16, so XTS never takes its ciphertext stealing path.
    public static IEnumerable<int> SizeValues => BenchSettings.Precise
        ? new[] { 1024, 1040, 1048576 }
        : BenchSettings.Quick
            ? new[] { 16, 1024, 1040, 1048576 }
            : new[] { 16, 1024, 65536, 1048576 };

    [GlobalSetup]
    public void Setup()
    {
        // 32 bytes is a valid key for GCM, and for XTS as a 16-byte data half and a 16-byte tweak half.
        byte[] key = RandomNumberGenerator.GetBytes(32);
        _gcm = new MkvGcm(key, tagSizeInBytes: 16, engine: Engine);
        _xts = new MkvXts(key, engine: Engine);

        _plaintext = RandomNumberGenerator.GetBytes(Size);
        _nonce = RandomNumberGenerator.GetBytes(12);
        _tag = new byte[16];
        _gcmCiphertext = new byte[Size];
        _xtsCiphertext = new byte[Size];
    }

    [GlobalCleanup]
    public void Cleanup()
    {
        _gcm.Dispose();
        _xts.Dispose();
    }

    [Benchmark]
    public void GcmEncrypt() => _gcm.Encrypt(_nonce, _plaintext, _gcmCiphertext, _tag);

    [Benchmark]
    public void XtsEncrypt() => _xts.Encrypt(0, _plaintext, _xtsCiphertext);
}
