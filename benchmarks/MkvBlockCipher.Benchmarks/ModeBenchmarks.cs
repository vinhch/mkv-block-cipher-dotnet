using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using BenchmarkDotNet.Attributes;

namespace MkvBlockCipher.Benchmarks;

// Setup builds the key and buffers, so the timed calls run only the mode. CtrHmac uses empty associated data.
[MemoryDiagnoser]
[SuppressMessage("Design", "CA1001", Justification = "BenchmarkDotNet runs the GlobalCleanup method, which disposes both instances.")]
public class ModeBenchmarks
{
    private MkvCipher _cipher = null!;
    private MkvCtrHmac _authenticated = null!;
    private byte[] _plaintext = null!;
    private byte[] _iv = null!;
    private byte[] _counter = null!;
    private byte[] _cbcCiphertext = null!;
    private byte[] _cbcDecryptBuffer = null!;
    private byte[] _ctrOutput = null!;
    private byte[] _nonce = null!;
    private byte[] _tag = null!;
    private byte[] _authCiphertext = null!;

    [Params(MkvBlockSize.Mkv128, MkvBlockSize.Mkv256)]
    public MkvBlockSize BlockSize { get; set; }

    [Params(16, 1024, 65536, 1048576)]
    public int Size { get; set; }

    [GlobalSetup]
    public void Setup()
    {
        // 32 bytes is a valid key for both block sizes.
        byte[] key = RandomNumberGenerator.GetBytes(32);
        _cipher = new MkvCipher(BlockSize, key);
        _authenticated = new MkvCtrHmac(BlockSize, key);

        int blockBytes = _cipher.BlockSizeBytes;
        _plaintext = RandomNumberGenerator.GetBytes(Size);
        _iv = RandomNumberGenerator.GetBytes(blockBytes);
        _counter = new byte[blockBytes];
        _nonce = RandomNumberGenerator.GetBytes(_authenticated.NonceSizeBytes);
        _tag = new byte[MkvCtrHmac.TagSizeBytes];

        _cbcCiphertext = new byte[_cipher.GetCiphertextLengthCbc(Size)];
        _cipher.EncryptCbc(_plaintext, _iv, _cbcCiphertext);
        _cbcDecryptBuffer = new byte[_cbcCiphertext.Length];
        _ctrOutput = new byte[Size];
        _authCiphertext = new byte[Size];
    }

    [GlobalCleanup]
    public void Cleanup()
    {
        _cipher.Dispose();
        _authenticated.Dispose();
    }

    [Benchmark]
    public int CbcEncrypt() => _cipher.EncryptCbc(_plaintext, _iv, _cbcCiphertext);

    [Benchmark]
    public int CbcDecrypt() => _cipher.DecryptCbc(_cbcCiphertext, _iv, _cbcDecryptBuffer);

    [Benchmark]
    public void CtrEncrypt() => _cipher.TransformCtr(_counter, _plaintext, _ctrOutput);

    [Benchmark]
    public void CtrHmacEncrypt() => _authenticated.Encrypt(_nonce, _plaintext, _authCiphertext, _tag);
}
