using MkvBlockCipher.Modes;
using Xunit;

namespace MkvBlockCipher.Tests.Modes;

public sealed class GcmTests
{
    private const int TagBytes = 16;

    // GCM specification test cases 1-4 (AES-128), 7-10 (AES-192) and 13-16 (AES-256), 96-bit IVs and full 16-byte tags.
    // Copied from the GCM specification test cases, without change.
    [Theory]
    // Test case 1: empty plaintext, no AAD.
    [InlineData(
        "00000000000000000000000000000000",
        "000000000000000000000000",
        "",
        "",
        "",
        "58e2fccefa7e3061367f1d57a4e7455a")]
    // Test case 2: one zero block.
    [InlineData(
        "00000000000000000000000000000000",
        "000000000000000000000000",
        "00000000000000000000000000000000",
        "",
        "0388dace60b6a392f328c2b971b2fe78",
        "ab6e47d42cec13bdf53a67b21257bddf")]
    // Test case 3: 64-byte plaintext, no AAD.
    [InlineData(
        "feffe9928665731c6d6a8f9467308308",
        "cafebabefacedbaddecaf888",
        "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255",
        "",
        "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985",
        "4d5c2af327cd64a62cf35abd2ba6fab4")]
    // Test case 4: 60-byte plaintext with 20-byte AAD.
    [InlineData(
        "feffe9928665731c6d6a8f9467308308",
        "cafebabefacedbaddecaf888",
        "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
        "feedfacedeadbeeffeedfacedeadbeefabaddad2",
        "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091",
        "5bc94fbc3221a5db94fae95ae7121a47")]
    // Test case 7: AES-192, empty plaintext, no AAD.
    [InlineData(
        "000000000000000000000000000000000000000000000000",
        "000000000000000000000000",
        "",
        "",
        "",
        "cd33b28ac773f74ba00ed1f312572435")]
    // Test case 8: AES-192, one zero block.
    [InlineData(
        "000000000000000000000000000000000000000000000000",
        "000000000000000000000000",
        "00000000000000000000000000000000",
        "",
        "98e7247c07f0fe411c267e4384b0f600",
        "2ff58d80033927ab8ef4d4587514f0fb")]
    // Test case 9: AES-192, 64-byte plaintext, no AAD.
    [InlineData(
        "feffe9928665731c6d6a8f9467308308feffe9928665731c",
        "cafebabefacedbaddecaf888",
        "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255",
        "",
        "3980ca0b3c00e841eb06fac4872a2757859e1ceaa6efd984628593b40ca1e19c7d773d00c144c525ac619d18c84a3f4718e2448b2fe324d9ccda2710acade256",
        "9924a7c8587336bfb118024db8674a14")]
    // Test case 10: AES-192, 60-byte plaintext with 20-byte AAD.
    [InlineData(
        "feffe9928665731c6d6a8f9467308308feffe9928665731c",
        "cafebabefacedbaddecaf888",
        "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
        "feedfacedeadbeeffeedfacedeadbeefabaddad2",
        "3980ca0b3c00e841eb06fac4872a2757859e1ceaa6efd984628593b40ca1e19c7d773d00c144c525ac619d18c84a3f4718e2448b2fe324d9ccda2710",
        "2519498e80f1478f37ba55bd6d27618c")]
    // Test case 13: AES-256, empty plaintext, no AAD.
    [InlineData(
        "0000000000000000000000000000000000000000000000000000000000000000",
        "000000000000000000000000",
        "",
        "",
        "",
        "530f8afbc74536b9a963b4f1c4cb738b")]
    // Test case 14: AES-256, one zero block.
    [InlineData(
        "0000000000000000000000000000000000000000000000000000000000000000",
        "000000000000000000000000",
        "00000000000000000000000000000000",
        "",
        "cea7403d4d606b6e074ec5d3baf39d18",
        "d0d1c8a799996bf0265b98b5d48ab919")]
    // Test case 15: AES-256, 64-byte plaintext, no AAD.
    [InlineData(
        "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308",
        "cafebabefacedbaddecaf888",
        "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255",
        "",
        "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015ad",
        "b094dac5d93471bdec1a502270e3cc6c")]
    // Test case 16: AES-256, 60-byte plaintext with 20-byte AAD.
    [InlineData(
        "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308",
        "cafebabefacedbaddecaf888",
        "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
        "feedfacedeadbeeffeedfacedeadbeefabaddad2",
        "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662",
        "76fc6ece0f4e1768cddf8853bb2d551b")]
    public void Core_matches_gcm_spec_test_cases(
        string keyHex,
        string nonceHex,
        string plaintextHex,
        string aadHex,
        string ciphertextHex,
        string tagHex)
    {
        AesTestEngine engine = new();
        byte[] key = Convert.FromHexString(keyHex);
        byte[] h = new byte[TagBytes];
        Gcm.ComputeH(engine, key, h);

        byte[] nonce = Convert.FromHexString(nonceHex);
        byte[] plaintext = Convert.FromHexString(plaintextHex);
        byte[] aad = Convert.FromHexString(aadHex);
        byte[] ciphertext = new byte[plaintext.Length];
        byte[] tag = new byte[TagBytes];

        Gcm.Encrypt(engine, key, h, nonce, plaintext, ciphertext, tag, aad);
        Assert.Equal(Convert.FromHexString(ciphertextHex), ciphertext);
        Assert.Equal(Convert.FromHexString(tagHex), tag);

        byte[] decrypted = new byte[plaintext.Length];
        Assert.True(Gcm.Decrypt(engine, key, h, nonce, ciphertext, tag, decrypted, aad));
        Assert.Equal(plaintext, decrypted);
    }

    [Fact]
    public void Decrypt_with_wrong_tag_returns_false_and_writes_nothing()
    {
        AesTestEngine engine = new();
        byte[] key = new byte[16];
        byte[] h = new byte[TagBytes];
        Gcm.ComputeH(engine, key, h);

        byte[] nonce = new byte[12];
        byte[] ciphertext = Convert.FromHexString("0388dace60b6a392f328c2b971b2fe78");
        byte[] wrongTag = new byte[TagBytes];
        byte[] plaintext = new byte[ciphertext.Length];
        Array.Fill(plaintext, (byte)0xAA);

        Assert.False(Gcm.Decrypt(engine, key, h, nonce, ciphertext, wrongTag, plaintext, default));
        Assert.Equal(Enumerable.Repeat((byte)0xAA, ciphertext.Length), plaintext);
    }
}
