using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;
using MkvBlockCipher;

// Copied from tests/MkvBlockCipher.Tests/TestData/Rev2025Vectors.cs:10-18. That file depends on xunit, so it is not referenced.
const string key16 = "000102030405060708090A0B0C0D0E0F";
const string plaintext16 = "FFEEDDCCBBAA99887766554433221100";
const string ciphertext16 = "F2795ECBA8F4D887F539EE8D8DF1141D";

byte[] key = Convert.FromHexString(key16);
byte[] plaintext = Convert.FromHexString(plaintext16);
byte[] expected = Convert.FromHexString(ciphertext16);

using var cipher = new MkvCipher(MkvBlockSize.Mkv128, key);

byte[] ciphertext = new byte[cipher.BlockSizeBytes];
cipher.EncryptBlock(plaintext, ciphertext);
byte[] decrypted = new byte[cipher.BlockSizeBytes];
cipher.DecryptBlock(ciphertext, decrypted);

bool encryptMatches = ciphertext.AsSpan().SequenceEqual(expected);
bool decryptMatches = decrypted.AsSpan().SequenceEqual(plaintext);

Console.WriteLine(
    $"engine={cipher.Engine.GetType().Name} avx2={Avx2.IsSupported} gfni={Gfni.IsSupported} avx512={Vector512.IsHardwareAccelerated}");
return encryptMatches && decryptMatches ? 0 : 1;
