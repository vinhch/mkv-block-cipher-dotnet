using Xunit;

namespace MkvBlockCipher.Tests.TestData;

// Known-answer rows. All are published test vectors except Mkv128Rev2026Ciphertext, which comes from the
// reference implementation.
public static class KnownAnswerVectors
{
    internal const string Key16 = "0102030405060708090A0B0C0D0E0F11";
    private const string Key24 = "0102030405060708090A0B0C0D0E0F111213141516171819";
    private const string Key32 = "0102030405060708090A0B0C0D0E0F1112131415161718191A1B1C1D1E1F2223";
    private const string Key48 = Key32 + "0102030405060708090A0B0C0D0E0F11";
    private const string Key64 = Key32 + Key32;

    internal const string Plaintext16 = "112233445566778899AABBCCDDEEFF00";
    private const string Plaintext32 = Plaintext16 + Plaintext16;

    internal const string Mkv128Rev2026Ciphertext = "1CC614ED63924A0F171A5AA4C9C2B120";

    public static TheoryData<MkvBlockSize, MkvRevision, string, string, string> Published { get; } = new()
    {
        { MkvBlockSize.Mkv128, MkvRevision.Rev2024, Key16, Plaintext16, "B331228334C3F81A37206591498756A1" },
        { MkvBlockSize.Mkv128, MkvRevision.Rev2024, Key24, Plaintext16, "4A9FC1350AAFCCAE7CB5B12AE4B24F91" },
        { MkvBlockSize.Mkv128, MkvRevision.Rev2024, Key32, Plaintext16, "5F16D17C48E40146559D602F50D6307E" },
        { MkvBlockSize.Mkv256, MkvRevision.Rev2024, Key32, Plaintext32, "CF2F2C1008186A578FE5B45DBD154473940C2BEC5682CDF83A3564A72DB0161B" },
        { MkvBlockSize.Mkv256, MkvRevision.Rev2024, Key48, Plaintext32, "731E244B25D8F7489D2E4BDEC8EAEE1796F55A26904EEDB22D96C2C17452739D" },
        { MkvBlockSize.Mkv256, MkvRevision.Rev2024, Key64, Plaintext32, "93B442FB88D257FBE71256BE511AAB9B1F71A4DD524635A61019A12ACB262C85" },
        { MkvBlockSize.Mkv128, MkvRevision.Rev2026, Key16, Plaintext16, Mkv128Rev2026Ciphertext },
        { MkvBlockSize.Mkv128, MkvRevision.Rev2026, Key24, Plaintext16, "A134C786F6E77485433B2D7CAAFD7A97" },
        { MkvBlockSize.Mkv128, MkvRevision.Rev2026, Key32, Plaintext16, "8A6F9BBC745BFEE7005F04054DD1FF8E" },
        { MkvBlockSize.Mkv256, MkvRevision.Rev2026, Key32, Plaintext32, "3E6359590DC566D8E79629607D5872A6A7C9ADF74BF0D2DF00EAF76FF7C129C3" },
        { MkvBlockSize.Mkv256, MkvRevision.Rev2026, Key48, Plaintext32, "515D487A2CC34D8A68BEFF4371BE4DF4AAF458B4AB540F394F72747BD9D9DFDB" },
        { MkvBlockSize.Mkv256, MkvRevision.Rev2026, Key64, Plaintext32, "5E6FD5F88B7924E0E24F070C8E3F3FBC264350BF06A169F55167C51521B7CFA4" },
    };
}
