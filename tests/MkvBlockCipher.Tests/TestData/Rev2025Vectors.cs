using Xunit;

namespace MkvBlockCipher.Tests.TestData;

// Keys are bytes 00 01 02 ... of the key length. The six ciphertexts, the first 8 bytes of RK[1] and the Mkv256 last round
// key (32-byte key) come from publicly available reference material. The other five last round keys are project-computed
// regression values.
public static class Rev2025Vectors
{
    private const string Key16 = "000102030405060708090A0B0C0D0E0F";
    private const string Key24 = "000102030405060708090A0B0C0D0E0F1011121314151617";
    private const string Key32 = "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F";
    private const string Key48 = Key32 + "202122232425262728292A2B2C2D2E2F";
    private const string Key64 = Key48 + "303132333435363738393A3B3C3D3E3F";

    private const string Plaintext16 = "FFEEDDCCBBAA99887766554433221100";
    private const string Plaintext32 = Plaintext16 + Plaintext16;

    public static TheoryData<MkvBlockSize, string, string, string> RoundKeys { get; } = new()
    {
        { MkvBlockSize.Mkv128, Key16, "D55F9779EFA06276", "AA89FB1AFDE0CBECDDB03D41CE3E5F00" },
        { MkvBlockSize.Mkv128, Key24, "1974492A8DE8FEE7", "8B2AA5F3A9E1C2573284E4AA4115A620" },
        { MkvBlockSize.Mkv128, Key32, "0245745DDFEA1357", "F1C80EAEF2DD216FD182F2002C83A271" },
        { MkvBlockSize.Mkv256, Key32, "D511DC576D930D91", "1C90E6439CA60AA2A6E40143A00447F9D8FDB7AFB118ED613ACD720BD59467DF" },
        { MkvBlockSize.Mkv256, Key48, "A5C8F69EB97064DE", "BBC4A411CECC2B583B07A8E5113FD30D248D41412A9EA47D5120C5F25120177C" },
        { MkvBlockSize.Mkv256, Key64, "809A8447DC898BD3", "FE951B1A6DFA1AEEE63DD42533180340685410E644080CB4FFB765A396731F20" },
    };

    public static TheoryData<MkvBlockSize, string, string, string> Blocks { get; } = new()
    {
        { MkvBlockSize.Mkv128, Key16, Plaintext16, "F2795ECBA8F4D887F539EE8D8DF1141D" },
        { MkvBlockSize.Mkv128, Key24, Plaintext16, "D8E0A9A2994B4622D837676B7A54BFE2" },
        { MkvBlockSize.Mkv128, Key32, Plaintext16, "893F15625E29414002725C12781A7A34" },
        { MkvBlockSize.Mkv256, Key32, Plaintext32, "24EB2357EABAE02C8E2C9E497125DE8AF0B43EF000BF15FF20E091B0DE08893D" },
        { MkvBlockSize.Mkv256, Key48, Plaintext32, "C2B27F34B9E38857D1E1C345817D04047677335009526ABCC9212CB9BBF26374" },
        { MkvBlockSize.Mkv256, Key64, Plaintext32, "3DAD4F9B1330C6111CED631DDDF6E3EEA0678D10DD7B75A06B5BA602FCCA28AB" },
    };
}
