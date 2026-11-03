namespace MkvBlockCipher;

/// <summary>Block size of the cipher: 128 bits (16 bytes) or 256 bits (32 bytes).</summary>
public enum MkvBlockSize
{
    /// <summary>128-bit block, 16 bytes.</summary>
    Mkv128,

    /// <summary>256-bit block, 32 bytes.</summary>
    Mkv256,
}
