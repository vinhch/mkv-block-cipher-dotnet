namespace MkvBlockCipher;

/// <summary>Algorithm revision. Rev2025 is the default.</summary>
public enum MkvRevision
{
    /// <summary>The earlier draft: no MixWords rotation, zero key-schedule constants, round counts 6, 7 and 8.</summary>
    Rev2024,

    /// <summary>
    /// This project's interpretation of publicly available reference material: MixWords rotation, key-schedule round constants,
    /// round counts 7, 8 and 9.
    /// </summary>
    Rev2025,
}
