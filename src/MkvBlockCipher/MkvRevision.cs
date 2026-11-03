namespace MkvBlockCipher;

/// <summary>
/// Round-count revision. For each block size the round count rises with the key length:
/// Rev2024 uses 6, 7 and 8 rounds, Rev2026 uses 7, 8 and 9 rounds.
/// Neither revision is claimed to be official.
/// </summary>
public enum MkvRevision
{
    /// <summary>Round counts 6, 7 and 8 for the three key lengths of each block size.</summary>
    Rev2024,

    /// <summary>Round counts 7, 8 and 9 for the three key lengths of each block size.</summary>
    Rev2026,
}
