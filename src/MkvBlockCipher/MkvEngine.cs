namespace MkvBlockCipher;

/// <summary>Engine implementation for the block rounds.</summary>
public enum MkvEngine
{
    /// <summary>Designed to never branch on or index memory by secret data.</summary>
    ConstantTime,

    /// <summary>Table-lookup engine, variable time by design.</summary>
    /// <remarks>
    /// Lookups index tables by state bytes, so the timing depends on the key and the input. Acceptable for offline
    /// or batch work on a host with no untrusted co-resident code. Not acceptable on multi-tenant servers, cloud VMs,
    /// or anywhere an attacker can measure timing.
    /// </remarks>
    VariableTime,
}
