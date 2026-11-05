namespace MkvBlockCipher.Tests.Modes;

// Initial counters that put a carry where the batch code could go wrong. See ModeTestSupport.CarryCounter.
public enum CarryShape
{
    // No carry: the counter is zero.
    Zero,
    // Low byte 0xF0: lanes past 0x0F carry into the byte above it.
    LowByte,
    // Low word FF..FF F0: lanes past 0x0F carry out of the low 64 bits.
    LowWord,
    // Three 0xFF bytes above the low word, over zeros: the carry ripples through them and stops at the zero.
    Ripple,
}
