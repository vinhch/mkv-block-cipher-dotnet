namespace MkvBlockCipher.Primitives;

internal static class GaloisField
{
    // x^8 + x^5 + x^3 + x + 1
    private const int Polynomial = 0x12B;

    // constant is public, so its bits may steer a branch; value is secret and never does.
    internal static byte Multiply(byte constant, byte value)
    {
        int product = 0;
        int a = value;
        for (int bit = 0; bit < 8; bit++)
        {
            if (((constant >> bit) & 1) != 0)
            {
                product ^= a;
            }

            a <<= 1;
            int overflow = (a >> 8) & 1;
            a ^= Polynomial & -overflow;
        }

        return (byte)product;
    }
}
