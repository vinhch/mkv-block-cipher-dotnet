using MkvBlockCipher.Primitives;

namespace MkvBlockCipher.Kernels;

// Entry n of Low(c) is c * n and of High(c) is c * (n << 4). Multiplying by c is linear over GF(2), so
// c * x = Low(c)[x & 15] ^ High(c)[x >> 4]. The index is the constant, which is public.
internal static class GfNibbleTables
{
    private static readonly byte[] LowProducts = BuildProducts(shift: 0);
    private static readonly byte[] HighProducts = BuildProducts(shift: 4);

    internal static ReadOnlySpan<byte> Low(byte constant) => LowProducts.AsSpan(16 * constant, 16);

    internal static ReadOnlySpan<byte> High(byte constant) => HighProducts.AsSpan(16 * constant, 16);

    private static byte[] BuildProducts(int shift)
    {
        byte[] products = new byte[256 * 16];
        for (int constant = 0; constant < 256; constant++)
        {
            for (int nibble = 0; nibble < 16; nibble++)
            {
                products[16 * constant + nibble] = GaloisField.Multiply((byte)constant, (byte)(nibble << shift));
            }
        }

        return products;
    }
}
