using MkvBlockCipher.Primitives;

namespace MkvBlockCipher.Kernels;

// Column tables for the table engine. Entry [column * 256 + value] holds, in byte r, matrix[r, column] times f(value),
// where f is the S-box for the forward tables and the identity for the inverse ones. The forward S-layer is folded
// in. The inverse S-layer is not: the round key sits between it and the inverse mix. Built at type initialisation
// from the S-box and mix matrices, so no table is typed by hand.
internal static class FusedTables
{
    internal static readonly uint[] Forward32 = Narrow(Columns(MixMatrices.M4, 4, SBoxTables.Forward));
    internal static readonly ulong[] Forward64 = Columns(MixMatrices.M8, 8, SBoxTables.Forward);
    internal static readonly uint[] Inverse32 = Narrow(Columns(MixMatrices.M4Inverse, 4, ReadOnlySpan<byte>.Empty));
    internal static readonly ulong[] Inverse64 = Columns(MixMatrices.M8Inverse, 8, ReadOnlySpan<byte>.Empty);

    // An empty S-box means the input is the raw byte.
    private static ulong[] Columns(ReadOnlySpan<byte> matrix, int wordBytes, ReadOnlySpan<byte> sbox)
    {
        ulong[] table = new ulong[wordBytes * 256];
        for (int column = 0; column < wordBytes; column++)
        {
            for (int value = 0; value < 256; value++)
            {
                byte input = sbox.IsEmpty ? (byte)value : sbox[value];
                ulong entry = 0;
                for (int row = 0; row < wordBytes; row++)
                {
                    entry |= (ulong)GaloisField.Multiply(matrix[row * wordBytes + column], input) << (8 * row);
                }

                table[column * 256 + value] = entry;
            }
        }

        return table;
    }

    private static uint[] Narrow(ulong[] table) => Array.ConvertAll(table, entry => (uint)entry);
}
