namespace MkvBlockCipher.Primitives;

// GF(2)-linear maps on bytes, encoded as the qword GFNI reads. Row i holds the mask for output bit i and sits in
// byte 7 - i; bit j of each row weights input bit j.
internal static class GfAffine
{
    // columns[j] is the image of input bit j. Only the first eight entries are read.
    internal static ulong FromColumns(ReadOnlySpan<byte> columns)
    {
        ulong matrix = 0;
        for (int input = 0; input < 8; input++)
        {
            for (int row = 0; row < 8; row++)
            {
                if (((columns[input] >> row) & 1) != 0)
                {
                    matrix |= 1UL << (8 * (7 - row) + input);
                }
            }
        }

        return matrix;
    }
}
