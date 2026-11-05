using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;
using MkvBlockCipher.Primitives;

namespace MkvBlockCipher.Kernels.X64;

// S-box as GF(2^4) arithmetic in GF(2^8) mod 0x11B: nibbles embed through beta = 0x5C, a root of t^4 + t + 1, and the
// result maps back to nibbles. Inversion, products and Frobenius maps run in GF(2^8); zero cases blend, never branch.
// Construction: docs/algorithm.md, "Where the tables come from". Callers check Gfni.IsSupported (V256 for 256 bits,
// V512 for 512 bits).
internal static class SBoxGfni
{
    private static readonly Vector128<byte> EmbedHigh128 = Vector128.Create(SubfieldMaps.EmbedHigh).AsByte();
    private static readonly Vector128<byte> EmbedLow128 = Vector128.Create(SubfieldMaps.EmbedLow).AsByte();
    private static readonly Vector128<byte> Identity128 = Vector128.Create(SubfieldMaps.Identity).AsByte();
    private static readonly Vector128<byte> Square128 = Vector128.Create(SubfieldMaps.Square).AsByte();
    private static readonly Vector128<byte> Fourth128 = Vector128.Create(SubfieldMaps.Fourth).AsByte();
    private static readonly Vector128<byte> Eighth128 = Vector128.Create(SubfieldMaps.Eighth).AsByte();
    private static readonly Vector128<byte> BackHigh128 = Vector128.Create(SubfieldMaps.BackHigh).AsByte();
    private static readonly Vector128<byte> BackLow128 = Vector128.Create(SubfieldMaps.BackLow).AsByte();

    private static readonly Vector256<byte> EmbedHigh256 = Vector256.Create(SubfieldMaps.EmbedHigh).AsByte();
    private static readonly Vector256<byte> EmbedLow256 = Vector256.Create(SubfieldMaps.EmbedLow).AsByte();
    private static readonly Vector256<byte> Identity256 = Vector256.Create(SubfieldMaps.Identity).AsByte();
    private static readonly Vector256<byte> Square256 = Vector256.Create(SubfieldMaps.Square).AsByte();
    private static readonly Vector256<byte> Fourth256 = Vector256.Create(SubfieldMaps.Fourth).AsByte();
    private static readonly Vector256<byte> Eighth256 = Vector256.Create(SubfieldMaps.Eighth).AsByte();
    private static readonly Vector256<byte> BackHigh256 = Vector256.Create(SubfieldMaps.BackHigh).AsByte();
    private static readonly Vector256<byte> BackLow256 = Vector256.Create(SubfieldMaps.BackLow).AsByte();

    private static readonly Vector512<byte> EmbedHigh512 = Vector512.Create(SubfieldMaps.EmbedHigh).AsByte();
    private static readonly Vector512<byte> EmbedLow512 = Vector512.Create(SubfieldMaps.EmbedLow).AsByte();
    private static readonly Vector512<byte> Identity512 = Vector512.Create(SubfieldMaps.Identity).AsByte();
    private static readonly Vector512<byte> Square512 = Vector512.Create(SubfieldMaps.Square).AsByte();
    private static readonly Vector512<byte> Fourth512 = Vector512.Create(SubfieldMaps.Fourth).AsByte();
    private static readonly Vector512<byte> Eighth512 = Vector512.Create(SubfieldMaps.Eighth).AsByte();
    private static readonly Vector512<byte> BackHigh512 = Vector512.Create(SubfieldMaps.BackHigh).AsByte();
    private static readonly Vector512<byte> BackLow512 = Vector512.Create(SubfieldMaps.BackLow).AsByte();

    internal static Vector128<byte> Forward(Vector128<byte> x)
    {
        Vector128<byte> zero = Vector128<byte>.Zero;
        Vector128<byte> highElement = Gfni.GaloisFieldAffineTransform(x, EmbedHigh128, 0);
        Vector128<byte> lowElement = Gfni.GaloisFieldAffineTransform(x, EmbedLow128, 0);
        Vector128<byte> inverseHigh = Gfni.GaloisFieldAffineTransformInverse(highElement, Identity128, 0);
        Vector128<byte> inverseHighFourth = Gfni.GaloisFieldAffineTransformInverse(highElement, Fourth128, 0);
        Vector128<byte> yLow = Vector128.ConditionalSelect(
            Vector128.Equals(lowElement, zero),
            inverseHigh,
            Gfni.GaloisFieldMultiply(inverseHighFourth, lowElement));
        Vector128<byte> product = Gfni.GaloisFieldMultiply(lowElement, yLow);
        Vector128<byte> yHigh = Vector128.ConditionalSelect(
            Vector128.Equals(yLow, zero),
            Gfni.GaloisFieldAffineTransformInverse(lowElement, Identity128, 0),
            Gfni.GaloisFieldAffineTransformInverse(product, Square128, 0));
        Vector128<byte> high = Gfni.GaloisFieldAffineTransform(yHigh, BackHigh128, 0);
        // The S-box output constant 0x01 is the affine b of the low back-map.
        Vector128<byte> low = Gfni.GaloisFieldAffineTransform(yLow, BackLow128, 0x01);
        return high | low;
    }

    internal static Vector128<byte> Inverse(Vector128<byte> z)
    {
        Vector128<byte> zero = Vector128<byte>.Zero;
        // z ^ 1 flips bit 0 of the low nibble, and phi(n ^ 1) = phi(n) ^ 1, so the 0x01 rides on the low embedding.
        Vector128<byte> highElement = Gfni.GaloisFieldAffineTransform(z, EmbedHigh128, 0);
        Vector128<byte> lowElement = Gfni.GaloisFieldAffineTransform(z, EmbedLow128, 0x01);
        Vector128<byte> inverseLow = Gfni.GaloisFieldAffineTransformInverse(lowElement, Identity128, 0);
        Vector128<byte> inverseHigh = Gfni.GaloisFieldAffineTransformInverse(highElement, Identity128, 0);
        Vector128<byte> highEighth = Gfni.GaloisFieldAffineTransform(highElement, Eighth128, 0);
        Vector128<byte> highEighthTimesLow = Gfni.GaloisFieldMultiply(highEighth, lowElement);
        Vector128<byte> xLow = Vector128.ConditionalSelect(
            Vector128.Equals(lowElement, zero),
            inverseHigh,
            Gfni.GaloisFieldAffineTransformInverse(highEighthTimesLow, Identity128, 0));
        Vector128<byte> lowProduct = Gfni.GaloisFieldMultiply(xLow, inverseLow);
        Vector128<byte> xHigh = Vector128.ConditionalSelect(
            Vector128.Equals(highElement, zero),
            inverseLow,
            Gfni.GaloisFieldAffineTransform(lowProduct, Fourth128, 0));
        Vector128<byte> high = Gfni.GaloisFieldAffineTransform(xHigh, BackHigh128, 0);
        Vector128<byte> low = Gfni.GaloisFieldAffineTransform(xLow, BackLow128, 0);
        return high | low;
    }

    internal static Vector256<byte> Forward(Vector256<byte> x)
    {
        Vector256<byte> zero = Vector256<byte>.Zero;
        Vector256<byte> highElement = Gfni.V256.GaloisFieldAffineTransform(x, EmbedHigh256, 0);
        Vector256<byte> lowElement = Gfni.V256.GaloisFieldAffineTransform(x, EmbedLow256, 0);
        Vector256<byte> inverseHigh = Gfni.V256.GaloisFieldAffineTransformInverse(highElement, Identity256, 0);
        Vector256<byte> inverseHighFourth = Gfni.V256.GaloisFieldAffineTransformInverse(highElement, Fourth256, 0);
        Vector256<byte> yLow = Vector256.ConditionalSelect(
            Vector256.Equals(lowElement, zero),
            inverseHigh,
            Gfni.V256.GaloisFieldMultiply(inverseHighFourth, lowElement));
        Vector256<byte> product = Gfni.V256.GaloisFieldMultiply(lowElement, yLow);
        Vector256<byte> yHigh = Vector256.ConditionalSelect(
            Vector256.Equals(yLow, zero),
            Gfni.V256.GaloisFieldAffineTransformInverse(lowElement, Identity256, 0),
            Gfni.V256.GaloisFieldAffineTransformInverse(product, Square256, 0));
        Vector256<byte> high = Gfni.V256.GaloisFieldAffineTransform(yHigh, BackHigh256, 0);
        // The S-box output constant 0x01 is the affine b of the low back-map.
        Vector256<byte> low = Gfni.V256.GaloisFieldAffineTransform(yLow, BackLow256, 0x01);
        return high | low;
    }

    internal static Vector256<byte> Inverse(Vector256<byte> z)
    {
        Vector256<byte> zero = Vector256<byte>.Zero;
        // z ^ 1 flips bit 0 of the low nibble, and phi(n ^ 1) = phi(n) ^ 1, so the 0x01 rides on the low embedding.
        Vector256<byte> highElement = Gfni.V256.GaloisFieldAffineTransform(z, EmbedHigh256, 0);
        Vector256<byte> lowElement = Gfni.V256.GaloisFieldAffineTransform(z, EmbedLow256, 0x01);
        Vector256<byte> inverseLow = Gfni.V256.GaloisFieldAffineTransformInverse(lowElement, Identity256, 0);
        Vector256<byte> inverseHigh = Gfni.V256.GaloisFieldAffineTransformInverse(highElement, Identity256, 0);
        Vector256<byte> highEighth = Gfni.V256.GaloisFieldAffineTransform(highElement, Eighth256, 0);
        Vector256<byte> highEighthTimesLow = Gfni.V256.GaloisFieldMultiply(highEighth, lowElement);
        Vector256<byte> xLow = Vector256.ConditionalSelect(
            Vector256.Equals(lowElement, zero),
            inverseHigh,
            Gfni.V256.GaloisFieldAffineTransformInverse(highEighthTimesLow, Identity256, 0));
        Vector256<byte> lowProduct = Gfni.V256.GaloisFieldMultiply(xLow, inverseLow);
        Vector256<byte> xHigh = Vector256.ConditionalSelect(
            Vector256.Equals(highElement, zero),
            inverseLow,
            Gfni.V256.GaloisFieldAffineTransform(lowProduct, Fourth256, 0));
        Vector256<byte> high = Gfni.V256.GaloisFieldAffineTransform(xHigh, BackHigh256, 0);
        Vector256<byte> low = Gfni.V256.GaloisFieldAffineTransform(xLow, BackLow256, 0);
        return high | low;
    }

    internal static Vector512<byte> Forward(Vector512<byte> x)
    {
        Vector512<byte> zero = Vector512<byte>.Zero;
        Vector512<byte> highElement = Gfni.V512.GaloisFieldAffineTransform(x, EmbedHigh512, 0);
        Vector512<byte> lowElement = Gfni.V512.GaloisFieldAffineTransform(x, EmbedLow512, 0);
        Vector512<byte> inverseHigh = Gfni.V512.GaloisFieldAffineTransformInverse(highElement, Identity512, 0);
        Vector512<byte> inverseHighFourth = Gfni.V512.GaloisFieldAffineTransformInverse(highElement, Fourth512, 0);
        Vector512<byte> yLow = Vector512.ConditionalSelect(
            Vector512.Equals(lowElement, zero),
            inverseHigh,
            Gfni.V512.GaloisFieldMultiply(inverseHighFourth, lowElement));
        Vector512<byte> product = Gfni.V512.GaloisFieldMultiply(lowElement, yLow);
        Vector512<byte> yHigh = Vector512.ConditionalSelect(
            Vector512.Equals(yLow, zero),
            Gfni.V512.GaloisFieldAffineTransformInverse(lowElement, Identity512, 0),
            Gfni.V512.GaloisFieldAffineTransformInverse(product, Square512, 0));
        Vector512<byte> high = Gfni.V512.GaloisFieldAffineTransform(yHigh, BackHigh512, 0);
        // The S-box output constant 0x01 is the affine b of the low back-map.
        Vector512<byte> low = Gfni.V512.GaloisFieldAffineTransform(yLow, BackLow512, 0x01);
        return high | low;
    }

    internal static Vector512<byte> Inverse(Vector512<byte> z)
    {
        Vector512<byte> zero = Vector512<byte>.Zero;
        // z ^ 1 flips bit 0 of the low nibble, and phi(n ^ 1) = phi(n) ^ 1, so the 0x01 rides on the low embedding.
        Vector512<byte> highElement = Gfni.V512.GaloisFieldAffineTransform(z, EmbedHigh512, 0);
        Vector512<byte> lowElement = Gfni.V512.GaloisFieldAffineTransform(z, EmbedLow512, 0x01);
        Vector512<byte> inverseLow = Gfni.V512.GaloisFieldAffineTransformInverse(lowElement, Identity512, 0);
        Vector512<byte> inverseHigh = Gfni.V512.GaloisFieldAffineTransformInverse(highElement, Identity512, 0);
        Vector512<byte> highEighth = Gfni.V512.GaloisFieldAffineTransform(highElement, Eighth512, 0);
        Vector512<byte> highEighthTimesLow = Gfni.V512.GaloisFieldMultiply(highEighth, lowElement);
        Vector512<byte> xLow = Vector512.ConditionalSelect(
            Vector512.Equals(lowElement, zero),
            inverseHigh,
            Gfni.V512.GaloisFieldAffineTransformInverse(highEighthTimesLow, Identity512, 0));
        Vector512<byte> lowProduct = Gfni.V512.GaloisFieldMultiply(xLow, inverseLow);
        Vector512<byte> xHigh = Vector512.ConditionalSelect(
            Vector512.Equals(highElement, zero),
            inverseLow,
            Gfni.V512.GaloisFieldAffineTransform(lowProduct, Fourth512, 0));
        Vector512<byte> high = Gfni.V512.GaloisFieldAffineTransform(xHigh, BackHigh512, 0);
        Vector512<byte> low = Gfni.V512.GaloisFieldAffineTransform(xLow, BackLow512, 0);
        return high | low;
    }
}
