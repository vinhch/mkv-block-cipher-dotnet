using MkvBlockCipher.Primitives;

namespace MkvBlockCipher.Kernels;

internal static class EngineFactory
{
    internal static BlockEngine Create(MkvParameters parameters, MkvEngine engine) =>
        engine switch
        {
            MkvEngine.ConstantTime => new ScalarEngine(parameters),
            _ => throw new ArgumentOutOfRangeException(nameof(engine)),
        };
}
