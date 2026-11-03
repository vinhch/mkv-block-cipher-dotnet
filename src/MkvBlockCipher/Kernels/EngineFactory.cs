using MkvBlockCipher.Kernels.X64;
using MkvBlockCipher.Primitives;

namespace MkvBlockCipher.Kernels;

internal static class EngineFactory
{
    internal static BlockEngine Create(MkvParameters parameters, MkvEngine engine) =>
        engine switch
        {
            MkvEngine.ConstantTime => X64Engine.IsSupported ? new X64Engine(parameters) : new ScalarEngine(parameters),
            _ => throw new ArgumentOutOfRangeException(nameof(engine)),
        };

    // Every engine that can run on this machine. Parity tests run against each one.
    internal static IEnumerable<BlockEngine> AllSupported(MkvParameters parameters)
    {
        yield return new ScalarEngine(parameters);
        if (X64Engine.IsSupported)
        {
            yield return new X64Engine(parameters);
        }
    }
}
