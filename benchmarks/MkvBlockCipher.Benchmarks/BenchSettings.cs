namespace MkvBlockCipher.Benchmarks;

// --quick exports this variable so the child processes BenchmarkDotNet starts see the same mode.
internal static class BenchSettings
{
    public const string QuickVariable = "MKV_BENCH_QUICK";

    public static bool Quick => Environment.GetEnvironmentVariable(QuickVariable) == "1";

    public static IEnumerable<MkvEngine> Engines => Quick
        ? new[] { MkvEngine.ConstantTime }
        : new[] { MkvEngine.ConstantTime, MkvEngine.VariableTime };
}
