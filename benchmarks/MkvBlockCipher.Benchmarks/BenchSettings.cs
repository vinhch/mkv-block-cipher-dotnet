namespace MkvBlockCipher.Benchmarks;

// --quick and --precise export their variables so the child processes BenchmarkDotNet starts see the same mode.
internal static class BenchSettings
{
    public const string QuickVariable = "MKV_BENCH_QUICK";
    public const string PreciseVariable = "MKV_BENCH_PRECISE";

    public static bool Quick => Environment.GetEnvironmentVariable(QuickVariable) == "1";

    public static bool Precise => Environment.GetEnvironmentVariable(PreciseVariable) == "1";

    public static IEnumerable<MkvEngine> Engines => Quick || Precise
        ? new[] { MkvEngine.ConstantTime }
        : new[] { MkvEngine.ConstantTime, MkvEngine.VariableTime };
}
