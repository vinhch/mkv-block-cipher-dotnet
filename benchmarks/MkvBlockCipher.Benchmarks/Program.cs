using BenchmarkDotNet.Configs;
using BenchmarkDotNet.Engines;
using BenchmarkDotNet.Exporters;
using BenchmarkDotNet.Exporters.Json;
using BenchmarkDotNet.Filters;
using BenchmarkDotNet.Jobs;
using BenchmarkDotNet.Running;
using BenchmarkDotNet.Validators;
using MkvBlockCipher.Benchmarks;

bool quick = args.Contains("--quick");
bool cold = args.Contains("--cold");
bool precise = args.Contains("--precise");
if ((quick ? 1 : 0) + (cold ? 1 : 0) + (precise ? 1 : 0) > 1)
{
    Console.Error.WriteLine("--quick, --cold and --precise cannot be combined.");
    return 1;
}

if (quick)
{
    Environment.SetEnvironmentVariable(BenchSettings.QuickVariable, "1");
}

if (precise)
{
    Environment.SetEnvironmentVariable(BenchSettings.PreciseVariable, "1");
}

string[] benchmarkArgs = args.Where(arg => arg is not ("--quick" or "--cold" or "--precise")).ToArray();
IConfig config = cold ? new ColdStartConfig() : new EngineJobs();
BenchmarkSwitcher.FromAssembly(typeof(Program).Assembly).Run(benchmarkArgs, config);
return 0;

// The runtime reads these toggles at process start, so each job runs in its own process.
internal sealed class EngineJobs : ManualConfig
{
    public EngineJobs()
    {
        Add(CreateMinimumViable());
        AddJob(BaseJob().WithId("Default"));
        AddJob(BaseJob().WithEnvironmentVariable("DOTNET_EnableGFNI", "0").WithId("NoGfni"));
        AddJob(BaseJob().WithEnvironmentVariable("DOTNET_EnableAVX2", "0").WithId("NoAvx2"));
        if (!BenchSettings.Quick && !BenchSettings.Precise)
        {
            AddJob(BaseJob().WithEnvironmentVariable("DOTNET_EnableHWIntrinsic", "0").WithId("NoHwIntrinsic"));
        }

        // Cold-start rows must never mix with steady-state rows.
        AddFilter(new SimpleFilter(benchmark => benchmark.Descriptor.Type != typeof(ColdStartBenchmarks) && (!BenchSettings.Precise || KeepInPrecise(benchmark))));
        AddValidator(JitOptimizationsValidator.FailOnError);
        AddExporter(MarkdownExporter.GitHub, JsonExporter.Full);
    }

    // Quick jobs use the short profile and precise jobs a longer one. Both carry their mode variable into the child processes.
    private static Job BaseJob() => BenchSettings.Quick
        ? Job.ShortRun.WithEnvironmentVariable(BenchSettings.QuickVariable, "1")
        : BenchSettings.Precise
            ? Job.Default.WithLaunchCount(2).WithWarmupCount(3).WithIterationCount(10)
                .WithEnvironmentVariable(BenchSettings.PreciseVariable, "1")
            : Job.Default;

    // Precise keeps every size for the default job, and only the largest size for the fallback jobs.
    private static bool KeepInPrecise(BenchmarkCase benchmark)
    {
        if (benchmark.Job.Id == "Default")
        {
            return true;
        }

        var size = benchmark.Parameters.Items.FirstOrDefault(parameter => parameter.Name == "Size");
        return size is null || (int)size.Value == 1048576;
    }
}


// Each launch runs in its own process, so every launch pays the first-call cost.
internal sealed class ColdStartConfig : ManualConfig
{
    public ColdStartConfig()
    {
        Add(CreateMinimumViable());
        AddJob(Job.Default.WithStrategy(RunStrategy.ColdStart).WithLaunchCount(5).WithIterationCount(1));
        AddFilter(new SimpleFilter(benchmark => benchmark.Descriptor.Type == typeof(ColdStartBenchmarks)));
        AddValidator(JitOptimizationsValidator.FailOnError);
        AddExporter(MarkdownExporter.GitHub, JsonExporter.Full);
    }
}
