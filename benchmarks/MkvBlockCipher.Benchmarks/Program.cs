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
if (quick && cold)
{
    Console.Error.WriteLine("--quick and --cold cannot be combined.");
    return 1;
}

if (quick)
{
    Environment.SetEnvironmentVariable(BenchSettings.QuickVariable, "1");
}

string[] benchmarkArgs = args.Where(arg => arg is not ("--quick" or "--cold")).ToArray();
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
        if (!BenchSettings.Quick)
        {
            AddJob(BaseJob().WithEnvironmentVariable("DOTNET_EnableHWIntrinsic", "0").WithId("NoHwIntrinsic"));
        }

        // Cold-start rows must never mix with steady-state rows.
        AddFilter(new SimpleFilter(benchmark => benchmark.Descriptor.Type != typeof(ColdStartBenchmarks)));
        AddValidator(JitOptimizationsValidator.FailOnError);
        AddExporter(MarkdownExporter.GitHub, JsonExporter.Full);
    }

    // Quick jobs use the short profile and carry the mode variable into their child processes.
    private static Job BaseJob() => BenchSettings.Quick
        ? Job.ShortRun.WithEnvironmentVariable(BenchSettings.QuickVariable, "1")
        : Job.Default;
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
