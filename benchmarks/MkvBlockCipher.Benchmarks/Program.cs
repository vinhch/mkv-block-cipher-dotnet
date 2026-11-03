using BenchmarkDotNet.Configs;
using BenchmarkDotNet.Exporters;
using BenchmarkDotNet.Exporters.Json;
using BenchmarkDotNet.Jobs;
using BenchmarkDotNet.Running;
using BenchmarkDotNet.Validators;

BenchmarkSwitcher.FromAssembly(typeof(Program).Assembly).Run(args, new EngineJobs());

// The runtime reads these toggles at process start, so each job runs in its own process.
internal sealed class EngineJobs : ManualConfig
{
    public EngineJobs()
    {
        Add(CreateMinimumViable());
        AddJob(Job.Default.WithId("Default"));
        AddJob(Job.Default.WithEnvironmentVariable("DOTNET_EnableGFNI", "0").WithId("NoGfni"));
        AddJob(Job.Default.WithEnvironmentVariable("DOTNET_EnableAVX2", "0").WithId("NoAvx2"));
        AddJob(Job.Default.WithEnvironmentVariable("DOTNET_EnableHWIntrinsic", "0").WithId("NoHwIntrinsic"));
        AddValidator(JitOptimizationsValidator.FailOnError);
        AddExporter(MarkdownExporter.GitHub, JsonExporter.Full);
    }
}
