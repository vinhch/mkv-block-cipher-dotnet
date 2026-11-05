using System.Runtime.Intrinsics.X86;
using MkvBlockCipher.Kernels;
using MkvBlockCipher.Primitives;
using Xunit;

namespace MkvBlockCipher.Tests.Kernels;

// Each test checks the expectation that scripts/test-sde.* sets in an MKV_EXPECT_* variable, and skips when it is unset.
public sealed class Avx512GuardTests
{
    private const string EngineVariable = "MKV_EXPECT_ENGINE";
    private const string VbmiVariable = "MKV_EXPECT_VBMI";
    private const string Avx512Engine = "X64Avx512Engine";
    private const string SkipReason = "Runs only under scripts/test-sde.*, which sets MKV_EXPECT_* variables.";

    public static bool ExpectEngineSet => ExpectedEngine is not null;

    public static bool ExpectAvx512Engine => ExpectedEngine == Avx512Engine;

    public static bool ExpectVbmiSet => ExpectedVbmi is not null;

    [Fact(SkipUnless = nameof(ExpectEngineSet), Skip = SkipReason)]
    public void Factory_picks_expected_engine()
    {
        MkvParameters parameters = MkvParameters.Create(MkvBlockSize.Mkv128, 16, MkvRevision.Rev2025);
        BlockEngine engine = EngineFactory.Create(parameters, MkvEngine.ConstantTime);

        Assert.Equal(ExpectedEngine, engine.GetType().Name);
    }

    [Fact(SkipUnless = nameof(ExpectAvx512Engine), Skip = SkipReason)]
    public void Avx512_is_visible_when_expected()
    {
        Assert.True(Avx512BW.IsSupported, "Avx512BW is not supported.");
        Assert.True(Gfni.V512.IsSupported, "Gfni.V512 is not supported.");
    }

    [Fact(SkipUnless = nameof(ExpectVbmiSet), Skip = SkipReason)]
    public void Vbmi_matches_expectation()
    {
        string? value = ExpectedVbmi;
        Assert.True(value is "0" or "1", $"{VbmiVariable} must be 0 or 1, got '{value}'.");
        Assert.Equal(value == "1", Avx512Vbmi.IsSupported);
    }

    private static string? ExpectedEngine => Environment.GetEnvironmentVariable(EngineVariable);

    private static string? ExpectedVbmi => Environment.GetEnvironmentVariable(VbmiVariable);
}
