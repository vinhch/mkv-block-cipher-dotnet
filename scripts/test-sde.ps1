#requires -version 7
# Runs the test executable under Intel SDE in three CPU setups and fails if any run fails.
# SDE_PATH is the sde binary from the Intel SDE kit.
$ErrorActionPreference = "Stop"

if (-not $env:SDE_PATH) {
  throw "SDE_PATH is not set. Download Intel SDE from https://www.intel.com/content/www/us/en/developer/articles/tool/software-development-emulator.html and set SDE_PATH to its sde binary."
}

dotnet build tests/MkvBlockCipher.Tests/MkvBlockCipher.Tests.csproj -c Release
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

$exe = "tests/MkvBlockCipher.Tests/bin/Release/net10.0/MkvBlockCipher.Tests"
if ($IsWindows) { $exe += ".exe" }

function Invoke-SdeRun {
  param([string]$Label, [hashtable]$Variables)
  Write-Host "== $Label"
  $saved = @{}
  foreach ($name in $Variables.Keys) {
    $saved[$name] = [Environment]::GetEnvironmentVariable($name)
    Set-Item -Path "Env:$name" -Value $Variables[$name]
  }
  try {
    & $env:SDE_PATH -icx -- $exe | Out-Host
    return $LASTEXITCODE
  }
  finally {
    foreach ($name in $Variables.Keys) {
      if ($null -eq $saved[$name]) {
        Remove-Item -Path "Env:$name" -ErrorAction SilentlyContinue
      }
      else {
        Set-Item -Path "Env:$name" -Value $saved[$name]
      }
    }
  }
}

# .NET 10 has no VBMI-only knob. DOTNET_EnableAVX512v2 gates IFMA and VBMI; Gfni.V512 has its own knob, EnableGFNI.
$runs = @(
  @{ Label = "AVX-512 with VBMI"; Variables = @{ MKV_EXPECT_ENGINE = "X64Avx512Engine"; MKV_EXPECT_VBMI = "1" } },
  @{ Label = "AVX-512 without VBMI, GFNI 512 kept"; Variables = @{ DOTNET_EnableAVX512v2 = "0"; MKV_EXPECT_ENGINE = "X64Avx512Engine"; MKV_EXPECT_VBMI = "0" } },
  @{ Label = "AVX2 width preference"; Variables = @{ DOTNET_PreferredVectorBitWidth = "256"; MKV_EXPECT_ENGINE = "X64Engine" } }
)

$status = 0
foreach ($run in $runs) {
  if ((Invoke-SdeRun $run.Label $run.Variables) -ne 0) { $status = 1 }
}
exit $status
