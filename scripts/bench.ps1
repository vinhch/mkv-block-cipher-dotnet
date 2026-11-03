#requires -version 7
param(
  [Parameter(ValueFromRemainingArguments = $true)][string[]]$Rest
)
$ErrorActionPreference = "Stop"
dotnet run -c Release --project benchmarks/MkvBlockCipher.Benchmarks/MkvBlockCipher.Benchmarks.csproj -- @Rest
exit $LASTEXITCODE
