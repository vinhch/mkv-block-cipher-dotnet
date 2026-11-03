#requires -version 7
param(
  [string]$Configuration = "Debug",
  [Parameter(ValueFromRemainingArguments = $true)][string[]]$Rest
)
$ErrorActionPreference = "Stop"
dotnet test MkvBlockCipher.slnx -c $Configuration @Rest
exit $LASTEXITCODE
