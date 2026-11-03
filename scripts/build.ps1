#requires -version 7
param([string]$Configuration = "Debug")
$ErrorActionPreference = "Stop"
dotnet build MkvBlockCipher.slnx -c $Configuration
exit $LASTEXITCODE
