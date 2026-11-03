#requires -version 7
$ErrorActionPreference = "Stop"
dotnet format --verify-no-changes
exit $LASTEXITCODE
