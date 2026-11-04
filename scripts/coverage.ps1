#requires -version 7
param([string]$Configuration = "Release")
$ErrorActionPreference = "Stop"
# Collect coverlet coverage over every test project, then render HTML and a console summary.
$ResultsDir = "artifacts/coverage"

if (Test-Path $ResultsDir) { Remove-Item -Recurse -Force $ResultsDir }
dotnet tool restore
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
dotnet test MkvBlockCipher.slnx -c $Configuration --coverlet --results-directory $ResultsDir
# $ErrorActionPreference does not stop on a failed native command, and coverlet still writes its reports
# when tests fail, so the exit code is checked before the guard.
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

# Guard the report COUNT, not just that some report exists: coverlet can instrument nothing and still exit 0,
# and a partial run is invisible to reportgenerator.
$reports = @(Get-ChildItem -Path $ResultsDir -Recurse -Filter "*coverage.cobertura.*.xml" -ErrorAction SilentlyContinue)
$expected = @(Get-ChildItem tests/*/*.csproj |
  Where-Object { -not (Select-String -Path $_.FullName -Pattern '<IsTestingPlatformApplication>false' -Quiet) }).Count
if ($reports.Count -ne $expected) {
  throw "expected $expected cobertura reports, got $($reports.Count): $($reports.Name -join ', ')"
}

dotnet tool run reportgenerator `
  "-reports:$ResultsDir/**/*coverage.cobertura.*.xml" `
  "-targetdir:$ResultsDir/report" `
  "-reporttypes:Html;TextSummary;MarkdownSummaryGithub"
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Get-Content "$ResultsDir/report/Summary.txt"
Write-Host "HTML report: $ResultsDir/report/index.html"
