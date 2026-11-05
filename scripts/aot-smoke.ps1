#requires -version 7
# Run from a VS developer prompt, or set IlcUseEnvironmentalTools=true. Otherwise ILC cannot find vswhere.
$ErrorActionPreference = "Stop"
$project = "samples/MkvBlockCipher.AotSmoke/MkvBlockCipher.AotSmoke.csproj"
$out = "artifacts/aot-smoke"
$rid = "win-" + [System.Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture.ToString().ToLowerInvariant()
Remove-Item -Recurse -Force $out -ErrorAction SilentlyContinue
dotnet publish $project -c Release -r $rid -p:PublishAot=true -o "$out/default"
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
# Second build: the instruction set of the machine running the script.
dotnet publish $project -c Release -r $rid -p:PublishAot=true -p:IlcInstructionSet=native -o "$out/native"
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
& "$out/default/MkvBlockCipher.AotSmoke.exe"
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
& "$out/native/MkvBlockCipher.AotSmoke.exe"
exit $LASTEXITCODE
