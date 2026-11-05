#!/usr/bin/env bash
set -euo pipefail
project=samples/MkvBlockCipher.AotSmoke/MkvBlockCipher.AotSmoke.csproj
out=artifacts/aot-smoke
rm -rf "$out"
dotnet publish "$project" -c Release -r linux-x64 -p:PublishAot=true -o "$out/default"
# Second build: the instruction set of the machine running the script.
dotnet publish "$project" -c Release -r linux-x64 -p:PublishAot=true -p:IlcInstructionSet=native -o "$out/native"
"$out/default/MkvBlockCipher.AotSmoke"
"$out/native/MkvBlockCipher.AotSmoke"
