#!/usr/bin/env bash
set -euo pipefail
dotnet run -c Release --project benchmarks/MkvBlockCipher.Benchmarks/MkvBlockCipher.Benchmarks.csproj -- "$@"
