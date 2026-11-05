#!/usr/bin/env bash
set -euo pipefail
# Runs the test executable under Intel SDE in three CPU setups and fails if any run fails.
# SDE_PATH is the sde binary from the Intel SDE kit.
if [[ -z "${SDE_PATH:-}" ]]; then
  echo "SDE_PATH is not set. Download Intel SDE from https://www.intel.com/content/www/us/en/developer/articles/tool/software-development-emulator.html and set SDE_PATH to its sde binary." >&2
  exit 1
fi

dotnet build tests/MkvBlockCipher.Tests/MkvBlockCipher.Tests.csproj -c Release
exe=tests/MkvBlockCipher.Tests/bin/Release/net10.0/MkvBlockCipher.Tests
if [[ -f "$exe.exe" ]]; then
  exe="$exe.exe"
fi

# .NET 10 has no VBMI-only knob. DOTNET_EnableAVX512v2 gates IFMA and VBMI; Gfni.V512 has its own knob, EnableGFNI.
run() {
  local label=$1
  shift
  echo "== $label"
  env "$@" "$SDE_PATH" -icx -- "$exe"
}

status=0
run "AVX-512 with VBMI" MKV_EXPECT_ENGINE=X64Avx512Engine MKV_EXPECT_VBMI=1 || status=1
run "AVX-512 without VBMI, GFNI 512 kept" DOTNET_EnableAVX512v2=0 MKV_EXPECT_ENGINE=X64Avx512Engine MKV_EXPECT_VBMI=0 || status=1
run "AVX2 width preference" DOTNET_PreferredVectorBitWidth=256 MKV_EXPECT_ENGINE=X64Engine || status=1
exit "$status"
