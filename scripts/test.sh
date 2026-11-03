#!/usr/bin/env bash
set -euo pipefail
dotnet test MkvBlockCipher.slnx -c "${1:-Debug}" "${@:2}"
