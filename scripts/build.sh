#!/usr/bin/env bash
set -euo pipefail
dotnet build MkvBlockCipher.slnx -c "${1:-Debug}"
