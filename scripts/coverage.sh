#!/usr/bin/env bash
set -euo pipefail
# Collect coverlet coverage over every test project, then render HTML and a console summary.
CONFIG="${1:-Release}"
RESULTS_DIR="artifacts/coverage"

rm -rf "$RESULTS_DIR"
dotnet tool restore
dotnet test MkvBlockCipher.slnx -c "$CONFIG" --coverlet --results-directory "$RESULTS_DIR" "${@:2}"

# Guard the report COUNT, not just that some report exists: coverlet.MTP can instrument nothing and still
# exit 0 with every test green, and a partial run (six reports out of seven) is invisible to reportgenerator.
# Counted in a loop: grep -L exits 1 on a listed file in some grep versions, and pipefail would end the script silently.
expected=0
for project in tests/*/*.csproj; do
  grep -q '<IsTestingPlatformApplication>false' "$project" || expected=$((expected + 1))
done
reports=$(find "$RESULTS_DIR" -name '*coverage.cobertura.*.xml' 2>/dev/null | wc -l | tr -d ' ' || true)
if (( reports != expected )); then
  printf 'expected %d cobertura reports, got %d:\n' "$expected" "$reports" >&2
  find "$RESULTS_DIR" -name '*coverage.cobertura.*.xml' 2>/dev/null >&2 || true
  exit 1
fi

dotnet tool run reportgenerator \
  "-reports:$RESULTS_DIR/**/*coverage.cobertura.*.xml" \
  "-targetdir:$RESULTS_DIR/report" \
  "-reporttypes:Html;TextSummary;MarkdownSummaryGithub"

cat "$RESULTS_DIR/report/Summary.txt"
echo "HTML report: $RESULTS_DIR/report/index.html"
