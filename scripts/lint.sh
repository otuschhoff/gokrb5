#!/usr/bin/env bash
set -euo pipefail

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
mode=${1:-full}
case "$mode" in
  full|report)
    if [ "$#" -gt 1 ]; then
      echo "Usage: bash scripts/lint.sh {full|report|new BASE_REV}" >&2
      exit 2
    fi
    ;;
  new)
    if [ "$#" -ne 2 ] || ! git -C "$root" rev-parse --verify "${2}^{commit}" >/dev/null; then
      echo "new requires an available base commit; fetch the base revision first" >&2
      exit 2
    fi
    ;;
  *)
    echo "Usage: bash scripts/lint.sh {full|report|new BASE_REV}" >&2
    exit 2
    ;;
esac

lint=${GOLANGCI_LINT:-"$root/.bin/golangci-lint-report"}
if ! lint_path=$(command -v "$lint"); then
  echo "Custom golangci-lint not found: $lint. See CONTRIBUTING.md for setup." >&2
  exit 2
fi
if [[ "$lint_path" != /* ]]; then
  lint_path="$PWD/$lint_path"
fi
if ! command -v jq >/dev/null; then
  echo "jq is required to distinguish lint findings from typecheck failures." >&2
  exit 2
fi

config="$root/.golangci.yml"
if [ "$mode" = report ]; then
  config="$root/.golangci-report.yml"
fi
if ! "$lint_path" config verify --config "$config"; then
  exit 2
fi

args=(--allow-serial-runners --config "$config"
  --max-issues-per-linter=0 --max-same-issues=0 --uniq-by-line=false
  --issues-exit-code=10)
if [ "$mode" = new ]; then
  args+=(--new-from-rev="$2")
fi
if [ -n "${LINT_REPORT_DIR:-}" ]; then
  if ! mkdir -p -- "$LINT_REPORT_DIR" || ! report_dir=$(cd -- "$LINT_REPORT_DIR" && pwd); then
    exit 2
  fi
  json_report="$report_dir/v8-$mode.json"
  args+=(--output.text.path="$report_dir/v8-$mode.txt")
else
  json_report=$(cd -- "${TMPDIR:-/tmp}" && mktemp "$PWD/gokrb5-lint.XXXXXX") || exit 2
  trap 'rm -f -- "$json_report"' EXIT
fi
args+=(--output.json.path="$json_report")

echo "Linting v8 ($mode)"
cd -- "$root/v8" || exit 2
status=0
GOWORK=off "$lint_path" run "${args[@]}" ./... || status=$?
case "$status" in
  10)
    # golangci-lint uses the findings exit code for typecheck diagnostics too.
    if jq -e '(.Issues | length > 0) and all(.Issues[]; .FromLinter != "typecheck")' "$json_report" >/dev/null; then
      exit 1
    fi
    echo "Lint did not complete successfully; see the diagnostics above." >&2
    exit 2
    ;;
  1) exit 2 ;;
  *) exit "$status" ;;
esac
