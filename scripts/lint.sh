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
if ! command -v "$lint" >/dev/null; then
  echo "Custom golangci-lint not found: $lint. See CONTRIBUTING.md for setup." >&2
  exit 2
fi

config="$root/.golangci.yml"
if [ "$mode" = report ]; then
  config="$root/.golangci-report.yml"
fi
"$lint" config verify --config "$config"

args=(--allow-serial-runners --config "$config"
  --max-issues-per-linter=0 --max-same-issues=0 --uniq-by-line=false)
if [ "$mode" = new ]; then
  args+=(--new-from-rev="$2")
fi
if [ -n "${LINT_REPORT_DIR:-}" ]; then
  mkdir -p -- "$LINT_REPORT_DIR"
  report_dir=$(cd -- "$LINT_REPORT_DIR" && pwd)
fi

status=0
for module in . v8; do
  label=v7
  if [ "$module" = v8 ]; then
    label=v8
  fi
  output=()
  if [ -n "${LINT_REPORT_DIR:-}" ]; then
    output=(--output.json.path="$report_dir/$label-$mode.json"
      --output.text.path="$report_dir/$label-$mode.txt")
  fi
  echo "Linting $label ($mode)"
  result=0
  (cd -- "$root/$module" && "$lint" run "${args[@]}" "${output[@]}" ./...) || result=$?
  if [ "$result" -gt 1 ]; then
    exit "$result"
  fi
  if [ "$result" -eq 1 ]; then
    status=1
  fi
done
exit "$status"
