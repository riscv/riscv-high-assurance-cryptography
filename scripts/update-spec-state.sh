#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "Usage: scripts/update-spec-state.sh <version> [date]" >&2
  exit 2
fi

version="$1"
updated_on="${2:-$(date +%Y-%m-%d)}"

# Every phase name, milestone version and notice below comes from
# scripts/release-info.sh, the single source of the canonical lifecycle phases.
# Nothing is hard-coded here, so SPEC_STATE.md cannot drift from the PDF title
# page or the Antora site.
ri=./scripts/release-info.sh
phases="draft-and-development development-complete stabilized frozen ratification-ready ratified"

phase="$($ri phase "$version")"
milestone="$($ri milestone "$version")"

{
  echo "# Specification State"
  echo
  echo "Current milestone: ${milestone}"
  echo "Current state: $($ri display "$version") (${phase})"
  echo "Current version: ${version}"
  echo "Last updated: ${updated_on}"
  echo
  echo "## Milestone Targets"
  echo
  for p in $phases; do
    floor="$($ri phase-floor-version "$p")"
    if $ri is-milestone "$floor"; then
      echo "- ${floor} $($ri display "$floor") (${p})"
    fi
  done
  echo
  echo "## State Definitions"
  for p in $phases; do
    floor="$($ri phase-floor-version "$p")"
    echo
    echo "### $($ri display "$floor")"
    echo
    $ri notice "$floor"
  done
} > SPEC_STATE.md
