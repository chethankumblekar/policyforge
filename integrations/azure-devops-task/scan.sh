#!/usr/bin/env bash
# Azure Pipelines execution handler for the PolicyForgeScan task (see
# task.json). Installs the CLI, runs a scan, uploads the SARIF results as
# a build artifact, and gates the build the same way the GitHub Action's
# fail-on-high input does.
set -uo pipefail

path_input="${INPUT_PATH:-.}"
policy_dir="${INPUT_POLICYDIR:-}"
fail_on_high="${INPUT_FAILONHIGH:-true}"
staging_dir="${BUILD_ARTIFACTSTAGINGDIRECTORY:-.}"

echo "##[section]Installing PolicyForge"
go install github.com/chethankumblekar/policyforge/cmd/policyforge@latest
policyforge_bin="$(go env GOPATH)/bin/policyforge"

args=(scan --path "$path_input" --format sarif)
if [ -n "$policy_dir" ]; then
  args+=(--policy-dir "$policy_dir")
fi

echo "##[section]Running PolicyForge scan"
sarif_file="$staging_dir/policyforge-results.sarif"
"$policyforge_bin" "${args[@]}" > "$sarif_file"
scan_exit=$?

echo "##vso[artifact.upload containerfolder=policyforge;artifactname=policyforge-results]$sarif_file"

if [ "$scan_exit" -ne 0 ]; then
  if [ "$fail_on_high" = "true" ]; then
    echo "##vso[task.logissue type=error]PolicyForge found HIGH or CRITICAL severity findings — see the policyforge-results artifact."
    echo "##vso[task.complete result=Failed;]"
    exit 1
  fi
  echo "##vso[task.logissue type=warning]PolicyForge found HIGH or CRITICAL severity findings (failOnHigh is false) — see the policyforge-results artifact."
fi
