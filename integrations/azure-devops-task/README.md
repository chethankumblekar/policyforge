# PolicyForge Azure DevOps task

`task.json` + `scan.sh` define a custom Azure Pipelines task with the same
job as the [GitHub Action](../github-action): install PolicyForge, run a
scan, publish SARIF results, and gate the build on HIGH/CRITICAL findings.

## Option A — no extension packaging required

If you don't want to package and publish this as a private Marketplace
extension, just run `scan.sh` directly as a pipeline step:

```yaml
steps:
  - task: GoTool@0
    inputs:
      version: '1.22'
  - bash: |
      chmod +x scan.sh
      ./scan.sh
    displayName: 'PolicyForge scan'
    env:
      INPUT_PATH: '$(Build.SourcesDirectory)'
      INPUT_FAILONHIGH: 'true'
    workingDirectory: integrations/azure-devops-task # or wherever you vendor scan.sh
```

## Option B — package as a private extension

Use the [`tfx-cli`](https://github.com/Microsoft/tfs-cli) to package and
publish `task.json`/`scan.sh` as a private extension to your Azure DevOps
organization, then reference it by task name in a pipeline:

```bash
npm install -g tfx-cli
tfx build tasks upload --task-path integrations/azure-devops-task
```

```yaml
steps:
  - task: PolicyForgeScan@0
    inputs:
      path: '$(Build.SourcesDirectory)'
      failOnHigh: true
```

## Inputs

| Input | Default | Description |
|---|---|---|
| `path` | `.` | Path to the directory of IaC files to scan |
| `policyDir` | *(none)* | Optional directory of custom user-authored `.rego` policy files (see root [README](../../README.md#custom-policy-authoring)) |
| `failOnHigh` | `true` | Fail the build if HIGH or CRITICAL findings are present |
