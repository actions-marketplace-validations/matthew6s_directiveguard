# AgentShield

**Know what a repository asks your AI coding agent to do before the agent does it.**

AgentShield is a fast, local scanner for risky AI-agent instructions, MCP configurations, and agent-facing GitHub workflows. It runs without an account, API key, network access, or language model.

```console
$ agentshield .
ASI001 HIGH   AGENTS.md:8  Remote content is piped to a shell
  Agent instructions download remote content and execute it directly.
  Fix: Download to a file, verify a pinned checksum or signature, inspect it, and then execute it.

1 findings (1 high, 0 medium, 0 low) in 1 files
```

> [!IMPORTANT]
> AgentShield finds suspicious patterns. A clean scan is not proof that a repository is safe, and findings require human review.

## What it scans

- `AGENTS.md`, `CLAUDE.md`, `.cursorrules`, and Copilot instruction files
- `.mcp.json` and common MCP configuration filenames
- `.github/workflows/*.yml`
- Direct execution of remote scripts
- Instructions requesting credentials or bypassing security controls
- Untrusted GitHub event content interpolated into shell commands
- Broad workflow permissions and dangerous `pull_request_target` checkouts
- Insecure MCP endpoints, embedded credentials, and unpinned packages

See the complete [rule reference](docs/rules.md).

## Install

Build from source with Go 1.26 or newer:

```sh
go install github.com/matthew6s/agentshield/cmd/agentshield@latest
```

Scan the current repository:

```sh
agentshield .
```

Machine-readable output and CI thresholds:

```sh
agentshield --format json --fail-on medium .
agentshield --format sarif --fail-on none . > agentshield.sarif
```

Exit codes are `0` for a passing scan, `1` when findings meet the configured threshold, and `2` for usage or scanning errors.

## GitHub Action

```yaml
name: AgentShield
on: [pull_request]

permissions:
  contents: read

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: matthew6s/agentshield@v1
        with:
          fail-on: high
```

Pin actions to full commit hashes in sensitive production workflows. Version tags are shown above for readability.

## Open source and Cloud

The CLI, core rules, and CI integration are MIT licensed. The planned paid [AgentShield Cloud](docs/cloud.md) adds organization-wide policy, continuous monitoring, history, ownership, audit exports, and enterprise access controls. The free scanner remains fully useful on its own.

## Development

```sh
go test -race ./...
go vet ./...
go build ./cmd/agentshield
```

See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md).

## License

MIT
