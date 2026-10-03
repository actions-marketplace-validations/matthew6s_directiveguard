# DirectiveGuard

**Know what a repository asks your AI coding agent to do before the agent does it.**

[![GitHub Marketplace](https://img.shields.io/badge/Marketplace-DirectiveGuard-2ea44f?logo=github)](https://github.com/marketplace/actions/directiveguard-ai-repository-scan)
[![CI](https://github.com/matthew6s/directiveguard/actions/workflows/ci.yml/badge.svg)](https://github.com/matthew6s/directiveguard/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

DirectiveGuard is a fast, local scanner for risky AI-agent instructions, MCP configurations, and agent-facing GitHub workflows. It runs without an account, API key, network access, or language model.

```console
$ directiveguard .
ASI001 HIGH   AGENTS.md:8  Remote content is piped to a shell
  Agent instructions download remote content and execute it directly.
  Fix: Download to a file, verify a pinned checksum or signature, inspect it, and then execute it.

1 findings (1 high, 0 medium, 0 low) in 1 files
```

> [!IMPORTANT]
> DirectiveGuard finds suspicious patterns. A clean scan is not proof that a repository is safe, and findings require human review.

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
go install github.com/matthew6s/directiveguard/cmd/directiveguard@latest
```

Scan the current repository:

```sh
directiveguard .
```

Machine-readable output and CI thresholds:

```sh
directiveguard --format json --fail-on medium .
directiveguard --format sarif --fail-on none . > directiveguard.sarif
```

Exit codes are `0` for a passing scan, `1` when findings meet the configured threshold, and `2` for usage or scanning errors.

## GitHub Action

Install it from the [GitHub Marketplace](https://github.com/marketplace/actions/directiveguard-ai-repository-scan), or add it directly to a workflow:

```yaml
name: DirectiveGuard
on: [pull_request]

permissions:
  contents: read

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: matthew6s/directiveguard@v1
        with:
          fail-on: high
```

To retain scan history in DirectiveGuard Cloud:

```yaml
      - uses: matthew6s/directiveguard@v1
        with:
          fail-on: high
          cloud-url: https://directiveguard.searce.space
          api-key: ${{ secrets.DIRECTIVEGUARD_API_KEY }}
```

Pin actions to full commit hashes in sensitive production workflows. Version tags are shown above for readability.

## Open source and Cloud

The CLI, core rules, and CI integration are MIT licensed. The deployable [DirectiveGuard Cloud](docs/cloud.md) MVP adds GitHub login, projects, scan history, plan limits, API keys, and Stripe subscriptions. The free scanner remains fully useful on its own.

## Development

```sh
go test -race ./...
go vet ./...
go build ./cmd/directiveguard
```

See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md).

## License

MIT
