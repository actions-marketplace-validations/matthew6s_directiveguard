# Detection rules

DirectiveGuard starts with a small set of reviewable, high-signal rules. Findings are evidence for human review, not a verdict that a repository is malicious.

| ID | Severity | Detects |
| --- | --- | --- |
| ASI001 | High | Remote content piped directly to a shell |
| ASI002 | High | Instructions requesting likely credential files |
| ASI003 | Medium | Language attempting to override governing security instructions |
| ASI004 | Medium | Broad recursive deletion of home or root paths |
| ASW001 | High | Untrusted GitHub event content interpolated directly into a `run` command |
| ASW002 | High | `permissions: write-all` |
| ASW003 | High | A `pull_request_target` workflow checking out an untrusted pull-request ref |
| ASW004 | Medium | GitHub Actions referenced by branches or the `latest` tag |
| ASM001 | High | MCP endpoints using plaintext HTTP |
| ASM002 | Medium | MCP packages installed automatically without an exact version |
| ASM003 | High | Likely literal credentials in MCP configuration |

## Rule design

Every rule needs:

- a specific security boundary it protects;
- positive and negative test cases;
- a practical remediation;
- a documented severity;
- consideration of common legitimate uses.

Rules intentionally favor precision over finding every possible unsafe instruction. Suppression support will be added only with explicit, reviewable exceptions so malicious repository content cannot silently disable scanning.
