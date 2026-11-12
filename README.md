# utcp-lint

**Catch SSRF and credential leaks in UTCP manuals, MCP server configs and OpenAPI specs — before they reach CI.**

One command, zero dependencies, no network calls unless you ask for them.

```bash
npx utcp-lint ./configs
```

```
configs/agent.json
  ✗ R1 tools[0].tool_call_template.url  aws_credential_reader
      Target is a cloud instance metadata endpoint (AWS / Azure / GCP / OpenStack).
      An agent calling this can read the host's temporary credentials.
      url: https://169.254.169.254/latest/meta-data/iam/security-credentials/
      → Remove the target, or point it at the public API hostname.

  ✗ R3 mcpServers.github.headers.Authorization  github
      A GitHub token is written directly into the config: ghp_****wxyz.
      → Replace it with an environment reference and rotate the key.

2 files · 9 targets · 2 errors · 0 warnings
```

---

## Why this exists

The UTCP reference implementations added a real security module. `utcp-http` 1.1.x ships `ensure_secure_url`, per-hop redirect revalidation, cross-origin credential stripping, and a loopback classifier that understands `127.1`, `2130706433`, `0x7f000001` and `::ffff:127.0.0.1`. That is good work, and it closed several CVEs.

It has one blind spot. `is_secure_url()` decides based on the **scheme**, and never looks at the **address**:

```python
from utcp_http._security import is_secure_url

is_secure_url("https://api.github.com/")                            # True
is_secure_url("https://169.254.169.254/latest/meta-data/")          # True  ← AWS/Azure/GCP IMDS
is_secure_url("https://100.100.100.200/latest/meta-data/")          # True  ← Alibaba Cloud
is_secure_url("https://metadata.google.internal/computeMetadata/v1/")# True  ← GCP
is_secure_url("https://10.0.0.5/internal-admin")                    # True  ← any VPC
```

Plaintext HTTP to a public host is rejected. HTTPS to the instance metadata service is not. A manual can declare a tool that reads the instance role credentials, pass every runtime check, and only fail if the network happens to block it — which, inside a VPC, it will not.

Two more things the runtime guard cannot do:

- **It fires too late.** By the time a call is rejected, the config is already committed, reviewed, deployed and copied into a container image.
- **It only covers the paths it knows about.** CLI, GraphQL and WebSocket transports do not all route through the same check.

`utcp-lint` reads the address instead of the scheme, and does it at commit time. That is the whole idea.

---

## What it checks

### R1 — the target address

Three layers, because there are three ways to get this wrong:

| Check | What it catches | Severity |
|---|---|---|
| `R1/cloud-metadata` | `169.254.169.254`, `169.254.170.2`, `100.100.100.200`, `metadata.google.internal`, `fd00:ec2::254` | error |
| `R1/private-address` | RFC 1918, CGNAT, IPv6 unique-local, and every integer/octal/hex spelling of them | error |
| `R1/plaintext-transport` | `http://` to anything that is not loopback | error |
| `R1/dynamic-host` | a host chosen by a tool argument (`https://{host}/api`) | warning |
| `R1/scheme` | `file:`, `gopher:`, `ftp:` and any other non-HTTP transport | error |
| `R1/dns-resolves-inward` | a public-looking hostname that resolves to a private address (with `--dns`) | warning |

Loopback is allowed on purpose: local development is legitimate, and every runtime guard in this space allows it too.

### R3 — the credential

There is no CVE behind this rule. That is the point. Every scanner in this space checks whether a config *works*; none checks whether it is safe to commit.

| Check | What it catches | Severity |
|---|---|---|
| `R3/live-key` | values shaped like a live key — `sk-…`, `ghp_…`, `AKIA…`, `AIza…`, `LTAI…`, `xox…`, JWTs | error |
| `R3/hardcoded-secret` | any literal credential that is not an environment reference | error |
| `R3/query-credential` | credentials sent as query parameters, where they land in access logs and `Referer` | warning |

`"${GITHUB_TOKEN}"` passes. `"ghp_abc123…"` does not. That is the entire rule.

Secrets are masked in all output formats, so a CI log never becomes the leak.

---

## Install

```bash
npm install --save-dev utcp-lint   # as a dev dependency
npx utcp-lint --version
```

Requires Node 18.17 or newer. No runtime dependencies.

## Usage

```bash
utcp-lint [options] [paths...]
```

Paths may be files or directories. With no path, the current directory is scanned; `node_modules` and `.git` are skipped.

```
-f, --format <name>   pretty | json | github        (default: pretty)
-o, --only <rules>    run only these rules, e.g. --only R1
-s, --skip <rules>    skip these rules, e.g. --skip R3
    --dns             resolve hostnames to catch DNS-rebinding shapes
    --timeout <ms>    per-lookup DNS timeout              (default: 2000)
    --strict          exit non-zero on warnings too
    --quiet           summary only
    --no-color        disable ANSI colour
-v, --version         print version
-h, --help            print help
```

Exit codes: `0` clean, `1` errors found, `2` the run itself failed.

### Supported inputs

The format is detected from the document's shape, not its filename, because configs get renamed constantly.

| Format | Detected by | Where URLs are read from |
|---|---|---|
| UTCP manual | `utcp_version`, `tools[]`, `manual_call_templates[]` | `tools[].tool_call_template.url` (and the older `tool_transport`) |
| MCP client config | `mcpServers{}` | `mcpServers.*.url`, plus credential-shaped `headers` |
| OpenAPI 3.x / Swagger 2.0 | `openapi`, `swagger`, `servers[]` | `servers[].url`, and `host` + `basePath` for 2.0 |

### Output

`--format json` for pipelines:

```json
{
  "summary": { "files": 2, "targets": 9, "errors": 2, "warnings": 0 },
  "findings": [
    {
      "rule": "R1",
      "check": "R1/cloud-metadata",
      "severity": "error",
      "file": "configs/agent.json",
      "pointer": "tools[0].tool_call_template.url",
      "tool": "aws_credential_reader",
      "message": "Target is a cloud instance metadata endpoint…",
      "hint": "Remove the target, or point it at the public API hostname."
    }
  ]
}
```

`--format github` emits workflow commands, so findings annotate the diff instead of scrolling past in a log.

---

## CI

```yaml
# .github/workflows/utcp-lint.yml
name: utcp-lint
on: [push, pull_request]

jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 20
      - run: npx utcp-lint --format github --strict .
```

`--strict` makes warnings fail the build too. Leave it off while you are adopting the tool.

---

## Suppressing a finding

Exemptions live in the config file next to the thing they exempt, and they can carry a reason:

```json
{
  "name": "metadata_probe",
  "_utcpLintIgnore": [
    { "rule": "R1", "reason": "Security regression test fixture, never deployed" }
  ],
  "tool_call_template": {
    "url": "https://169.254.169.254/latest/meta-data/"
  }
}
```

The bare form `"R1: reason"` and the OpenAPI-flavoured `x-utcp-lint-ignore` are accepted too. Rule-level suppression is also available on the command line with `--skip`.

Suppression is deliberately local. A blanket ignore file that hides findings across a whole repository defeats the purpose.

---

## Relationship to the runtime guards

This tool does not replace them, and it does not claim they are broken. They run at a different time and answer a different question:

| | Runtime guard (`utcp-http`) | `utcp-lint` |
|---|---|---|
| When | at call time | at commit time |
| Sees | scheme, redirect chain, declared loopback | scheme, resolved address, credential shape |
| On failure | the call is rejected | the build is rejected |
| Catches metadata over HTTPS | no | yes |
| Catches a literal key in a header | no | yes |

Use both. The runtime guard is the last line; this is the first.

## Limitations

- **JSON only** in 0.1.0. YAML MCP configs are not parsed yet.
- **DNS checks are opt-in** (`--dns`), because a linter that silently makes network calls in CI is a bad citizen. Without it, a hostname that resolves to a private address is not caught.
- **No taint tracking.** `R1/dynamic-host` warns that the destination is argument-controlled; it cannot tell you whether that argument is attacker-controlled.
- **`env` blocks in MCP stdio configs are not scanned.** A literal token in `mcpServers.x.env` is invisible to 0.1.0.
- Rules are deliberately few. A security tool that cries wolf gets switched off in a week.

## License

Apache-2.0.
