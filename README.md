# utcp-lint

**A static check for CVE-2026-45366 and CVE-2026-101060 — the two SSRF bugs in the UTCP reference implementations — plus the credential leaks and manual-schema mistakes that neither CVE covers.**

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

## The two CVEs

Both are fixed upstream. Both are still reachable through configuration, which is why a linter exists.

### CVE-2026-45366 — `@utcp/http` before 1.1.2 (CVSS 4.7, CWE-918)

The validated URL and the called URL were different URLs. `registerManual()` checked the discovery URL against an HTTPS / loopback allowlist, `callTool()` then reused the resolved `toolCallTemplate.url` without re-checking, and `OpenApiConverter` trusted whatever `servers[0].url` the spec declared. A spec hosted on a legitimate HTTPS endpoint could declare:

```json
{ "servers": [{ "url": "http://169.254.169.254" }] }
```

and the converter built tools that pointed straight at the instance metadata service.

The discovery-time guard had a second flaw: it was a `startsWith("http://localhost")` prefix test, so `http://localhost.evil.com` — an ordinary registrable domain — passed it.

→ `R2/loopback-prefix`, `R2/wildcard-dns-metadata`

### CVE-2026-101060 — `python-utcp` before 1.1.4 (CVSS 8.4, CWE-918)

The validated URL and the fetched URL were different URLs, one hop later. `HttpCommunicationProtocol.call_tool` validated the initial tool URL, then followed HTTP redirects without revalidating the target. An endpoint under attacker control answers `302 Location: http://169.254.169.254/…` and the client returns the internal response body to the caller.

→ `R2/shortener`, `R2/tunnel`

### What upgrading does not fix

Pinning `utcp-http >= 1.1.2` and `utcp >= 1.1.4` closes the library bug. It does not close the manual. A config that points at a URL shortener, at a wildcard-DNS hostname, or at a host that merely *starts with* `localhost` reintroduces the same trust-boundary gap no matter which client version reads it — the client is doing exactly what the manual told it to do.

That residue is what `utcp-lint` reads: the manual, at commit time, before any client sees it.

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

### R2 — the trust boundary

The address rules in R1 answer "where does this point". R2 answers a different question: **is the URL that was reviewed the URL that will be called.** That is the shape of both CVEs above, and configuration can reintroduce it after the libraries are patched.

| Check | What it catches | Severity |
|---|---|---|
| `R2/loopback-prefix` | `localhost.evil.com`, `127.0.0.1.attacker.tld` — a hostname that only *begins with* a trusted label (CVE-2026-45366) | error |
| `R2/wildcard-dns-metadata` | `169.254.169.254.nip.io` and `169-254-169-254.nip.io` — IMDS reached through a hostname | error |
| `R2/wildcard-dns-private` | RFC 1918, CGNAT or ULA encoded in `nip.io`, `sslip.io`, `xip.io`, `traefik.me` | error |
| `R2/wildcard-dns` | any other address wrapped in a wildcard-DNS hostname | warning |
| `R2/shortener` | `bit.ly`, `t.cn`, `tinyurl.com` and a dozen more — the destination is decided after review (CVE-2026-101060) | error |
| `R2/tunnel` | `ngrok.io`, `trycloudflare.com`, `loca.lt`, `serveo.net` — the endpoint changes with whoever holds the tunnel | warning |
| `R2/loopback-alias` | `localtest.me`, `lvh.me`, `vcap.me` — public names that resolve to 127.0.0.1 by design | warning |
| `R2/relative-target` | `/api/v1` — no origin at all, so the loader decides where the call goes | warning |

The wildcard-DNS checks are the ones R1 structurally cannot do. `169.254.169.254.nip.io` is a *name*, not a literal address, so the address classifier in R1 has nothing to look at — and every hostname allowlist in every client waves it through. R2 decodes the address back out of the hostname and hands it to the same classifier R1 uses.

```bash
# what R2 sees that a hostname allowlist does not
169.254.169.254.nip.io     → 169.254.169.254  (AWS/Azure/GCP IMDS)   error
10-0-0-5.nip.io            → 10.0.0.5         (RFC 1918)            error
8.8.8.8.nip.io             → 8.8.8.8          (public)              warning
```

### R3 — the credential

There is no CVE behind this rule. That is the point. Every scanner in this space checks whether a config *works*; none checks whether it is safe to commit.

| Check | What it catches | Severity |
|---|---|---|
| `R3/live-key` | values shaped like a live key — `sk-…`, `ghp_…`, `AKIA…`, `AIza…`, `LTAI…`, `xox…`, JWTs | error |
| `R3/hardcoded-secret` | any literal credential that is not an environment reference | error |
| `R3/query-credential` | credentials sent as query parameters, where they land in access logs and `Referer` | warning |

`"${GITHUB_TOKEN}"` passes. `"ghp_abc123…"` does not. That is the entire rule.

Secrets are masked in all output formats, so a CI log never becomes the leak.

### R4 — the manual itself

This rule exists because we shipped the bug it catches. The first version of our own manual carried an `info` block — the shape every other API description format uses — and `python-utcp` rejected the entire document:

```
TypeError: UtcpManual.__init__() got an unexpected keyword argument 'info'
```

It had been served over HTTPS for an hour before anyone tried to register it. Every URL check passed, because the URLs were fine. The document simply was not a manual.

`UtcpManual.model_fields` is exactly `utcp_version`, `manual_version`, `tools`. Anything else fails at load time — which is the worst time, because the build is already green and the agent is already running.

| Check | What it catches | Severity |
|---|---|---|
| `R4/unknown-field` | any top-level field UtcpManual does not define — `info`, `metadata`, `description`, `name`, `version`, `auth` | error |
| `R4/no-tools` | `tools` missing entirely | error |
| `R4/tool-no-name` | a tool with no name, so no client can address it | error |
| `R4/tool-no-template` | a tool with no `tool_call_template`, so it cannot be invoked | error |
| `R4/template-no-type` | a template with no `call_template_type`, so the client cannot pick a transport | error |
| `R4/tool-not-object` | a string or array sitting in `tools[]` | error |
| `R4/empty-tools` | `tools: []` — loads fine, offers nothing | warning |
| `R4/duplicate-tool-name` | two tools sharing one name; one of them is unreachable | warning |
| `R4/tool-no-description` | a tool an agent will never choose, because nothing describes it | warning |
| `R4/unknown-version` | a `utcp_version` this tool does not recognise | warning |

R4 runs once per document rather than once per target, because these are properties of the file, not of a URL.

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

| | Runtime guard (`utcp-http` / `utcp`) | `utcp-lint` |
|---|---|---|
| When | at call time | at commit time |
| Sees | scheme, redirect chain, declared loopback | scheme, address, hostname shape, credential shape, manual schema |
| On failure | the call is rejected | the build is rejected |
| Catches metadata over HTTPS | no | yes |
| Catches a literal key in a header | no | yes |
| Catches an `info` block that makes the manual unloadable | no — it fails with a `TypeError` | yes, as a lint error |
| Catches `169.254.169.254.nip.io` | only if `--dns` resolves it | yes, by decoding the hostname |

Use both. The runtime guard is the last line; this is the first.

## Limitations

- **JSON only.** YAML MCP configs are not parsed yet.
- **DNS checks are opt-in** (`--dns`), because a linter that silently makes network calls in CI is a bad citizen. Without it, a hostname that resolves to a private address is not caught — unless it is a wildcard-DNS name, which R2 decodes without touching the network.
- **No taint tracking.** `R1/dynamic-host` warns that the destination is argument-controlled; it cannot tell you whether that argument is attacker-controlled.
- **`env` blocks in MCP stdio configs are not scanned.** A literal token in `mcpServers.x.env` is invisible to this version.
- **R2 is a blocklist, not a proof.** It knows the shorteners, tunnels and wildcard-DNS providers that exist today. A domain registered tomorrow to serve the same purpose is not on the list. The rule catches the shapes that appear in real manuals; it does not make a manual trustworthy.
- **R4 checks structure, not semantics.** It knows `UtcpManual` has three fields. It does not validate `inputs` against JSON Schema, so a tool with a malformed parameter schema still passes.
- Rules are deliberately few. A security tool that cries wolf gets switched off in a week.

## License

Apache-2.0.
