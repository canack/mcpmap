# mcpmap

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.85%2B-orange.svg?logo=rust)](https://www.rust-lang.org)
[![CI](https://github.com/canack/mcpmap/actions/workflows/ci.yml/badge.svg)](https://github.com/canack/mcpmap/actions)

Network scanner that discovers and security-audits [MCP](https://modelcontextprotocol.io) servers across IP ranges. Like nmap, but for Model Context Protocol.

## Install

```bash
cargo install mcpmap
```

Requires Rust 1.85+. Pre-built binaries on [GitHub Releases](https://github.com/canack/mcpmap/releases).

## Usage

```bash
mcpmap 192.168.1.0/24                          # discover MCP servers
mcpmap 192.168.1.0/24 --enumerate              # list tools + risk levels
mcpmap 192.168.1.0/24 --enumerate --active     # active security audit (safe, metadata-only)
mcpmap 192.168.1.0/24 --enumerate --active \
  --probe-tools --i-accept-risk                # call LOW-risk tools
mcpmap 192.168.1.0/24 --enumerate --active \
  --pin baseline.json                          # save tool hashes
mcpmap 192.168.1.0/24 --enumerate --active \
  --verify baseline.json                       # verify against baseline
mcpmap 192.168.1.0/24 --enumerate --json       # JSON output for CI/CD
```

## How It Works

```
Targets ──▶ Port Scan ──▶ HTTP Probe ──▶ MCP Handshake ──▶ Security Checks
                                              │
                                     --enumerate: Tool Enumeration
                                              │
                                        --active: Behavioral Probing
```

**Passive (default):** Port scan → HTTP heuristic → JSON-RPC `initialize` handshake → origin/auth/session validation → tool enumeration with risk classification.

**Active (`--active`):** Schema poisoning, resource injection, tool squatting, temporal rug-pull, exfiltration chains, cross-server manipulation, response injection, denial-of-wallet.

## Active Probing Tiers

| Tier | Flag | What it does |
|------|------|-------------|
| 1 — Safe | `--active` | Metadata-only: tools/list, resources/list, schema analysis. No tool calls. |
| 2 — Controlled | `+ --probe-tools --i-accept-risk` | Calls LOW-risk tools (read, get, list, search) with test inputs. |
| 3 — Aggressive | `+ --probe-medium` | Also calls MEDIUM-risk tools. Pentest only. |

**CRITICAL/HIGH risk tools are NEVER called. No flag overrides this.**

Safety limits: 3 calls/tool, 50 calls/server, 5s/call timeout, 100KB response cap, 120s total probe timeout.

## Security Detections

15 vulnerability classes across passive and active scanning:

| ID | Vulnerability | Sev. | Mode |
|----|---|---|---|
| MCP-001 | DNS rebinding (missing Origin validation) | High | Passive |
| MCP-002 | Missing authentication | High | Passive |
| MCP-003 | Insecure transport (no TLS) | Med | Passive |
| MCP-004 | Predictable session IDs | High | Passive |
| MCP-005 | Dangerous tool exposure | Crit | `--enumerate` |
| MCP-006 | Prompt injection in tool descriptions | Med | `--enumerate` |
| MCP-007 | Resource content injection | Med | `--active` |
| MCP-008 | Schema poisoning | High | `--active` |
| MCP-009 | Tool name squatting | High | `--active` |
| MCP-010 | Rug-pull (definition mutation) | Crit | `--active` |
| MCP-011 | Response injection (ATPA) | High | `--probe-tools` |
| MCP-012 | Denial of wallet | Med | `--probe-tools` |
| MCP-013 | Exfiltration chain risk | High | `--active` |
| MCP-014 | Cross-server manipulation | Med | `--active` |
| MCP-015 | Pin verification failed | Crit | `--verify` |

## Example Output

```
MCPMAP - 256 targets scanned in 3.42s
────────────────────────────────────────────────────────────
192.168.1.10:3001 [CONFIRMED 100%]
  Server: filesystem-server/1.2.0 (MCP 2025-11-25)
  Capabilities: tools, resources
  Transport: SSE @ /mcp
  Origin: NOT VALIDATED (DNS rebinding risk)
  Tools: 5 discovered [HIGH RISK]
    - read_file [Medium] - Read file contents
    - write_file [High] - Write to files
    - delete_file [Critical] - Delete files
  Active Probe: Tier 2 executed, 3 findings
    MCP-008 [HIGH] Schema poisoning: parameter 'content_include_env_vars'
    MCP-010 [CRITICAL] Rug-pull: get_weather description changed after 3 calls
    MCP-012 [MEDIUM] analyze_data returned 102KB (threshold: 50KB)

192.168.1.15:8000 [LIKELY 75%]
  Server: unknown (MCP 2024-11-05)
  Capabilities: tools
  Transport: HTTP @ /
  Auth: Required (Bearer)
────────────────────────────────────────────────────────────
2 MCP servers | 1 confirmed | 1 likely | 1 auth required
```

## Options

```
SCANNING
  -m, --mode <MODE>         fast | full | stealth              [default: fast]
  -p, --ports <PORTS>       port spec (80,443 or 1-1000)      [default: known MCP ports]
  -t, --threads <N>         concurrent threads                 [default: 50]
      --timeout <SECS>      connection timeout                 [default: 5]
      --rate-limit <N>      max req/sec (0 = unlimited)        [default: 0]
      --deep-probe          try extra endpoints (/sse, /api/mcp, etc.)
      --scheme <S>          http | https | both                [default: both]
      --insecure            accept invalid TLS certs
      --max-targets <N>     safety cap on target count         [default: 1000000]

ENUMERATION & ACTIVE
      --enumerate           list tools on confirmed servers
      --active              tier 1: metadata-only probing (requires --enumerate)
      --probe-tools         tier 2: call LOW-risk tools (requires --i-accept-risk)
      --probe-medium        tier 3: also call MEDIUM-risk tools
      --i-accept-risk       explicit consent for tool invocation
      --dry-run             show probe plan without executing
      --pin <FILE>          save SHA-256 tool/resource hashes
      --verify <FILE>       diff against saved pin file

OUTPUT
      --json                JSON output
  -W, --wide                wide table (grep-friendly)
      --min-confidence <N>  minimum confidence 0-100           [default: 0]
      --show-all            include low-confidence results
  -q, --quiet               suppress progress output
  -v                        verbose (-v, -vv, -vvv)
```

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Success |
| `1` | Error |
| `2` | Pin verification failed (`--verify`) |

## License

[MIT](LICENSE)
