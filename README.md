# mcpmap

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.85%2B-orange.svg?logo=rust)](https://www.rust-lang.org)
[![CI](https://github.com/canack/mcpmap/actions/workflows/ci.yml/badge.svg)](https://github.com/canack/mcpmap/actions)

Network scanner that discovers and security-audits [MCP](https://modelcontextprotocol.io) servers across IP ranges. Like nmap, but for Model Context Protocol.

## Install

```bash
cargo install mcpmap
```

Requires Rust 1.85+. Pre-built binaries available on [GitHub Releases](https://github.com/canack/mcpmap/releases).

## Quick Start

```bash
# Discover MCP servers on a network
mcpmap 192.168.1.0/24

# List tools and classify risk
mcpmap 192.168.1.0/24 --enumerate

# Active security audit (metadata-only, safe)
mcpmap 192.168.1.0/24 --enumerate --active

# Active audit with tool probing (calls LOW-risk tools)
mcpmap 192.168.1.0/24 --enumerate --active --probe-tools --i-accept-risk

# Save tool hashes as baseline, verify later
mcpmap 192.168.1.0/24 --enumerate --active --pin baseline.json
mcpmap 192.168.1.0/24 --enumerate --active --verify baseline.json

# JSON output for CI/CD pipelines
mcpmap 192.168.1.0/24 --enumerate --active --json
```

## What It Does

```
Target IPs ──▶ Port Scan ──▶ HTTP Probe ──▶ MCP Handshake ──▶ Security Checks
                                                │
                                                ▼
                                          Tool Enumeration (--enumerate)
                                                │
                                                ▼
                                          Active Probing (--active)
                                           ├─ Tier 1: metadata analysis
                                           ├─ Tier 2: LOW-risk tool calls
                                           └─ Tier 3: MEDIUM-risk tool calls
```

**Passive pipeline (default):**
1. **Port scan** — checks known MCP ports (or full range with `--mode full`)
2. **HTTP heuristic** — filters out non-HTTP services
3. **MCP handshake** — sends JSON-RPC `initialize` request, validates response
4. **Security checks** — origin validation, auth detection, session analysis
5. **Tool enumeration** — lists exposed tools with risk classification (`--enumerate`)

**Active probing (`--active`):**
6. **Schema analysis** — detects poisoned parameter names and enum values
7. **Resource scanning** — reads MCP resources, checks for injection
8. **Tool squatting** — compares tool names against known MCP tools
9. **Temporal stability** — detects time-based tool definition changes
10. **Exfil chain analysis** — identifies tool-chaining exfiltration paths
11. **Tool output analysis** — calls safe tools, scans output for injection (Tier 2)
12. **Rug-pull detection** — calls tools, re-checks definitions for mutation (Tier 2)
13. **Denial-of-wallet** — measures response sizes and recursive patterns (Tier 2)

## Active Probing

Active probing is mcpmap's key differentiator. No other MCP scanner does behavioral testing.

### Tier System

```
╔══════════════════════════════════════════════════════════════════╗
║  Tier 1: SAFE (--active)                         Risk: NONE    ║
║  Only MCP metadata operations: tools/list, resources/list,     ║
║  resources/read. No tool invocations. No side effects.         ║
╠══════════════════════════════════════════════════════════════════╣
║  Tier 2: CONTROLLED (--active --probe-tools --i-accept-risk)   ║
║  Calls LOW-risk tools (read, get, list, fetch, search, view)   ║
║  with benign test inputs. Max 3 calls/tool, 50 calls/server.   ║
╠══════════════════════════════════════════════════════════════════╣
║  Tier 3: AGGRESSIVE (--active --probe-tools --probe-medium     ║
║                       --i-accept-risk)                         ║
║  Also calls MEDIUM-risk tools. Pentest scenarios only.         ║
╚══════════════════════════════════════════════════════════════════╝

  CRITICAL/HIGH risk tools (exec, shell, write, delete) are NEVER called.
  No flag overrides this. Hardcoded safety invariant.
```

### Safety Guarantees

| Guarantee | Enforcement |
|-----------|-------------|
| CRITICAL/HIGH tools never called | Hardcoded, no flag overrides |
| Max 3 calls per tool | Counter-enforced |
| Max 50 calls per server | Counter-enforced |
| 5-second timeout per tool call | `tokio::time::timeout` |
| 100KB response truncation | Chunk-based streaming read |
| 120-second overall probe timeout | Wraps entire active probe |
| Explicit consent for Tier 2+ | `--i-accept-risk` required |
| Dry-run preview | `--dry-run` shows plan without executing |

### Dry-Run Mode

Preview what active probing would do before executing:

```bash
mcpmap 192.168.1.10 --enumerate --active --probe-tools --i-accept-risk --dry-run
```

```
[DRY RUN] Active probe plan for 192.168.1.10:8080:

  Tier 1 (Safe — metadata only):
    ✓ tools/list hash baseline
    ✓ resources/list → resources/read scan
    ✓ Schema analysis for 6 tools
    ✓ Tool squatting check
    ✓ Temporal stability check (5s delay)
    ✓ Exfiltration chain analysis

  Tier 2 (Controlled — LOW-risk tool calls):
    ✓ Call get_weather("test") — LOW risk
    ✓ Call search_docs("test") — LOW risk
    ✗ SKIP write_file — HIGH risk (never callable)
    ✗ SKIP execute_command — CRITICAL risk (never callable)
    ✓ Re-check tools/list for rug-pull detection
    ✓ Analyze outputs for injection patterns
```

## Tool Integrity Pinning

Save a cryptographic baseline of all tool definitions and resource content, then verify nothing has changed:

```bash
# Create baseline
mcpmap 192.168.1.0/24 --enumerate --active --pin baseline.json

# Later: verify against baseline (exits code 2 if diffs found)
mcpmap 192.168.1.0/24 --enumerate --active --verify baseline.json
```

Pin files contain SHA-256 hashes of tool descriptions, input schemas, and resource content. Use in CI/CD to detect rug-pull attacks between deployments.

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

## Security Detections

mcpmap detects 15 vulnerability classes across passive and active scanning:

### Passive (always active)

| ID | Vulnerability | Severity | Flag |
|----|---|---|---|
| MCP-001 | DNS rebinding (missing Origin validation) | High | auto |
| MCP-002 | Missing authentication | High | auto |
| MCP-003 | Insecure transport (HTTP) | Medium | auto |
| MCP-004 | Predictable session IDs | High | auto |
| MCP-005 | Dangerous tool exposure | Critical | `--enumerate` |
| MCP-006 | Prompt injection in tool descriptions | Medium | `--enumerate` |

### Active Tier 1 (metadata-only, `--active`)

| ID | Vulnerability | Severity | Flag |
|----|---|---|---|
| MCP-007 | Resource content injection | Medium | `--active` |
| MCP-008 | Schema poisoning (malicious param names) | High | `--active` |
| MCP-009 | Tool name squatting | High | `--active` |
| MCP-013 | Exfiltration chain risk | High | `--active` |
| MCP-014 | Cross-server manipulation | Medium | `--active` |

### Active Tier 2 (tool probing, `--active --probe-tools`)

| ID | Vulnerability | Severity | Flag |
|----|---|---|---|
| MCP-010 | Rug-pull (tool definition mutation) | Critical | `--probe-tools` |
| MCP-011 | Response injection (ATPA) | High | `--probe-tools` |
| MCP-012 | Denial of wallet (massive output / recursion) | Medium-High | `--probe-tools` |

### Pin Verification (`--verify`)

| ID | Vulnerability | Severity | Flag |
|----|---|---|---|
| MCP-015 | Pin verification failed (definitions changed) | Critical | `--verify` |

See [SECURITY.md](SECURITY.md) for detailed descriptions and mitigations.

## Options

### Scanning

| Flag | Description | Default |
|---|---|---|
| `-m, --mode` | `fast`, `full`, `stealth` | `fast` |
| `-p, --ports` | Port range (`80,443` or `1-1000`) | Known MCP ports |
| `-t, --threads` | Concurrent threads | `50` |
| `--timeout` | Connection timeout (seconds) | `5` |
| `--rate-limit` | Max requests/second (0 = unlimited) | `0` |
| `--deep-probe` | Try additional endpoints (`/sse`, `/api/mcp`) | off |
| `--scheme` | `http`, `https`, `both` | `both` |
| `--insecure` | Accept invalid TLS certificates | off |
| `--max-targets` | Max IP:port combinations | `1000000` |

### Enumeration & Active Probing

| Flag | Description | Default |
|---|---|---|
| `--enumerate` | List tools on confirmed servers | off |
| `--active` | Enable active probing (Tier 1, requires `--enumerate`) | off |
| `--probe-tools` | Enable Tier 2: call LOW-risk tools (requires `--i-accept-risk`) | off |
| `--probe-medium` | Enable Tier 3: also call MEDIUM-risk tools | off |
| `--i-accept-risk` | Explicit consent for tool invocation | off |
| `--dry-run` | Show probe plan without executing | off |
| `--pin FILE` | Save tool/resource hashes to pin file | - |
| `--verify FILE` | Verify against previously saved pin file | - |

### Output

| Flag | Description | Default |
|---|---|---|
| `--json` | JSON output | off |
| `-W, --wide` | Wide table format (grep-friendly) | off |
| `--min-confidence` | Minimum confidence score (0-100) | `0` |
| `--show-all` | Include low-confidence results | off |
| `-q, --quiet` | Suppress progress output | off |
| `-v` | Verbose (`-v`, `-vv`, `-vvv`) | off |

## Default Ports (Fast Mode)

`3000-3003, 4000-4001, 5000-5001, 8000-8001, 8080-8081, 8888, 9000-9001`

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Scan completed successfully |
| `1` | Error (invalid target, network failure, etc.) |
| `2` | Pin verification failed (diffs detected with `--verify`) |

## License

[MIT](LICENSE)
