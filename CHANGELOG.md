# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.1] - 2026-02-20

### Changed

- Default fast-mode ports updated to verified MCP server defaults (FastMCP, MCP Inspector, Cloudflare Workers, Azure Functions, Docker MCP Gateway, etc.)
- Multi-platform Docker image (linux/amd64 + linux/arm64)

### Added

- Install via Homebrew (`brew install canack/tap/mcpmap`)
- Install via shell one-liner
- Docker image on ghcr.io (`ghcr.io/canack/mcpmap`)
- cargo-dist release pipeline (5 platform binaries, installers, Homebrew formula)

## [0.1.0] - 2026-02-16

### Added

- Multi-stage MCP server discovery pipeline (port scan, HTTP heuristic, MCP handshake, validation, enumeration)
- Confidence-scored results (Confirmed/Likely/Unlikely) with evidence tracking
- Passive security detections: DNS rebinding (MCP-001), missing auth (MCP-002), insecure transport (MCP-003), weak session IDs (MCP-004), dangerous tools (MCP-005), prompt injection (MCP-006)
- Active behavioral probing with three tiers: safe metadata-only (Tier 1), LOW-risk tool calls (Tier 2), MEDIUM-risk tool calls (Tier 3)
- Active detections: resource injection (MCP-007), schema poisoning (MCP-008), tool squatting (MCP-009), rug-pull (MCP-010), response injection (MCP-011), denial-of-wallet (MCP-012), exfiltration chains (MCP-013), cross-server manipulation (MCP-014)
- Tool integrity pinning with SHA-256 hashes (`--pin` / `--verify`, MCP-015)
- Streamable HTTP and legacy SSE transport support
- IPv4/IPv6 and CIDR range scanning
- Concurrent scanning with configurable threads and rate limiting
- Graceful shutdown with partial result output on SIGINT
- Multiple output formats: normal table, wide (grep-friendly), JSON
- `--dry-run` mode for previewing active probe plans
- Safety controls: CRITICAL/HIGH tools never called, per-tool/per-server call limits, timeouts

[0.1.1]: https://github.com/canack/mcpmap/releases/tag/v0.1.1
[0.1.0]: https://github.com/canack/mcpmap/releases/tag/v0.1.0
