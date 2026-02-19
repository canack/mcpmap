use crate::cli::OutputFormat;
use crate::mcp::active::ActiveProbeResult;
use crate::mcp::prober::McpProbeResult;
use crate::mcp::protocol::{ConfidenceLevel, RiskLevel, TransportType};
use crate::scanner::engine::ScanResult;
use colored::Colorize;
use serde::Serialize;
use std::time::Duration;

// =============================================================================
// Public API
// =============================================================================

/// Print results in the specified format
pub fn print_results(
    results: &[ScanResult],
    total_scanned: usize,
    scan_duration: Option<Duration>,
    format: OutputFormat,
) {
    match format {
        OutputFormat::Normal => print_table_results(results, total_scanned, scan_duration),
        OutputFormat::Wide => print_wide_results(results, total_scanned, scan_duration),
    }
}

#[derive(Debug, Serialize)]
pub struct ScanSummary {
    pub total_scanned: usize,
    pub mcp_servers_found: usize,
    pub confirmed: usize,
    pub likely: usize,
    pub auth_required: usize,
}

// =============================================================================
// JSON Output Types
// =============================================================================

#[derive(Serialize)]
struct JsonMeta {
    tool: &'static str,
    version: &'static str,
    timestamp: String,
    args: String,
    duration_ms: u64,
}

#[derive(Serialize)]
struct JsonConfidence {
    score: u8,
    level: String,
    evidence: Vec<String>,
}

#[derive(Serialize)]
struct JsonServer {
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    protocol_version: Option<String>,
    capabilities: Vec<String>,
    transport: String,
}

#[derive(Serialize)]
struct JsonFinding {
    id: String,
    title: String,
    severity: String,
    description: String,
}

#[derive(Serialize)]
struct JsonSecurity {
    auth_required: bool,
    tls: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    origin_validated: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    session_id: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    findings: Vec<JsonFinding>,
    #[serde(skip_serializing_if = "Option::is_none")]
    active_probe: Option<ActiveProbeResult>,
}

#[derive(Serialize)]
struct JsonTool {
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,
    risk: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    warnings: Vec<String>,
}

#[derive(Serialize)]
struct JsonResult {
    host: String,
    port: u16,
    url: String,
    timestamp: String,
    confidence: JsonConfidence,
    server: JsonServer,
    security: JsonSecurity,
    #[serde(skip_serializing_if = "Option::is_none")]
    tools: Option<Vec<JsonTool>>,
    response_time_ms: u64,
}

#[derive(Serialize)]
struct JsonSummary {
    total_scanned: usize,
    servers_found: usize,
    confirmed: usize,
    likely: usize,
    auth_required: usize,
}

#[derive(Serialize)]
struct JsonOutput {
    meta: JsonMeta,
    results: Vec<JsonResult>,
    summary: JsonSummary,
}

pub fn print_table_results(
    results: &[ScanResult],
    total_scanned: usize,
    scan_duration: Option<Duration>,
) {
    let summary = calculate_summary(results, total_scanned);

    // Filter to MCP results only
    let mcp_results: Vec<_> = results
        .iter()
        .filter(|r| {
            r.mcp_result
                .as_ref()
                .is_some_and(|m| m.is_mcp_server() || m.confidence.score > 0)
        })
        .collect();

    print_header(total_scanned, scan_duration);

    if mcp_results.is_empty() {
        println!("{}", "No MCP servers detected.".dimmed());
    } else {
        for r in &mcp_results {
            print_result(r);
        }
    }

    print_footer(&summary);
}

fn print_header(total_scanned: usize, scan_duration: Option<Duration>) {
    let duration_str = scan_duration
        .map(|d| format!(" in {:.2}s", d.as_secs_f64()))
        .unwrap_or_default();

    let target_label = if total_scanned == 1 {
        "target"
    } else {
        "targets"
    };
    println!(
        "{}",
        format!("{} {} scanned{}", total_scanned, target_label, duration_str).bold()
    );
    println!("{}", "\u{2500}".repeat(60).dimmed());
}

fn print_result(r: &ScanResult) {
    let mcp = r.mcp_result.as_ref().unwrap();

    // Host:Port line
    let addr = format!("{}:{}", r.target.ip, r.target.port);
    let confidence_badge = format_confidence_badge(&mcp.confidence.level, mcp.confidence.score);
    let risk_badge = format_risk_badge(&mcp.risk_level);

    println!(
        "{} {} {}",
        addr.bold().white(),
        confidence_badge,
        risk_badge
    );

    // Server info line
    if let Some(info) = &mcp.server_info {
        let name = info.name.as_deref().unwrap_or("unknown");
        let version = info.version.as_deref().unwrap_or("-");
        let proto = info
            .protocol_version
            .as_deref()
            .map(|v| format!(" (MCP {})", v))
            .unwrap_or_default();

        println!(
            "  {} {}/{}{}",
            "Server:".dimmed(),
            name.cyan(),
            version,
            proto.dimmed()
        );

        if !info.capabilities.is_empty() {
            println!(
                "  {} {}",
                "Capabilities:".dimmed(),
                info.capabilities.join(", ")
            );
        }
    }

    // Transport & endpoint with TLS indicator
    let transport = mcp.transport_type.to_string();
    let tls_status = if mcp.tls_enabled {
        "(TLS)".green().to_string()
    } else {
        "(no TLS)".red().to_string()
    };

    if let Some(endpoint) = mcp.endpoint() {
        println!(
            "  {} {} @ {} {}",
            "Transport:".dimmed(),
            transport,
            endpoint.dimmed(),
            tls_status
        );
    } else {
        println!("  {} {} {}", "Transport:".dimmed(), transport, tls_status);
    }

    // Auth indicator
    if mcp.auth_required {
        println!("  {} {}", "Auth:".dimmed(), "Required".yellow());
    }

    // Origin validation (DNS rebinding protection)
    if let Some(origin_validated) = mcp.origin_validation {
        if origin_validated {
            println!("  {} {}", "Origin:".dimmed(), "Validated (secure)".green());
        } else {
            println!(
                "  {} {}",
                "Origin:".dimmed(),
                "NOT VALIDATED (DNS rebinding risk)".red().bold()
            );
        }
    }

    // Security warnings (prompt injection, weak session, etc.)
    if !mcp.security_warnings.is_empty() {
        println!(
            "  {} {}",
            "Security:".dimmed(),
            format!("{} warning(s)", mcp.security_warnings.len()).red()
        );
        for warning in mcp.security_warnings.iter().take(3) {
            println!("    {} {}", "⚠".yellow(), warning);
        }
        if mcp.security_warnings.len() > 3 {
            println!(
                "    {} (+{} more)",
                "...".dimmed(),
                mcp.security_warnings.len() - 3
            );
        }
    }

    // Tools (if enumerated)
    if let Some(tools) = &mcp.tools {
        if !tools.is_empty() {
            let tool_list: Vec<String> = tools
                .iter()
                .take(5)
                .map(|t| {
                    let risk_indicator = match t.risk_level {
                        RiskLevel::Critical => "!!".red().to_string(),
                        RiskLevel::High => "!".red().to_string(),
                        RiskLevel::Medium => "*".yellow().to_string(),
                        _ => "".to_string(),
                    };
                    format!("{}{}", t.name, risk_indicator)
                })
                .collect();

            let suffix = if tools.len() > 5 {
                format!(" (+{})", tools.len() - 5)
            } else {
                String::new()
            };

            println!(
                "  {} {}{}",
                "Tools:".dimmed(),
                tool_list.join(", "),
                suffix.dimmed()
            );
        }
    }

    // Active probe results
    if let Some(active) = &mcp.active_probe {
        if !active.findings.is_empty() {
            println!(
                "  {} Tier {} executed, {} finding(s)",
                "Active Probe:".dimmed(),
                active.tier_executed,
                active.findings.len().to_string().red()
            );
            for finding in active.findings.iter().take(5) {
                use crate::mcp::active::Severity;
                let severity_colored = match finding.severity {
                    Severity::Critical => format!("[{}]", finding.severity)
                        .on_red()
                        .white()
                        .bold()
                        .to_string(),
                    Severity::High => format!("[{}]", finding.severity).red().bold().to_string(),
                    Severity::Medium => format!("[{}]", finding.severity).yellow().to_string(),
                    _ => format!("[{}]", finding.severity).dimmed().to_string(),
                };
                println!(
                    "    {} {} {}",
                    finding.id.bold(),
                    severity_colored,
                    finding.description
                );
            }
            if active.findings.len() > 5 {
                println!(
                    "    {} (+{} more)",
                    "...".dimmed(),
                    active.findings.len() - 5
                );
            }
        }
    }

    // Evidence (abbreviated)
    if !mcp.confidence.evidence.is_empty() {
        let evidence: Vec<_> = mcp.confidence.evidence.iter().take(2).cloned().collect();
        println!(
            "  {} {}",
            "Evidence:".dimmed(),
            evidence.join("; ").dimmed()
        );
    }

    println!();
}

fn format_confidence_badge(level: &ConfidenceLevel, score: u8) -> String {
    match level {
        ConfidenceLevel::Confirmed => format!("[CONFIRMED {}%]", score).green().bold().to_string(),
        ConfidenceLevel::Likely => format!("[LIKELY {}%]", score).yellow().to_string(),
        ConfidenceLevel::Unlikely => format!("[UNLIKELY {}%]", score).dimmed().to_string(),
    }
}

fn format_risk_badge(level: &RiskLevel) -> String {
    match level {
        RiskLevel::Critical => "[CRITICAL]".on_red().white().bold().to_string(),
        RiskLevel::High => "[HIGH]".red().bold().to_string(),
        RiskLevel::Medium => "[MEDIUM]".yellow().to_string(),
        RiskLevel::Low => "[LOW]".dimmed().to_string(),
        RiskLevel::Info => "".to_string(),
    }
}

fn print_footer(summary: &ScanSummary) {
    println!("{}", "─".repeat(60).dimmed());

    if summary.mcp_servers_found == 0 {
        println!("{}", "No MCP servers found".dimmed());
        return;
    }

    let mut parts = vec![format!(
        "{} MCP server{}",
        summary.mcp_servers_found,
        if summary.mcp_servers_found == 1 {
            ""
        } else {
            "s"
        }
    )];

    if summary.confirmed > 0 {
        parts.push(format!(
            "{} confirmed",
            summary.confirmed.to_string().green()
        ));
    }

    if summary.likely > 0 {
        parts.push(format!("{} likely", summary.likely.to_string().yellow()));
    }

    if summary.auth_required > 0 {
        parts.push(format!("{} auth-protected", summary.auth_required));
    }

    println!("{}", parts.join(" | "));
}

// =============================================================================
// Wide Table Format (header/footer to stderr, data to stdout for grep/awk)
// =============================================================================

/// Detect terminal width from stderr (which stays connected to the terminal
/// even when stdout is piped). Falls back to 120.
fn terminal_width() -> usize {
    let (_, width) = console::Term::stderr().size();
    if width > 0 { width as usize } else { 120 }
}

/// Format server capabilities as count (e.g., "4" for tools+resources+prompts+logging)
fn format_capabilities(mcp: &McpProbeResult) -> String {
    let Some(info) = &mcp.server_info else {
        return "-".to_string();
    };
    if info.capabilities.is_empty() {
        return "0".to_string();
    }
    info.capabilities.len().to_string()
}

fn print_wide_results(
    results: &[ScanResult],
    total_scanned: usize,
    scan_duration: Option<Duration>,
) {
    let summary = calculate_summary(results, total_scanned);

    let mcp_results: Vec<_> = results
        .iter()
        .filter(|r| {
            r.mcp_result
                .as_ref()
                .is_some_and(|m| m.is_mcp_server() || m.confidence.score > 0)
        })
        .collect();

    // Dynamic SERVER column: fill remaining space after fixed columns
    // Fixed: HOST(17) PORT(5) CONF(4) PROTO(10) TRANS(5) TLS(3) ORG(3) AUTH(4) CAPS(4) WARN(4)
    // Separators: 10 gaps × 2 chars = 20
    let tw = terminal_width();
    let server_width = tw.saturating_sub(79).max(15);

    if mcp_results.is_empty() {
        eprintln!("{}", "No MCP servers detected.".dimmed());
        return;
    }

    // Column headers
    eprintln!(
        "{}",
        format!(
            "{:<17} {:>5}  {:>4}  {:<sw$}  {:<10}  {:<5}  {:>3}  {:>3}  {:>4}  {:>4}  {:>4}",
            "HOST",
            "PORT",
            "CONF",
            "SERVER",
            "PROTO",
            "TRANS",
            "TLS",
            "ORG",
            "AUTH",
            "CAPS",
            "WARN",
            sw = server_width,
        )
        .dimmed()
    );
    eprintln!("{}", "\u{2500}".repeat(tw).dimmed());

    for r in &mcp_results {
        print_wide_line(r, server_width);
    }

    // Footer: compact summary with scan stats
    eprintln!("{}", "\u{2500}".repeat(tw).dimmed());
    let duration_str = scan_duration
        .map(|d| format!(" in {:.2}s", d.as_secs_f64()))
        .unwrap_or_default();
    let mut parts = vec![format!("{} scanned", total_scanned)];
    parts.push(format!("{} found", summary.mcp_servers_found));
    if summary.confirmed > 0 {
        parts.push(format!("{} confirmed", summary.confirmed));
    }
    if summary.likely > 0 {
        parts.push(format!("{} likely", summary.likely));
    }
    if summary.auth_required > 0 {
        parts.push(format!("{} auth-protected", summary.auth_required));
    }
    eprintln!("{}", format!("{}{}", parts.join(", "), duration_str).bold());
}

fn print_wide_line(r: &ScanResult, server_width: usize) {
    let mcp = r.mcp_result.as_ref().unwrap();

    let host = r.target.ip.to_string();
    let port = r.target.port;

    let conf = format!("{}%", mcp.confidence.score);
    let conf_colored = match mcp.confidence.level {
        ConfidenceLevel::Confirmed => conf.green(),
        ConfidenceLevel::Likely => conf.yellow(),
        ConfidenceLevel::Unlikely => conf.dimmed(),
    };

    // Server: name/version (truncated to fit column)
    let server_str = mcp
        .server_info
        .as_ref()
        .map(|i| {
            let name = i.name.as_deref().unwrap_or("unknown");
            match i.version.as_deref() {
                Some(v) => format!("{}/{}", name, v),
                None => name.to_string(),
            }
        })
        .unwrap_or_else(|| "unknown".to_string());
    let server_display = if server_str.chars().count() > server_width {
        let truncated: String = server_str
            .chars()
            .take(server_width.saturating_sub(3))
            .collect();
        format!("{}...", truncated)
    } else {
        server_str
    };

    let proto = mcp
        .server_info
        .as_ref()
        .and_then(|i| i.protocol_version.as_deref())
        .unwrap_or("-");

    let transport = match mcp.transport_type {
        TransportType::StreamableHttp => "HTTP",
        TransportType::Sse => "SSE",
        TransportType::Unknown => "?",
    };

    let tls = if mcp.tls_enabled {
        "Y".green()
    } else {
        "N".red()
    };

    let origin = match mcp.origin_validation {
        Some(true) => "Y".green(),
        Some(false) => "N".red(),
        None => "?".dimmed(),
    };

    let auth = if mcp.auth_required {
        "Y".yellow()
    } else {
        "N".dimmed()
    };

    let caps = format_capabilities(mcp);

    let warn_count = mcp.security_warnings.len();
    let warn = if warn_count > 0 {
        warn_count.to_string().red().to_string()
    } else {
        "0".dimmed().to_string()
    };

    println!(
        "{:<17} {:>5}  {:>4}  {:<sw$}  {:<10}  {:<5}  {:>3}  {:>3}  {:>4}  {:>4}  {:>4}",
        host,
        port,
        conf_colored,
        server_display.cyan(),
        proto,
        transport,
        tls,
        origin,
        auth,
        caps,
        warn,
        sw = server_width,
    );
}

pub fn print_json_results(
    results: &[ScanResult],
    total_scanned: usize,
    scan_duration: Duration,
    args: &str,
) {
    let scan_timestamp = now_utc_iso8601();
    let summary = calculate_summary(results, total_scanned);

    let json_results: Vec<JsonResult> = results
        .iter()
        .filter_map(|r| {
            let mcp = r.mcp_result.as_ref()?;
            if !mcp.is_mcp_server() && mcp.confidence.score == 0 {
                return None;
            }

            let scheme = if mcp.tls_enabled { "https" } else { "http" };
            let endpoint = mcp.endpoint().unwrap_or("/");
            let url = format!("{}://{}:{}{}", scheme, r.target.ip, r.target.port, endpoint);

            let (name, version, protocol_version, capabilities) =
                if let Some(info) = &mcp.server_info {
                    (
                        info.name.clone(),
                        info.version.clone(),
                        info.protocol_version.clone(),
                        info.capabilities.clone(),
                    )
                } else {
                    (None, None, None, Vec::new())
                };

            let transport = match mcp.transport_type {
                TransportType::StreamableHttp => "streamable-http",
                TransportType::Sse => "sse",
                TransportType::Unknown => "unknown",
            };

            let findings = build_findings(mcp);

            let tools = mcp.tools.as_ref().map(|t| {
                t.iter()
                    .map(|tool| JsonTool {
                        name: tool.name.clone(),
                        description: tool.description.clone(),
                        risk: tool.risk_level.to_string().to_lowercase(),
                        warnings: tool.security_warnings.clone(),
                    })
                    .collect()
            });

            Some(JsonResult {
                host: r.target.ip.to_string(),
                port: r.target.port,
                url,
                timestamp: scan_timestamp.clone(),
                confidence: JsonConfidence {
                    score: mcp.confidence.score,
                    level: mcp.confidence.level.to_string().to_lowercase(),
                    evidence: mcp.confidence.evidence.clone(),
                },
                server: JsonServer {
                    name,
                    version,
                    protocol_version,
                    capabilities,
                    transport: transport.to_string(),
                },
                security: JsonSecurity {
                    auth_required: mcp.auth_required,
                    tls: mcp.tls_enabled,
                    origin_validated: mcp.origin_validation,
                    session_id: mcp.session_id.clone(),
                    findings,
                    active_probe: mcp.active_probe.clone(),
                },
                tools,
                response_time_ms: mcp.response_time_ms,
            })
        })
        .collect();

    let output = JsonOutput {
        meta: JsonMeta {
            tool: "mcpmap",
            version: env!("CARGO_PKG_VERSION"),
            timestamp: scan_timestamp,
            args: args.to_string(),
            duration_ms: scan_duration.as_millis() as u64,
        },
        results: json_results,
        summary: JsonSummary {
            total_scanned: summary.total_scanned,
            servers_found: summary.mcp_servers_found,
            confirmed: summary.confirmed,
            likely: summary.likely,
            auth_required: summary.auth_required,
        },
    };

    match serde_json::to_string_pretty(&output) {
        Ok(json) => println!("{}", json),
        Err(e) => eprintln!("Failed to serialize results: {}", e),
    }
}

fn build_findings(mcp: &McpProbeResult) -> Vec<JsonFinding> {
    let mut findings = Vec::new();

    // MCP-001: DNS rebinding (missing origin validation)
    if mcp.origin_validation == Some(false) {
        findings.push(JsonFinding {
            id: "MCP-001".to_string(),
            title: "DNS Rebinding".to_string(),
            severity: "high".to_string(),
            description:
                "Server does not validate Origin header. Vulnerable to DNS rebinding attacks."
                    .to_string(),
        });
    }

    // MCP-002: Missing authentication
    if !mcp.auth_required {
        findings.push(JsonFinding {
            id: "MCP-002".to_string(),
            title: "Missing Authentication".to_string(),
            severity: "high".to_string(),
            description: "Server accepts unauthenticated connections.".to_string(),
        });
    }

    // MCP-003: Insecure transport
    if !mcp.tls_enabled {
        findings.push(JsonFinding {
            id: "MCP-003".to_string(),
            title: "Insecure Transport".to_string(),
            severity: "medium".to_string(),
            description: "Connection is not encrypted (HTTP). Traffic is interceptable."
                .to_string(),
        });
    }

    // MCP-004: Weak session ID
    for warning in &mcp.security_warnings {
        let wl = warning.to_lowercase();
        if wl.contains("session") || wl.contains("entropy") {
            findings.push(JsonFinding {
                id: "MCP-004".to_string(),
                title: "Weak Session ID".to_string(),
                severity: "high".to_string(),
                description: warning.clone(),
            });
            break;
        }
    }

    // MCP-005: Dangerous tool exposure
    if let Some(tools) = &mcp.tools {
        let critical_tools: Vec<&str> = tools
            .iter()
            .filter(|t| matches!(t.risk_level, RiskLevel::Critical))
            .map(|t| t.name.as_str())
            .collect();
        if !critical_tools.is_empty() {
            findings.push(JsonFinding {
                id: "MCP-005".to_string(),
                title: "Dangerous Tool Exposure".to_string(),
                severity: "critical".to_string(),
                description: format!("Critical-risk tools exposed: {}", critical_tools.join(", ")),
            });
        }
    }

    // MCP-006: Prompt injection in tool descriptions
    if let Some(tools) = &mcp.tools {
        let injection_tools: Vec<&str> = tools
            .iter()
            .filter(|t| !t.security_warnings.is_empty())
            .map(|t| t.name.as_str())
            .collect();
        if !injection_tools.is_empty() {
            findings.push(JsonFinding {
                id: "MCP-006".to_string(),
                title: "Prompt Injection".to_string(),
                severity: "medium".to_string(),
                description: format!(
                    "Suspicious patterns in tool descriptions: {}",
                    injection_tools.join(", ")
                ),
            });
        }
    }

    // MCP-008: Schema poisoning
    if let Some(tools) = &mcp.tools {
        let schema_tools: Vec<&str> = tools
            .iter()
            .filter(|t| !t.schema_warnings.is_empty())
            .map(|t| t.name.as_str())
            .collect();
        if !schema_tools.is_empty() {
            findings.push(JsonFinding {
                id: "MCP-008".to_string(),
                title: "Schema Poisoning".to_string(),
                severity: "high".to_string(),
                description: format!(
                    "Suspicious parameter definitions in tools: {}",
                    schema_tools.join(", ")
                ),
            });
        }
    }

    // MCP-007 through MCP-015 from active probe results
    if let Some(active) = &mcp.active_probe {
        for finding in &active.findings {
            // Avoid duplicating MCP-008 (already handled above from schema_warnings)
            if finding.id == "MCP-008" {
                continue;
            }
            findings.push(JsonFinding {
                id: finding.id.clone(),
                title: finding.title.clone(),
                severity: finding.severity.to_string().to_lowercase(),
                description: finding.description.clone(),
            });
        }
    }

    findings
}

fn now_utc_iso8601() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    // Howard Hinnant's civil_from_days algorithm
    let days = secs.div_euclid(86400);
    let time_secs = secs.rem_euclid(86400);
    let h = time_secs / 3600;
    let m = (time_secs % 3600) / 60;
    let s = time_secs % 60;

    let z = days + 719468;
    let era = z.div_euclid(146097);
    let doe = z.rem_euclid(146097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if month <= 2 { y + 1 } else { y };

    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        year, month, d, h, m, s
    )
}

fn calculate_summary(results: &[ScanResult], total_scanned: usize) -> ScanSummary {
    let mcp_servers: Vec<_> = results
        .iter()
        .filter(|r| {
            r.mcp_result
                .as_ref()
                .is_some_and(|m| m.is_mcp_server() || m.confidence.score > 0)
        })
        .collect();

    let confirmed = mcp_servers
        .iter()
        .filter(|r| {
            r.mcp_result
                .as_ref()
                .is_some_and(|m| m.confidence.level == ConfidenceLevel::Confirmed)
        })
        .count();

    let likely = mcp_servers
        .iter()
        .filter(|r| {
            r.mcp_result
                .as_ref()
                .is_some_and(|m| m.confidence.level == ConfidenceLevel::Likely)
        })
        .count();

    let auth_required = mcp_servers
        .iter()
        .filter(|r| r.mcp_result.as_ref().is_some_and(|m| m.auth_required))
        .count();

    ScanSummary {
        total_scanned,
        mcp_servers_found: mcp_servers.len(),
        confirmed,
        likely,
        auth_required,
    }
}
