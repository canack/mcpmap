use clap::Parser;
use mcpmap::cli::{Args, parse_target};
use mcpmap::mcp::active::PinFile;
use mcpmap::output::{print_json_results, print_results};
use mcpmap::scanner::engine::{ScanConfig, ScanEngine};
use std::process;
use std::time::{Duration, Instant};
use tokio_util::sync::CancellationToken;
use tracing::Level;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() {
    let args = Args::parse();

    init_logging(args.verbose, args.quiet);

    let ips = match parse_target(&args.target) {
        Ok(ips) => ips,
        Err(e) => {
            eprintln!("Error: {}", e);
            process::exit(1);
        }
    };

    if args.threads == 0 {
        eprintln!("Error: --threads must be at least 1");
        process::exit(1);
    }

    let ports = args.get_ports();

    if ports.is_empty() {
        eprintln!("Error: No valid ports to scan");
        process::exit(1);
    }

    let total_targets = ips.len() * ports.len();

    if total_targets > args.max_targets {
        eprintln!(
            "Error: Target count ({}) exceeds limit ({}). Use --max-targets to increase.",
            total_targets, args.max_targets
        );
        process::exit(1);
    }

    if !args.quiet {
        let host_label = if ips.len() == 1 { "host" } else { "hosts" };
        let port_label = if ports.len() == 1 { "port" } else { "ports" };
        let mode_str = format!("{:?}", args.mode).to_lowercase();
        eprintln!(
            "mcpmap v{} \u{2014} {} {}, {} {}, {}",
            env!("CARGO_PKG_VERSION"),
            ips.len(),
            host_label,
            ports.len(),
            port_label,
            mode_str,
        );
    }

    if args.insecure {
        eprintln!(
            "WARNING: --insecure mode enabled. TLS certificate validation disabled. Traffic may be interceptable."
        );
    }

    if args.probe_tools && !args.i_accept_risk {
        eprintln!("WARNING: --probe-tools will invoke LOW-risk tools on target MCP servers.");
        eprintln!("This may cause side effects on the target system.");
        eprintln!("Add --i-accept-risk to confirm you understand and accept this risk.");
        process::exit(1);
    }

    if args.probe_medium && !args.quiet {
        eprintln!("WARNING: --probe-medium will invoke MEDIUM-risk tools on target MCP servers.");
        eprintln!(
            "This significantly increases the chance of side effects (file reads, network I/O, etc)."
        );
        eprintln!("Proceeding because --i-accept-risk was specified.");
    }

    let config = ScanConfig {
        mode: args.mode,
        threads: args.threads,
        timeout: Duration::from_secs(args.timeout),
        show_progress: !args.quiet && !args.json,
        rate_limit: args.rate_limit,
        enumerate: args.enumerate,
        show_all: args.show_all,
        min_confidence: args.min_confidence,
        deep_probe: args.deep_probe,
        insecure: args.insecure,
        scheme: args.scheme,
        active: args.active,
        probe_tools: args.probe_tools,
        probe_medium: args.probe_medium,
        dry_run: args.dry_run,
        pin_file: args.pin.clone(),
        verify_file: args.verify.clone(),
    };

    let cancel_token = CancellationToken::new();
    let cancel_clone = cancel_token.clone();
    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.ok();
        eprintln!("\nInterrupted. Returning partial results...");
        cancel_clone.cancel();
    });

    let engine = match ScanEngine::new(config, cancel_token) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("Error: Failed to initialize scanner: {}", e);
            process::exit(1);
        }
    };

    let start = Instant::now();
    #[allow(unused_mut)]
    let mut results = engine.scan(ips, ports).await;
    let elapsed = start.elapsed();

    // Visual break between progress bar and results
    if !args.quiet && !args.json {
        eprintln!();
    }

    // Pin file: save tool/resource hashes
    if let Some(ref pin_path) = args.pin {
        let mut pin_file = PinFile::new();
        for result in &results {
            let Some(mcp) = &result.mcp_result else {
                continue;
            };
            if let Some(active) = &mcp.active_probe {
                let key = format!("{}:{}", result.target.ip, result.target.port);
                pin_file.servers.insert(
                    key,
                    mcpmap::mcp::active::ServerPin::from_scan_result(mcp, active),
                );
            }
        }
        if let Err(e) = pin_file.save(pin_path) {
            eprintln!("Error saving pin file: {}", e);
        } else if !args.quiet {
            eprintln!("Pin file saved to {}", pin_path.display());
        }
    }

    // Pin file: verify against saved baseline
    if let Some(ref verify_path) = args.verify {
        match PinFile::load(verify_path) {
            Ok(saved) => {
                let mut current = PinFile::new();
                for result in &results {
                    let Some(mcp) = &result.mcp_result else {
                        continue;
                    };
                    if let Some(active) = &mcp.active_probe {
                        let key = format!("{}:{}", result.target.ip, result.target.port);
                        current.servers.insert(
                            key,
                            mcpmap::mcp::active::ServerPin::from_scan_result(mcp, active),
                        );
                    }
                }

                let diffs = saved.diff(&current);
                if diffs.is_empty() {
                    if !args.quiet {
                        eprintln!("Pin verification: OK (no changes detected)");
                    }
                } else {
                    eprintln!(
                        "Pin verification: FAILED ({} change(s) detected)",
                        diffs.len()
                    );
                    // Collect per-server diff descriptions for MCP-015 injection
                    let mut server_diffs: std::collections::HashMap<String, Vec<String>> =
                        std::collections::HashMap::new();
                    for diff in &diffs {
                        let (server_key, desc) = match diff {
                            mcpmap::mcp::active::PinDiff::ServerAdded(s) => {
                                eprintln!("  + Server added: {}", s);
                                (s.clone(), format!("Server added: {}", s))
                            }
                            mcpmap::mcp::active::PinDiff::ServerRemoved(s) => {
                                eprintln!("  - Server removed: {}", s);
                                (s.clone(), format!("Server removed: {}", s))
                            }
                            mcpmap::mcp::active::PinDiff::ToolAdded { server, tool } => {
                                eprintln!("  + Tool added: {} on {}", tool, server);
                                (server.clone(), format!("Tool added: {}", tool))
                            }
                            mcpmap::mcp::active::PinDiff::ToolRemoved { server, tool } => {
                                eprintln!("  - Tool removed: {} on {}", tool, server);
                                (server.clone(), format!("Tool removed: {}", tool))
                            }
                            mcpmap::mcp::active::PinDiff::ToolDescriptionChanged {
                                server,
                                tool,
                                ..
                            } => {
                                eprintln!("  ~ Tool description changed: {} on {}", tool, server);
                                (
                                    server.clone(),
                                    format!("Tool description changed: {}", tool),
                                )
                            }
                            mcpmap::mcp::active::PinDiff::ToolSchemaChanged { server, tool } => {
                                eprintln!("  ~ Tool schema changed: {} on {}", tool, server);
                                (server.clone(), format!("Tool schema changed: {}", tool))
                            }
                            mcpmap::mcp::active::PinDiff::ResourceAdded { server, uri } => {
                                eprintln!("  + Resource added: {} on {}", uri, server);
                                (server.clone(), format!("Resource added: {}", uri))
                            }
                            mcpmap::mcp::active::PinDiff::ResourceRemoved { server, uri } => {
                                eprintln!("  - Resource removed: {} on {}", uri, server);
                                (server.clone(), format!("Resource removed: {}", uri))
                            }
                            mcpmap::mcp::active::PinDiff::ResourceContentChanged {
                                server,
                                uri,
                            } => {
                                eprintln!("  ~ Resource content changed: {} on {}", uri, server);
                                (server.clone(), format!("Resource content changed: {}", uri))
                            }
                        };
                        server_diffs.entry(server_key).or_default().push(desc);
                    }

                    // M1: Inject MCP-015 findings into results for JSON/table output
                    for result in &mut results {
                        let key = format!("{}:{}", result.target.ip, result.target.port);
                        let Some(diff_evidence) = server_diffs.get(&key) else {
                            continue;
                        };
                        let Some(mcp) = &mut result.mcp_result else {
                            continue;
                        };
                        let finding = mcpmap::mcp::active::ActiveFinding {
                            id: "MCP-015".to_string(),
                            title: "Pin Verification Failed".to_string(),
                            severity: mcpmap::mcp::active::Severity::Critical,
                            description: format!(
                                "{} change(s) detected since baseline",
                                diff_evidence.len()
                            ),
                            evidence: diff_evidence.clone(),
                        };
                        mcp.security_warnings.push(format!(
                            "MCP-015 [CRITICAL] Pin verification failed: {} change(s)",
                            diff_evidence.len()
                        ));
                        if let Some(ref mut active) = mcp.active_probe {
                            active.findings.push(finding);
                        } else {
                            mcp.active_probe = Some(mcpmap::mcp::active::ActiveProbeResult {
                                tier_executed: 0,
                                findings: vec![finding],
                                tool_hashes: std::collections::HashMap::new(),
                                resource_findings: Vec::new(),
                                behavioral_changes: Vec::new(),
                                output_analysis: Vec::new(),
                            });
                        }
                    }
                    // Print output BEFORE exiting so MCP-015 findings appear
                    if args.json {
                        let args_str = std::env::args().collect::<Vec<_>>().join(" ");
                        print_json_results(&results, total_targets, elapsed, &args_str);
                    } else {
                        print_results(
                            &results,
                            total_targets,
                            Some(elapsed),
                            args.get_output_format(),
                        );
                    }
                    process::exit(2);
                }
            }
            Err(e) => {
                eprintln!("Error loading pin file: {}", e);
                process::exit(1);
            }
        }
    }

    if args.json {
        let args_str = std::env::args().collect::<Vec<_>>().join(" ");
        print_json_results(&results, total_targets, elapsed, &args_str);
    } else {
        print_results(
            &results,
            total_targets,
            Some(elapsed),
            args.get_output_format(),
        );
    }

    if results.is_empty() {
        process::exit(1);
    }
}

fn init_logging(verbose: u8, quiet: bool) {
    if quiet {
        return;
    }

    let level = match verbose {
        0 => Level::WARN,
        1 => Level::INFO,
        2 => Level::DEBUG,
        _ => Level::TRACE,
    };

    let filter = EnvFilter::from_default_env().add_directive(level.into());

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .without_time()
        .init();
}
