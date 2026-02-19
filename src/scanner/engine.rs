use crate::cli::{ScanMode, SchemeMode};
use crate::error::Result;
use crate::mcp::active::ActiveProber;
use crate::mcp::prober::{McpProbeResult, McpProber};
use crate::mcp::protocol::ConfidenceLevel;
use crate::scanner::port::{PortStatus, check_port};
use crate::scanner::target::{ScanTarget, generate_targets, shuffle_targets};
use futures::stream::{self, StreamExt};
use indicatif::{ProgressBar, ProgressStyle};
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant as StdInstant};
use tokio::sync::Semaphore;
use tokio::time::sleep;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info};

/// Configuration for the scan engine.
#[derive(Debug, Clone)]
pub struct ScanConfig {
    pub mode: ScanMode,
    pub threads: usize,
    pub timeout: Duration,
    pub show_progress: bool,
    /// Rate limit in requests per second (0 = unlimited)
    pub rate_limit: u32,
    /// Enumerate tools on confirmed MCP servers
    pub enumerate: bool,
    /// Show all results including unlikely ones
    pub show_all: bool,
    /// Minimum confidence score to include in results
    pub min_confidence: u8,
    /// Deep probe: try additional endpoints (/sse, /api/mcp, /v1/mcp)
    pub deep_probe: bool,
    /// Accept invalid TLS certificates
    pub insecure: bool,
    /// URL scheme mode (http, https, both)
    pub scheme: SchemeMode,
    /// Enable active behavioral probing
    pub active: bool,
    /// Enable Tier 2: call LOW-risk tools
    pub probe_tools: bool,
    /// Enable Tier 3: also call MEDIUM-risk tools
    pub probe_medium: bool,
    /// Show plan without executing
    pub dry_run: bool,
    /// Pin file path for saving hashes
    pub pin_file: Option<std::path::PathBuf>,
    /// Verify file path for comparing against saved hashes
    pub verify_file: Option<std::path::PathBuf>,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            mode: ScanMode::Fast,
            threads: 50,
            timeout: Duration::from_secs(5),
            show_progress: true,
            rate_limit: 0,
            enumerate: false,
            show_all: false,
            min_confidence: 0,
            deep_probe: false,
            insecure: false,
            scheme: SchemeMode::Both,
            active: false,
            probe_tools: false,
            probe_medium: false,
            dry_run: false,
            pin_file: None,
            verify_file: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ScanResult {
    pub target: ScanTarget,
    pub port_status: PortStatus,
    pub mcp_result: Option<McpProbeResult>,
}

/// MCP server scanning engine with concurrent target probing.
pub struct ScanEngine {
    config: ScanConfig,
    prober: Arc<McpProber>,
    cancel_token: CancellationToken,
}

impl ScanEngine {
    /// Create a new scan engine with the given configuration.
    pub fn new(config: ScanConfig, cancel_token: CancellationToken) -> Result<Self> {
        let prober = Arc::new(
            McpProber::with_options(config.timeout, config.insecure)?
                .with_enumerate(config.enumerate)
                .with_deep_probe(config.deep_probe)
                .with_scheme(config.scheme),
        );
        Ok(Self {
            config,
            prober,
            cancel_token,
        })
    }

    /// Scan the given IPs and ports for MCP servers.
    pub async fn scan(&self, ips: Vec<IpAddr>, ports: Vec<u16>) -> Vec<ScanResult> {
        let mut targets = generate_targets(&ips, &ports);
        let total_targets = targets.len();

        info!(
            "Scanning {} targets ({} hosts × {} ports)",
            total_targets,
            ips.len(),
            ports.len()
        );

        if self.config.mode == ScanMode::Stealth {
            shuffle_targets(&mut targets);
        }

        let semaphore = Arc::new(Semaphore::new(self.config.threads));
        let prober = Arc::clone(&self.prober);
        let progress = if self.config.show_progress {
            let pb = ProgressBar::new(total_targets as u64);
            pb.set_style(
                ProgressStyle::default_bar()
                    .template("{bar:40.cyan/blue} {pos}/{len} ({elapsed}) {msg}")
                    .unwrap()
                    .progress_chars("\u{2588}\u{2592}\u{2591}"),
            );
            Some(pb)
        } else {
            None
        };

        let found_count = Arc::new(AtomicU64::new(0));

        let rate_limit = self.config.rate_limit;

        // Lock-free rate limiter: AtomicU64 stores the next allowed slot in microseconds
        // elapsed from scan_start. Each task atomically reserves a time slot via CAS.
        let scan_start = StdInstant::now();
        let rate_limiter: Option<Arc<AtomicU64>> = if rate_limit > 0 {
            Some(Arc::new(AtomicU64::new(0)))
        } else {
            None
        };
        let rate_interval_us = if rate_limit > 0 {
            1_000_000 / rate_limit as u64
        } else {
            0
        };

        let mut results: Vec<ScanResult> = stream::iter(targets)
            .map(|target| {
                let semaphore = Arc::clone(&semaphore);
                let prober = Arc::clone(&prober);
                let timeout = self.config.timeout;
                let mode = self.config.mode;
                let show_all = self.config.show_all;
                let min_confidence = self.config.min_confidence;
                let progress = progress.clone();
                let rate_limiter = rate_limiter.clone();
                let found_count = Arc::clone(&found_count);
                let cancel = self.cancel_token.clone();

                async move {
                    if cancel.is_cancelled() {
                        return None;
                    }

                    let _permit = semaphore.acquire().await.unwrap();

                    if cancel.is_cancelled() {
                        return None;
                    }

                    // Lock-free rate limiting: atomically reserve a time slot via CAS
                    if let Some(ref limiter) = rate_limiter {
                        loop {
                            let now_us = scan_start.elapsed().as_micros() as u64;
                            let current = limiter.load(Ordering::Acquire);
                            let slot = current.max(now_us);
                            let next = slot + rate_interval_us;
                            if limiter
                                .compare_exchange_weak(
                                    current,
                                    next,
                                    Ordering::AcqRel,
                                    Ordering::Relaxed,
                                )
                                .is_ok()
                            {
                                if slot > now_us {
                                    sleep(Duration::from_micros(slot - now_us)).await;
                                }
                                break;
                            }
                        }
                    }

                    if mode == ScanMode::Stealth {
                        let delay = rand::random::<u64>() % 500;
                        sleep(Duration::from_millis(delay)).await;
                    }

                    let addr = target.socket_addr();
                    let port_status = check_port(addr, timeout).await;

                    let mcp_result = if port_status == PortStatus::Open {
                        debug!("Port open: {}", target);
                        Some(prober.probe(&target).await)
                    } else {
                        None
                    };

                    if let Some(ref mcp) = mcp_result {
                        let dominated = mcp.confidence.score >= min_confidence
                            && if show_all {
                                mcp.confidence.score > 0 || mcp.is_mcp_server()
                            } else {
                                mcp.confidence.level != ConfidenceLevel::Unlikely
                                    || mcp.is_mcp_server()
                            };
                        if dominated {
                            let count = found_count.fetch_add(1, Ordering::Relaxed) + 1;
                            if let Some(ref pb) = progress {
                                pb.set_message(format!("found: {}", count));
                            }
                        }
                    }

                    if let Some(ref pb) = progress {
                        pb.inc(1);
                    }

                    Some(ScanResult {
                        target,
                        port_status,
                        mcp_result,
                    })
                }
            })
            .buffer_unordered(self.config.threads)
            .filter_map(|r| async { r })
            .collect()
            .await;

        if let Some(pb) = progress {
            pb.finish_and_clear();
        }

        // Active probing stage (after all scan results collected)
        if self.config.active {
            let active_prober = ActiveProber::new(
                self.prober.client().clone(),
                self.config.timeout,
                self.config.probe_tools,
                self.config.probe_medium,
                self.config.dry_run,
            );

            for result in &mut results {
                if self.cancel_token.is_cancelled() {
                    break;
                }
                let Some(mcp) = &mut result.mcp_result else {
                    continue;
                };
                if !mcp.confidence.is_confirmed() || mcp.auth_required {
                    continue;
                }

                let scheme = if mcp.tls_enabled { "https" } else { "http" };
                let active_result = active_prober
                    .probe(
                        &result.target,
                        &mcp.endpoint_path,
                        mcp.session_id.as_deref(),
                        scheme,
                        mcp.tools.as_deref(),
                        mcp.server_info.as_ref(),
                    )
                    .await;

                // Merge active findings into security_warnings
                for finding in &active_result.findings {
                    mcp.security_warnings.push(format!(
                        "{} [{}] {}",
                        finding.id, finding.severity, finding.description
                    ));
                }

                // Update risk level if active probe found critical issues
                let has_critical = active_result
                    .findings
                    .iter()
                    .any(|f| f.severity == crate::mcp::active::Severity::Critical);
                if has_critical && mcp.risk_level != crate::mcp::protocol::RiskLevel::Critical {
                    mcp.risk_level = crate::mcp::protocol::RiskLevel::Critical;
                }

                mcp.active_probe = Some(active_result);
            }
        }

        let show_all = self.config.show_all;
        let min_confidence = self.config.min_confidence;

        results
            .into_iter()
            .filter(|r| {
                let Some(mcp) = r.mcp_result.as_ref() else {
                    return false;
                };

                // Filter by minimum confidence score
                if mcp.confidence.score < min_confidence {
                    return false;
                }

                // If show_all is enabled, include all results with any confidence
                if show_all {
                    return mcp.confidence.score > 0 || mcp.is_mcp_server();
                }

                // Default: only show Likely or Confirmed (score >= 30)
                mcp.confidence.level != ConfidenceLevel::Unlikely || mcp.is_mcp_server()
            })
            .collect()
    }
}
