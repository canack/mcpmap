use crate::cli::SchemeMode;
use crate::error::{McpmapError, Result};
use crate::mcp::active::ActiveProbeResult;
use crate::mcp::protocol::{
    self, KNOWN_PROTOCOL_VERSIONS, McpConfidence, PROTOCOL_VERSION_LATEST, PROTOCOL_VERSION_LEGACY,
    RiskLevel, ToolInfo, TransportType, create_initialize_request,
    create_initialize_request_with_version, create_initialized_notification,
    create_tools_list_request,
};
use crate::scanner::target::ScanTarget;
use futures::stream::{FuturesUnordered, StreamExt};
use reqwest::Client;
use reqwest::header::{ACCEPT, CONTENT_TYPE, HeaderMap};
use serde::Serialize;
use std::net::IpAddr;
use std::time::{Duration, Instant};
use tracing::{debug, trace, warn};

const MCP_ENDPOINTS_DEFAULT: &[&str] = &["/", "/mcp", "/.well-known/mcp"];
const MCP_ENDPOINTS_DEEP: &[&str] = &[
    "/",
    "/mcp",
    "/sse",
    "/api/mcp",
    "/v1/mcp",
    "/.well-known/mcp",
    "/mcp/v1",
    "/api/v1/mcp",
];
const MAX_BODY_SIZE: usize = 65536; // 64KB max response body

// =============================================================================
// Non-MCP Service Signatures (for Stage 2 filtering)
// =============================================================================

/// Signatures that indicate a service is NOT an MCP server.
/// These are checked against the GET / response in Stage 2.
struct NonMcpSignature {
    check_type: SignatureCheckType,
    pattern: &'static str,
}

enum SignatureCheckType {
    HeaderServer,
    HeaderXPoweredBy,
    BodyPrefix,
}

const NON_MCP_SIGNATURES: &[NonMcpSignature] = &[
    NonMcpSignature {
        check_type: SignatureCheckType::HeaderServer,
        pattern: "nginx",
    },
    NonMcpSignature {
        check_type: SignatureCheckType::HeaderServer,
        pattern: "apache",
    },
    NonMcpSignature {
        check_type: SignatureCheckType::HeaderServer,
        pattern: "cloudflare",
    },
    NonMcpSignature {
        check_type: SignatureCheckType::HeaderServer,
        pattern: "redis",
    },
    NonMcpSignature {
        check_type: SignatureCheckType::HeaderXPoweredBy,
        pattern: "express",
    },
    NonMcpSignature {
        check_type: SignatureCheckType::HeaderXPoweredBy,
        pattern: "php",
    },
    NonMcpSignature {
        check_type: SignatureCheckType::BodyPrefix,
        pattern: "<!doctype html",
    },
    NonMcpSignature {
        check_type: SignatureCheckType::BodyPrefix,
        pattern: "<html",
    },
    NonMcpSignature {
        check_type: SignatureCheckType::BodyPrefix,
        pattern: "<?xml",
    },
];

// =============================================================================
// MCP Server Info
// =============================================================================

#[derive(Debug, Clone, Default, Serialize)]
pub struct McpServerInfo {
    pub name: Option<String>,
    pub version: Option<String>,
    pub protocol_version: Option<String>,
    pub capabilities: Vec<String>,
}

// =============================================================================
// Main Probe Result
// =============================================================================

#[derive(Debug, Clone, Serialize)]
pub struct McpProbeResult {
    pub host: IpAddr,
    pub port: u16,
    pub confidence: McpConfidence,
    pub server_info: Option<McpServerInfo>,
    pub endpoint_path: String,
    pub transport_type: TransportType,
    pub response_time_ms: u64,
    pub auth_required: bool,
    pub error: Option<String>,
    pub tools: Option<Vec<ToolInfo>>,
    pub risk_level: RiskLevel,

    /// Security: Origin header validation status
    /// true = server validates Origin (good), false = no validation (DNS rebinding risk)
    pub origin_validation: Option<bool>,

    /// Session ID from Mcp-Session-Id header (if server uses sessions)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,

    /// Whether connection was over TLS (HTTPS)
    pub tls_enabled: bool,

    /// Security warnings detected during scan
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub security_warnings: Vec<String>,

    /// Active probe results (populated when --active is used)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active_probe: Option<ActiveProbeResult>,
}

impl Default for McpProbeResult {
    fn default() -> Self {
        Self {
            host: IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
            port: 0,
            confidence: McpConfidence::default(),
            server_info: None,
            endpoint_path: String::new(),
            transport_type: TransportType::Unknown,
            response_time_ms: 0,
            auth_required: false,
            error: None,
            tools: None,
            risk_level: RiskLevel::Info,
            origin_validation: None,
            session_id: None,
            tls_enabled: false,
            security_warnings: Vec::new(),
            active_probe: None,
        }
    }
}

impl McpProbeResult {
    fn new(target: &ScanTarget) -> Self {
        Self {
            host: target.ip,
            port: target.port,
            ..Default::default()
        }
    }

    pub fn is_mcp_server(&self) -> bool {
        self.confidence.is_likely()
    }

    pub fn server_name(&self) -> Option<&str> {
        self.server_info.as_ref().and_then(|i| i.name.as_deref())
    }

    pub fn server_version(&self) -> Option<&str> {
        self.server_info.as_ref().and_then(|i| i.version.as_deref())
    }

    pub fn protocol_version(&self) -> Option<&str> {
        self.server_info
            .as_ref()
            .and_then(|i| i.protocol_version.as_deref())
    }

    pub fn endpoint(&self) -> Option<&str> {
        if self.endpoint_path.is_empty() {
            None
        } else {
            Some(&self.endpoint_path)
        }
    }

    fn with_confidence(mut self, confidence: McpConfidence) -> Self {
        self.confidence = confidence;
        self
    }

    fn with_server_info(mut self, info: McpServerInfo) -> Self {
        self.server_info = Some(info);
        self
    }

    fn with_endpoint(mut self, path: &str) -> Self {
        self.endpoint_path = path.to_string();
        self
    }

    fn with_transport(mut self, transport: TransportType) -> Self {
        self.transport_type = transport;
        self
    }

    fn with_auth_required(mut self, auth: bool, error: Option<String>) -> Self {
        self.auth_required = auth;
        self.error = error;
        // Note: Auth alone does NOT confirm MCP server
        // is_mcp_server is set based on confidence.is_likely() in with_confidence()
        self
    }

    fn with_tools(mut self, tools: Vec<ToolInfo>) -> Self {
        // Calculate overall risk level (highest among all tools)
        self.risk_level = tools
            .iter()
            .map(|t| t.risk_level)
            .min() // RiskLevel ordering: Critical < High < Medium < Low < Info
            .unwrap_or(RiskLevel::Info);

        // Collect tool-level security warnings
        for tool in &tools {
            for warning in &tool.security_warnings {
                self.security_warnings
                    .push(format!("Tool '{}': {}", tool.name, warning));
            }
        }

        self.tools = Some(tools);
        self
    }

    fn with_tls(mut self, enabled: bool) -> Self {
        self.tls_enabled = enabled;
        if !enabled {
            self.security_warnings
                .push("No TLS: traffic can be intercepted".to_string());
        }
        self
    }

    fn with_session_id(mut self, session_id: Option<String>) -> Self {
        if let Some(ref sid) = session_id {
            // Analyze session ID for security issues
            if let Some(warning) = Self::analyze_session_id(sid) {
                self.security_warnings.push(warning);
            }
        }
        self.session_id = session_id;
        self
    }

    /// Analyze session ID format for potential security issues
    fn analyze_session_id(sid: &str) -> Option<String> {
        // Check if it's a simple sequential number
        if sid.parse::<u64>().is_ok() {
            return Some(format!("Weak session ID: sequential number ({})", sid));
        }

        // Check if it's too short (weak entropy)
        if sid.len() < 16 {
            return Some(format!("Weak session ID: too short ({} chars)", sid.len()));
        }

        // Check Shannon entropy for IDs that pass length check
        let entropy = Self::shannon_entropy(sid);
        if entropy < 3.0 {
            return Some(format!(
                "Weak session ID: low entropy ({:.1} bits/char)",
                entropy
            ));
        }

        // Check for predictable patterns
        let lowercase = sid.to_lowercase();
        if lowercase.starts_with("session-")
            || lowercase.starts_with("user-")
            || lowercase.starts_with("sess_")
        {
            // Check the suffix
            let suffix = &sid[sid.find('-').or_else(|| sid.find('_')).unwrap_or(0) + 1..];
            if suffix.parse::<u64>().is_ok() {
                return Some("Weak session ID: predictable pattern".to_string());
            }
        }

        None
    }

    /// Calculate Shannon entropy in bits per character
    fn shannon_entropy(s: &str) -> f64 {
        if s.is_empty() {
            return 0.0;
        }
        let len = s.len() as f64;
        let mut freq = [0u32; 256];
        for b in s.bytes() {
            freq[b as usize] += 1;
        }
        freq.iter()
            .filter(|&&count| count > 0)
            .map(|&count| {
                let p = count as f64 / len;
                -p * p.log2()
            })
            .sum()
    }

    fn add_security_warning(&mut self, warning: String) {
        self.security_warnings.push(warning);
    }
}

// =============================================================================
// HTTP Heuristic Result (Stage 2)
// =============================================================================

#[derive(Debug, Default)]
struct HttpHeuristicResult {
    is_http: bool,
    is_likely_mcp: bool,
    skip_reason: Option<String>,
}

// =============================================================================
// MCP Prober
// =============================================================================

#[derive(Clone)]
pub struct McpProber {
    client: Client,
    http_timeout: Duration,
    enumerate: bool,
    deep_probe: bool,
    scheme: SchemeMode,
}

impl McpProber {
    pub fn new(timeout: Duration) -> Result<Self> {
        Self::with_options(timeout, false)
    }

    pub fn with_options(timeout: Duration, insecure: bool) -> Result<Self> {
        // HTTP heuristic timeout: half of main timeout, clamped to 2-5 seconds
        let http_timeout_secs = (timeout.as_secs() / 2).clamp(2, 5);
        let http_timeout = Duration::from_secs(http_timeout_secs);

        let client = Client::builder()
            .timeout(timeout)
            .connect_timeout(http_timeout) // Use derived timeout for connection
            .pool_max_idle_per_host(10)
            .pool_idle_timeout(Duration::from_secs(30))
            .danger_accept_invalid_certs(insecure)
            .build()
            .map_err(McpmapError::Network)?;

        Ok(Self {
            client,
            http_timeout,
            enumerate: false,
            deep_probe: false,
            scheme: SchemeMode::Both,
        })
    }

    pub fn with_enumerate(mut self, enumerate: bool) -> Self {
        self.enumerate = enumerate;
        self
    }

    pub fn with_deep_probe(mut self, deep_probe: bool) -> Self {
        self.deep_probe = deep_probe;
        self
    }

    pub fn with_scheme(mut self, scheme: SchemeMode) -> Self {
        self.scheme = scheme;
        self
    }

    /// Get a reference to the underlying HTTP client (for active probing)
    pub fn client(&self) -> &Client {
        &self.client
    }

    /// Create standard MCP HTTP headers (delegates to protocol::mcp_headers)
    fn mcp_headers(&self) -> HeaderMap {
        protocol::mcp_headers(None)
    }

    /// Create MCP headers with session ID (delegates to protocol::mcp_headers)
    fn mcp_headers_with_session(&self, session_id: Option<&str>) -> HeaderMap {
        protocol::mcp_headers(session_id)
    }

    /// Main probe entry point - runs the full multi-stage pipeline
    pub async fn probe(&self, target: &ScanTarget) -> McpProbeResult {
        let start = Instant::now();

        let schemes: Vec<&str> = match self.scheme {
            SchemeMode::Both => vec!["https", "http"],
            SchemeMode::Https => vec!["https"],
            SchemeMode::Http => vec!["http"],
        };

        // Probe all schemes in parallel, take first positive result
        let mut futs = FuturesUnordered::new();
        for scheme in &schemes {
            futs.push(self.probe_single_scheme(target, scheme));
        }

        while let Some(result) = futs.next().await {
            if let Some(mut result) = result {
                result.response_time_ms = start.elapsed().as_millis() as u64;

                // Stage 5: Capability Enumeration (if enabled and confirmed)
                if self.enumerate && result.confidence.is_confirmed() && !result.auth_required {
                    let scheme = if result.tls_enabled { "https" } else { "http" };
                    let session_id = result.session_id.as_deref();
                    if let Some(tools) = self
                        .stage5_enumerate_tools_with_scheme(
                            target,
                            &result.endpoint_path,
                            session_id,
                            scheme,
                        )
                        .await
                    {
                        result = result.with_tools(tools);
                    }
                }

                return result;
            }
        }

        McpProbeResult::new(target)
    }

    /// Probe a single scheme (HTTP or HTTPS) through Stage 2 + Stage 3 pipeline
    async fn probe_single_scheme(
        &self,
        target: &ScanTarget,
        scheme: &str,
    ) -> Option<McpProbeResult> {
        trace!("{}: Trying {} scheme", target, scheme);

        let heuristic = self.stage2_http_heuristic_with_scheme(target, scheme).await;
        if !heuristic.is_http {
            trace!("{}: Not {} service", target, scheme);
            return None;
        }

        if let Some(reason) = &heuristic.skip_reason {
            trace!("{}: Stage 2 hint: {} (continuing anyway)", target, reason);
        }

        let mut result = self.stage3_mcp_handshake_with_scheme(target, scheme).await;

        if result.confidence.score > 0 || result.auth_required {
            result = result.with_tls(scheme == "https");

            let session_id = result.session_id.clone();
            result = result.with_session_id(session_id);

            if result.origin_validation == Some(false) {
                result.add_security_warning("Origin not validated: DNS rebinding risk".to_string());
            }

            Some(result)
        } else {
            None
        }
    }

    // =========================================================================
    // Stage 2: HTTP Heuristic
    // =========================================================================

    async fn stage2_http_heuristic_with_scheme(
        &self,
        target: &ScanTarget,
        scheme: &str,
    ) -> HttpHeuristicResult {
        let url = target.url_with_scheme(scheme, "/");
        trace!("Stage 2: GET {}", url);

        let mut response =
            match tokio::time::timeout(self.http_timeout, self.client.get(&url).send()).await {
                Ok(Ok(resp)) => resp,
                Ok(Err(e)) => {
                    trace!("Stage 2 HTTP error: {}", e);
                    return HttpHeuristicResult::default();
                }
                Err(_) => {
                    trace!("Stage 2 timeout");
                    return HttpHeuristicResult::default();
                }
            };

        let status = response.status().as_u16();
        let headers = response.headers().clone();
        let content_type = headers
            .get(CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(String::from);
        let server_header = headers
            .get("server")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_lowercase());
        let x_powered_by = headers
            .get("x-powered-by")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_lowercase());

        // Read limited body for signature checking (chunk-based, max 4KB)
        let body = {
            let mut buf = Vec::with_capacity(4096);
            while let Ok(Some(chunk)) = response.chunk().await {
                buf.extend_from_slice(&chunk);
                if buf.len() >= 4096 {
                    break;
                }
            }
            String::from_utf8_lossy(&buf).to_lowercase()
        };

        let mut result = HttpHeuristicResult {
            is_http: true,
            is_likely_mcp: true,
            skip_reason: None,
        };

        // Check non-MCP signatures - score-based, not hard-skip
        // Server headers (nginx/apache) may indicate reverse proxy, not definitive non-MCP
        let mut non_mcp_signals = 0u8;
        let mut non_mcp_reasons = Vec::new();

        for sig in NON_MCP_SIGNATURES {
            let matches = match sig.check_type {
                SignatureCheckType::HeaderServer => server_header
                    .as_ref()
                    .is_some_and(|h| h.contains(sig.pattern)),
                SignatureCheckType::HeaderXPoweredBy => x_powered_by
                    .as_ref()
                    .is_some_and(|h| h.contains(sig.pattern)),
                SignatureCheckType::BodyPrefix => body.starts_with(sig.pattern),
            };

            if matches {
                non_mcp_signals += 1;
                non_mcp_reasons.push(sig.pattern);
            }
        }

        // Only mark as non-MCP if we see strong evidence (body prefix like HTML/XML)
        // or multiple signals. A single server header could be a reverse proxy.
        if non_mcp_signals > 0 {
            let has_body_match = non_mcp_reasons
                .iter()
                .any(|r| *r == "<!doctype html" || *r == "<html" || *r == "<?xml");

            if has_body_match || non_mcp_signals >= 2 {
                result.is_likely_mcp = false;
                result.skip_reason = Some(format!(
                    "Non-MCP signatures: {}",
                    non_mcp_reasons.join(", ")
                ));
            } else {
                // Single header match (likely reverse proxy) - reduce confidence but don't skip
                result.skip_reason = Some(format!(
                    "Possible reverse proxy: {}",
                    non_mcp_reasons.join(", ")
                ));
                // Keep is_likely_mcp = true to allow probing
            }
        }

        // 405 Method Not Allowed on GET gives low confidence for MCP
        // (Streamable HTTP servers expect POST, but any POST-only API returns 405)
        if status == 405 {
            result.is_likely_mcp = true;
            result.skip_reason = None;
        }

        // SSE content type indicates potential old transport
        if content_type
            .as_ref()
            .is_some_and(|ct| ct.contains("text/event-stream"))
        {
            result.is_likely_mcp = true;
            result.skip_reason = None;
        }

        result
    }

    // =========================================================================
    // Stage 3: MCP Initialize Handshake
    // =========================================================================

    async fn stage3_mcp_handshake_with_scheme(
        &self,
        target: &ScanTarget,
        scheme: &str,
    ) -> McpProbeResult {
        let endpoints = if self.deep_probe {
            MCP_ENDPOINTS_DEEP
        } else {
            MCP_ENDPOINTS_DEFAULT
        };

        // Probe all endpoints in parallel, take first positive result
        let mut futs = FuturesUnordered::new();
        for endpoint in endpoints {
            futs.push(self.probe_single_endpoint(target, endpoint, scheme));
        }

        while let Some(result) = futs.next().await {
            if let Some(result) = result {
                return result;
            }
        }

        McpProbeResult::new(target)
    }

    /// Probe a single endpoint with POST, falling back to legacy SSE transport
    async fn probe_single_endpoint(
        &self,
        target: &ScanTarget,
        endpoint: &str,
        scheme: &str,
    ) -> Option<McpProbeResult> {
        let url = target.url_with_scheme(scheme, endpoint);
        trace!("Stage 3: POST {}", url);

        match self.probe_endpoint(&url).await {
            Ok(mut result) => {
                if result.confidence.score > 0 || result.auth_required {
                    result = result.with_endpoint(endpoint);
                    result.host = target.ip;
                    result.port = target.port;
                    result.origin_validation = self.test_origin_validation(&url).await;
                    debug!(
                        "MCP found at {}{} (score: {})",
                        target, endpoint, result.confidence.score
                    );
                    Some(result)
                } else {
                    trace!("POST returned non-MCP response, trying legacy SSE: {}", url);
                    self.try_legacy_sse_with_fixup(target, endpoint, scheme)
                        .await
                }
            }
            Err(e) => {
                trace!("Stage 3 probe failed for {}: {}", url, e);
                self.try_legacy_sse_with_fixup(target, endpoint, scheme)
                    .await
            }
        }
    }

    /// Try legacy SSE transport and fix up host/port on result
    async fn try_legacy_sse_with_fixup(
        &self,
        target: &ScanTarget,
        endpoint: &str,
        scheme: &str,
    ) -> Option<McpProbeResult> {
        self.try_legacy_sse_transport_with_scheme(target, endpoint, scheme)
            .await
            .map(|mut r| {
                r.host = target.ip;
                r.port = target.port;
                r
            })
    }

    /// Backwards compatibility: Try legacy HTTP+SSE transport (pre-2025-03-26)
    ///
    /// Legacy SSE transport flow:
    /// 1. GET /sse → keep connection open, receive SSE events
    /// 2. First event: "endpoint" with session_id in data
    /// 3. POST /messages/?session_id=xxx with JSON-RPC request
    /// 4. Response comes through SSE stream (NOT from POST!)
    /// 5. Close connection
    async fn try_legacy_sse_transport_with_scheme(
        &self,
        target: &ScanTarget,
        endpoint: &str,
        scheme: &str,
    ) -> Option<McpProbeResult> {
        // For legacy SSE, try common SSE endpoints
        let sse_endpoints = if endpoint == "/" || endpoint == "/mcp" {
            vec!["/sse", endpoint]
        } else {
            vec![endpoint]
        };

        for sse_endpoint in sse_endpoints {
            if let Some(result) = self
                .probe_legacy_sse_endpoint(target, sse_endpoint, scheme)
                .await
            {
                return Some(result);
            }
        }

        None
    }

    /// Probe a single legacy SSE endpoint with proper bidirectional communication
    async fn probe_legacy_sse_endpoint(
        &self,
        target: &ScanTarget,
        sse_endpoint: &str,
        scheme: &str,
    ) -> Option<McpProbeResult> {
        use tokio::time::timeout;

        let sse_url = target.url_with_scheme(scheme, sse_endpoint);
        trace!("Trying legacy SSE transport: GET {}", sse_url);

        let mut headers = HeaderMap::new();
        headers.insert(ACCEPT, "text/event-stream".parse().unwrap());

        // Start SSE connection
        let mut sse_response = match self.client.get(&sse_url).headers(headers).send().await {
            Ok(r) => r,
            Err(_) => return None,
        };

        // Check if server returns SSE stream
        let content_type = sse_response
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())?;

        if !content_type.contains("text/event-stream") {
            return None;
        }

        // Step 1: Read first event to get session_id (with timeout)
        let first_event = self
            .read_sse_first_event_from_stream(&mut sse_response)
            .await?;

        if !first_event.contains("event: endpoint") && !first_event.contains("event:endpoint") {
            return None;
        }

        // Extract messages endpoint URL from data: field.
        // The MCP spec does not mandate a specific path or query param name —
        // official SDKs vary: TypeScript uses /messages?sessionId=, Python uses
        // /messages/?session_id=, mcp-go uses /message?sessionId=.  The official
        // TypeScript MCP *client* treats the data value as an opaque URL, so we
        // do the same: accept any non-empty value after the "event: endpoint" gate.
        let messages_path = first_event.lines().find_map(|line| {
            line.strip_prefix("data:")
                .map(|d| d.trim().to_string())
                .filter(|d| !d.is_empty())
        })?;

        let messages_url = if messages_path.starts_with("http") {
            messages_path.clone()
        } else {
            format!("{}://{}{}", scheme, target, messages_path)
        };

        trace!("Legacy SSE: session URL = {}", messages_url);

        // Step 2: POST initialize request (fire-and-forget style - response comes via SSE)
        let init_request = create_initialize_request_with_version(PROTOCOL_VERSION_LATEST);
        let post_headers = self.mcp_headers();

        // Send POST in background - we don't wait for its response
        let client = self.client.clone();
        let post_url = messages_url.clone();
        let post_body = serde_json::to_string(&init_request).ok()?;

        tokio::spawn(async move {
            if let Err(e) = client
                .post(&post_url)
                .headers(post_headers)
                .body(post_body)
                .send()
                .await
            {
                tracing::trace!("Legacy SSE POST failed: {}", e);
            }
        });

        // Step 3: Read response from SSE stream (with timeout)
        let sse_timeout = Duration::from_secs(3);
        let response_body =
            match timeout(sse_timeout, self.read_sse_json_response(&mut sse_response)).await {
                Ok(Some(body)) => body,
                Ok(None) | Err(_) => {
                    // Timeout or no response - but we confirmed SSE transport exists
                    trace!("Legacy SSE: no response within timeout, but transport confirmed");
                    let mut confidence = McpConfidence::new();
                    confidence
                        .add_evidence(60, "MCP SSE transport (endpoint event, no init response)");

                    return Some(
                        McpProbeResult::default()
                            .with_confidence(confidence)
                            .with_endpoint(sse_endpoint)
                            .with_transport(TransportType::Sse),
                    );
                }
            };

        // Step 4: Parse and validate the response
        let (confidence, server_info) = self.stage4_validate_response(&response_body);

        if confidence.score == 0 {
            // Got SSE event but not valid MCP response
            let mut fallback_confidence = McpConfidence::new();
            fallback_confidence.add_evidence(50, "MCP SSE transport (endpoint event)");

            return Some(
                McpProbeResult::default()
                    .with_confidence(fallback_confidence)
                    .with_endpoint(sse_endpoint)
                    .with_transport(TransportType::Sse),
            );
        }

        // Extract session ID from URL query parameters.
        // Accept common variants: sessionId (TS SDK, mcp-go), session_id (Python SDK), sid.
        let session_id = messages_path
            .split_once('?')
            .map(|(_, query)| query)
            .unwrap_or("")
            .split('&')
            .find_map(|pair| {
                pair.split_once('=')
                    .filter(|(key, _)| {
                        let k = key.to_lowercase();
                        k == "sessionid" || k == "session_id" || k == "sid"
                    })
                    .map(|(_, value)| value.to_string())
            });

        let mut result = McpProbeResult::default()
            .with_confidence(confidence)
            .with_server_info(server_info)
            .with_endpoint(sse_endpoint)
            .with_transport(TransportType::Sse);

        result.session_id = session_id;

        // Test Origin validation on the messages endpoint
        result.origin_validation = self.test_origin_validation(&messages_url).await;

        debug!(
            "MCP found via legacy SSE at {}{} (score: {})",
            target, sse_endpoint, result.confidence.score
        );

        Some(result)
    }

    /// Read the first complete SSE event from an open stream
    async fn read_sse_first_event_from_stream(
        &self,
        response: &mut reqwest::Response,
    ) -> Option<String> {
        use tokio::time::timeout;

        let mut body = Vec::with_capacity(1024);
        let read_timeout = Duration::from_secs(2);

        loop {
            match timeout(read_timeout, response.chunk()).await {
                Ok(Ok(Some(chunk))) => {
                    body.extend_from_slice(&chunk);
                    let body_str = String::from_utf8_lossy(&body);

                    // Check if we have a complete SSE event
                    if body_str.contains("\n\n") || body_str.contains("\r\n\r\n") {
                        return Some(body_str.to_string());
                    }

                    if body.len() > 4096 {
                        return Some(body_str.to_string());
                    }
                }
                Ok(Ok(None)) => {
                    let body_str = String::from_utf8_lossy(&body).to_string();
                    return if body_str.is_empty() {
                        None
                    } else {
                        Some(body_str)
                    };
                }
                Ok(Err(_)) | Err(_) => {
                    let body_str = String::from_utf8_lossy(&body).to_string();
                    return if body_str.is_empty() {
                        None
                    } else {
                        Some(body_str)
                    };
                }
            }
        }
    }

    /// Read JSON-RPC response from SSE stream (looking for message event)
    async fn read_sse_json_response(&self, response: &mut reqwest::Response) -> Option<String> {
        let mut body = Vec::with_capacity(4096);
        let read_timeout = Duration::from_millis(500);

        // Read chunks until we get a complete JSON-RPC response event
        loop {
            match tokio::time::timeout(read_timeout, response.chunk()).await {
                Ok(Ok(Some(chunk))) => {
                    body.extend_from_slice(&chunk);
                    let body_str = String::from_utf8_lossy(&body);

                    // Look for message event with JSON-RPC data
                    if let Some(json) = Self::extract_jsonrpc_from_sse(&body_str) {
                        return Some(json);
                    }

                    if body.len() > 16384 {
                        // Try to extract whatever we have
                        return Self::extract_jsonrpc_from_sse(&body_str);
                    }
                }
                Ok(Ok(None)) => {
                    let body_str = String::from_utf8_lossy(&body);
                    return Self::extract_jsonrpc_from_sse(&body_str);
                }
                Ok(Err(_)) | Err(_) => {
                    let body_str = String::from_utf8_lossy(&body);
                    return Self::extract_jsonrpc_from_sse(&body_str);
                }
            }
        }
    }

    /// Extract JSON-RPC message from SSE event stream
    fn extract_jsonrpc_from_sse(body: &str) -> Option<String> {
        // Normalize line endings
        let normalized = body.replace("\r\n", "\n");

        // Split into events
        for event in normalized.split("\n\n") {
            let mut event_type = None;
            let mut data_lines = Vec::new();

            for line in event.lines() {
                if let Some(t) = line.strip_prefix("event:") {
                    event_type = Some(t.trim());
                } else if let Some(d) = line.strip_prefix("data:") {
                    data_lines.push(d.trim());
                }
            }

            // Look for message event or raw JSON-RPC data
            let data = data_lines.join("\n");
            if data.is_empty() {
                continue;
            }

            // Check if it's JSON-RPC
            if data.contains("\"jsonrpc\"")
                && (data.contains("\"result\"") || data.contains("\"error\""))
            {
                // Validate it parses as JSON
                if serde_json::from_str::<serde_json::Value>(&data).is_ok() {
                    return Some(data);
                }
            }

            // Also check for "message" event type
            if event_type == Some("message")
                && !data.is_empty()
                && serde_json::from_str::<serde_json::Value>(&data).is_ok()
            {
                return Some(data);
            }
        }

        None
    }

    /// Test if server validates Origin header (DNS rebinding protection)
    /// Returns: Some(true) = validates (secure), Some(false) = no validation (vulnerable)
    ///
    /// Test methodology:
    /// - Send request with malicious Origin header (http://evil-attacker.com)
    /// - If server accepts (2xx) → vulnerable to DNS rebinding
    /// - If server rejects (403) → properly validates Origin (secure)
    /// - If server returns 401 → server doesn't validate origin before auth (still vulnerable)
    ///   Only a 403 specifically indicates origin rejection.
    async fn test_origin_validation(&self, url: &str) -> Option<bool> {
        let mut headers = self.mcp_headers();
        // Simulate DNS rebinding attack with malicious Origin
        headers.insert("origin", "http://evil-attacker.com".parse().unwrap());

        let request = create_initialize_request_with_version(PROTOCOL_VERSION_LATEST);
        let response = self
            .client
            .post(url)
            .headers(headers)
            .json(&request)
            .send()
            .await
            .ok()?;

        let status = response.status();

        if status == reqwest::StatusCode::FORBIDDEN {
            // Server rejects malicious Origin - secure against DNS rebinding
            trace!("Origin validation: ENABLED (secure) - rejected evil origin");
            Some(true)
        } else if status.is_success() || status == reqwest::StatusCode::UNAUTHORIZED {
            // 2xx: server accepts malicious Origin - vulnerable
            // 401: server checked auth before origin - origin not validated (still vulnerable)
            trace!(
                "Origin validation: DISABLED (DNS rebinding risk) - status {}",
                status
            );
            Some(false)
        } else {
            // Other error (network, 5xx, etc.) - can't determine
            None
        }
    }

    async fn probe_endpoint(
        &self,
        url: &str,
    ) -> std::result::Result<McpProbeResult, reqwest::Error> {
        let headers = self.mcp_headers();

        // Try latest protocol version first
        let request = create_initialize_request_with_version(PROTOCOL_VERSION_LATEST);
        let response = self
            .client
            .post(url)
            .headers(headers.clone())
            .json(&request)
            .send()
            .await?;

        // If we get an error response, try legacy protocol version
        let response = if response.status().is_client_error() || response.status().is_server_error()
        {
            trace!("Latest protocol version failed, trying legacy: {}", url);
            let legacy_request = create_initialize_request_with_version(PROTOCOL_VERSION_LEGACY);
            self.client
                .post(url)
                .headers(headers)
                .json(&legacy_request)
                .send()
                .await?
        } else {
            response
        };

        let status = response.status();
        let response_headers = response.headers().clone();
        let content_type = response_headers
            .get(CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(String::from);

        // Capture Mcp-Session-Id header if present (spec 2025-06-18+)
        let session_id = response_headers
            .get("mcp-session-id")
            .and_then(|v| v.to_str().ok())
            .map(String::from);

        // Handle auth responses - look for MCP-specific indicators before scoring
        if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
            let mut confidence = McpConfidence::new();
            let mut has_mcp_hints = false;

            // Check WWW-Authenticate header for MCP/OAuth hints
            if let Some(www_auth) = response_headers
                .get("www-authenticate")
                .and_then(|v| v.to_str().ok())
            {
                let www_auth_lower = www_auth.to_lowercase();
                if www_auth_lower.contains("mcp") || www_auth_lower.contains("bearer") {
                    has_mcp_hints = true;
                    confidence.add_evidence(25, &format!("WWW-Authenticate: {}", www_auth));
                }
            }

            // Check for MCP-specific headers
            if response_headers.get("mcp-session-id").is_some() {
                has_mcp_hints = true;
                confidence.add_evidence(30, "Mcp-Session-Id header present in auth response");
            }

            // Read response body for JSON-RPC error hints
            let body = self.read_limited_body(response).await.unwrap_or_default();
            if !body.is_empty() {
                if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&body) {
                    // Check for JSON-RPC error format
                    if parsed.get("jsonrpc").is_some() && parsed.get("error").is_some() {
                        has_mcp_hints = true;
                        confidence.add_evidence(35, "JSON-RPC error response format");
                    }
                }
            }

            // Only set meaningful confidence if we found MCP hints
            // Otherwise, this could be any auth-protected endpoint
            if has_mcp_hints {
                confidence.add_evidence(15, &format!("HTTP {} on MCP endpoint", status.as_u16()));
            } else {
                // Low confidence - just an auth response, could be anything
                confidence
                    .set_fixed_score(15, &format!("HTTP {} (no MCP indicators)", status.as_u16()));
            }

            let error_msg = if status == reqwest::StatusCode::UNAUTHORIZED {
                "Authentication required"
            } else {
                "Forbidden"
            };

            return Ok(McpProbeResult::default()
                .with_confidence(confidence)
                .with_auth_required(true, Some(error_msg.to_string())));
        }

        if !status.is_success() {
            return Ok(McpProbeResult::default());
        }

        // Detect transport type from content-type
        let transport = if content_type
            .as_ref()
            .is_some_and(|ct| ct.contains("text/event-stream"))
        {
            TransportType::Sse
        } else {
            TransportType::StreamableHttp
        };

        // Check for MCP-specific headers that boost confidence
        let has_mcp_headers = response_headers.get("mcp-session-id").is_some()
            || response_headers.get("mcp-protocol-version").is_some();

        // Read body with size limit
        let body = self.read_limited_body(response).await?;

        // Stage 4: Validate and score the response
        let (mut confidence, server_info) = self.stage4_validate_response(&body);

        if confidence.score == 0 {
            return Ok(McpProbeResult::default());
        }

        // Boost confidence for MCP-specific response headers
        if has_mcp_headers {
            confidence.add_evidence(
                25,
                "MCP-specific headers (mcp-session-id or mcp-protocol-version)",
            );
        }

        let mut result = McpProbeResult::default()
            .with_confidence(confidence)
            .with_server_info(server_info)
            .with_transport(transport);

        result.session_id = session_id;

        Ok(result)
    }

    async fn read_limited_body(
        &self,
        response: reqwest::Response,
    ) -> std::result::Result<String, reqwest::Error> {
        protocol::read_limited_body(response, MAX_BODY_SIZE, true).await
    }

    // =========================================================================
    // Stage 4: Response Validation & Confidence Scoring
    // =========================================================================

    fn stage4_validate_response(&self, body: &str) -> (McpConfidence, McpServerInfo) {
        let mut confidence = McpConfidence::new();
        let mut server_info = McpServerInfo::default();

        // Parse JSON
        let parsed: serde_json::Value = match serde_json::from_str(body) {
            Ok(v) => v,
            Err(_) => return (confidence, server_info),
        };

        // Check JSON-RPC 2.0 compliance
        if !Self::is_valid_jsonrpc_response(&parsed) {
            return (confidence, server_info);
        }

        // +20 for valid JSON-RPC 2.0 response
        confidence.add_evidence(20, "Valid JSON-RPC 2.0 response");

        // Get result object
        let result = match parsed.get("result") {
            Some(r) => r,
            None => {
                // Check for error response (still valid MCP)
                if parsed.get("error").is_some() {
                    confidence.add_evidence(10, "JSON-RPC error response (valid MCP)");
                }
                return (confidence, server_info);
            }
        };

        // protocolVersion: +30 for known MCP versions, +10 for unknown
        if let Some(pv) = result.get("protocolVersion").and_then(|v| v.as_str()) {
            if KNOWN_PROTOCOL_VERSIONS.contains(&pv) {
                confidence.add_evidence(30, &format!("protocolVersion: {} (known MCP)", pv));
            } else {
                confidence.add_evidence(10, &format!("protocolVersion: {} (unknown version)", pv));
            }
            server_info.protocol_version = Some(pv.to_string());
        }

        // +20 for serverInfo
        if let Some(si) = result.get("serverInfo") {
            if let Some(name) = si.get("name").and_then(|v| v.as_str()) {
                server_info.name = Some(name.to_string());
                confidence.add_evidence(10, &format!("serverInfo.name: {}", name));
            }
            if let Some(version) = si.get("version").and_then(|v| v.as_str()) {
                server_info.version = Some(version.to_string());
                confidence.add_evidence(10, &format!("serverInfo.version: {}", version));
            }
        }

        // +20 for capabilities object
        if let Some(caps) = result.get("capabilities") {
            if caps.is_object() {
                confidence.add_evidence(20, "capabilities object present");

                // +10 for having actual capabilities
                // Collect all capability keys, not just known ones
                if let Some(obj) = caps.as_object() {
                    for key in obj.keys() {
                        server_info.capabilities.push(key.clone());
                    }
                }

                if !server_info.capabilities.is_empty() {
                    confidence.add_evidence(
                        10,
                        &format!("capabilities: {}", server_info.capabilities.join(", ")),
                    );
                }
            }
        }

        (confidence, server_info)
    }

    fn is_valid_jsonrpc_response(parsed: &serde_json::Value) -> bool {
        Self::is_valid_jsonrpc_response_with_id(parsed, None)
    }

    fn is_valid_jsonrpc_response_with_id(
        parsed: &serde_json::Value,
        expected_id: Option<u64>,
    ) -> bool {
        // 1. "jsonrpc": "2.0" field MUST exist
        if parsed.get("jsonrpc").and_then(|v| v.as_str()) != Some("2.0") {
            return false;
        }

        // 2. "id" field must exist (numeric or string per JSON-RPC 2.0 spec)
        let id_value = match parsed.get("id") {
            Some(v) if v.is_u64() || v.is_string() => v,
            _ => return false,
        };

        // 3. If expected_id specified, must match (accept stringified numeric IDs)
        if let Some(expected) = expected_id {
            let matches = id_value.as_u64() == Some(expected)
                || id_value.as_str() == Some(&expected.to_string());
            if !matches {
                return false;
            }
        }

        // 4. Either "result" OR "error" must exist (not both, not neither)
        let has_result = parsed.get("result").is_some();
        let has_error = parsed.get("error").is_some();
        if has_result == has_error {
            return false;
        }

        true
    }

    // =========================================================================
    // Stage 5: Capability Enumeration
    // =========================================================================

    async fn stage5_enumerate_tools_with_scheme(
        &self,
        target: &ScanTarget,
        endpoint: &str,
        session_id: Option<&str>,
        scheme: &str,
    ) -> Option<Vec<ToolInfo>> {
        let url = target.url_with_scheme(scheme, endpoint);
        trace!("Stage 5: tools/list {}", url);

        // Start with standard MCP headers including protocol version
        let mut headers = self.mcp_headers_with_session(session_id);

        // Step 1: Send initialize request to start session
        let init_request = create_initialize_request();
        let init_response = self
            .client
            .post(&url)
            .headers(headers.clone())
            .json(&init_request)
            .send()
            .await
            .ok();

        // Capture new session ID from initialize response (if different)
        let active_session_id = init_response
            .as_ref()
            .and_then(|r| r.headers().get("mcp-session-id"))
            .and_then(|v| v.to_str().ok())
            .map(String::from)
            .or_else(|| session_id.map(String::from));

        // Update headers with new session ID if we got one
        if let Some(ref sid) = active_session_id {
            if let Ok(value) = sid.parse() {
                headers.insert("mcp-session-id", value);
            }
        }

        // Step 2: Send notifications/initialized (required by MCP spec)
        // This notification has no id field. Server SHOULD respond with 202 Accepted.
        let initialized_notification = create_initialized_notification();
        match self
            .client
            .post(&url)
            .headers(headers.clone())
            .json(&initialized_notification)
            .send()
            .await
        {
            Ok(resp) => {
                let status = resp.status();
                // Per spec: Server SHOULD return 202 Accepted for notifications
                // Non-202 is unusual but not fatal - continue with tools/list
                if status != reqwest::StatusCode::ACCEPTED && !status.is_success() {
                    warn!(
                        "notifications/initialized returned {} (expected 202), continuing anyway",
                        status
                    );
                }
            }
            Err(e) => {
                warn!("notifications/initialized failed: {}, continuing anyway", e);
            }
        }

        // Step 3: Now send tools/list
        let request = create_tools_list_request();
        let response = match self
            .client
            .post(&url)
            .headers(headers)
            .json(&request)
            .send()
            .await
        {
            Ok(r) => r,
            Err(e) => {
                warn!("Stage 5 request failed: {}", e);
                return None;
            }
        };

        if !response.status().is_success() {
            return None;
        }

        let body = match self.read_limited_body(response).await {
            Ok(b) => b,
            Err(_) => return None,
        };

        let parsed: serde_json::Value = match serde_json::from_str(&body) {
            Ok(v) => v,
            Err(_) => return None,
        };

        // Validate JSON-RPC response (id should be 2 for tools/list)
        if parsed.get("jsonrpc").and_then(|v| v.as_str()) != Some("2.0") {
            return None;
        }
        let id_matches = parsed
            .get("id")
            .is_some_and(|v| v.as_u64() == Some(2) || v.as_str() == Some("2"));
        if !id_matches {
            return None;
        }

        let result = parsed.get("result")?;
        let tools_array = result.get("tools")?.as_array()?;

        Some(ToolInfo::from_json_array(tools_array))
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mcp::protocol::ConfidenceLevel;

    #[test]
    fn test_valid_jsonrpc_response() {
        let valid = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {}
        });
        assert!(McpProber::is_valid_jsonrpc_response(&valid));

        let valid_error = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "error": {"code": -32600, "message": "Invalid Request"}
        });
        assert!(McpProber::is_valid_jsonrpc_response(&valid_error));
    }

    #[test]
    fn test_invalid_jsonrpc_missing_version() {
        let invalid = serde_json::json!({
            "id": 1,
            "result": {}
        });
        assert!(!McpProber::is_valid_jsonrpc_response(&invalid));
    }

    #[test]
    fn test_invalid_jsonrpc_wrong_version() {
        let invalid = serde_json::json!({
            "jsonrpc": "1.0",
            "id": 1,
            "result": {}
        });
        assert!(!McpProber::is_valid_jsonrpc_response(&invalid));
    }

    #[test]
    fn test_jsonrpc_any_id_accepted() {
        // is_valid_jsonrpc_response accepts any numeric ID (relaxed)
        let valid = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 2,
            "result": {}
        });
        assert!(McpProber::is_valid_jsonrpc_response(&valid));
    }

    #[test]
    fn test_jsonrpc_strict_id_check() {
        // is_valid_jsonrpc_response_with_id rejects wrong ID
        let invalid = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 2,
            "result": {}
        });
        assert!(!McpProber::is_valid_jsonrpc_response_with_id(
            &invalid,
            Some(1)
        ));
        assert!(McpProber::is_valid_jsonrpc_response_with_id(
            &invalid,
            Some(2)
        ));
    }

    #[test]
    fn test_invalid_jsonrpc_both_result_and_error() {
        let invalid = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {},
            "error": {}
        });
        assert!(!McpProber::is_valid_jsonrpc_response(&invalid));
    }

    #[test]
    fn test_invalid_jsonrpc_neither_result_nor_error() {
        let invalid = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1
        });
        assert!(!McpProber::is_valid_jsonrpc_response(&invalid));
    }

    #[test]
    fn test_tool_risk_critical() {
        let tool = ToolInfo::new(
            "execute_shell".to_string(),
            Some("Run shell commands".to_string()),
        );
        assert_eq!(tool.risk_level, RiskLevel::Critical);

        let tool = ToolInfo::new("run_command".to_string(), None);
        assert_eq!(tool.risk_level, RiskLevel::Critical);
    }

    #[test]
    fn test_tool_risk_high() {
        let tool = ToolInfo::new("write_file".to_string(), None);
        assert_eq!(tool.risk_level, RiskLevel::High);

        let tool = ToolInfo::new("query_database".to_string(), None);
        assert_eq!(tool.risk_level, RiskLevel::High);
    }

    #[test]
    fn test_tool_risk_low() {
        // Use tool names that only match low-risk patterns (read/get/list/fetch/search/view)
        // Avoid names containing high-risk patterns (file, write, delete, database, query, sql, etc.)
        let tool = ToolInfo::new("get_status".to_string(), None);
        assert_eq!(tool.risk_level, RiskLevel::Low);

        let tool = ToolInfo::new("list_items".to_string(), None);
        assert_eq!(tool.risk_level, RiskLevel::Low);

        let tool = ToolInfo::new("view_details".to_string(), None);
        assert_eq!(tool.risk_level, RiskLevel::Low);
    }

    #[test]
    fn test_confidence_scoring() {
        let mut conf = McpConfidence::new();
        assert_eq!(conf.level, ConfidenceLevel::Unlikely);

        conf.add_evidence(20, "Test");
        assert_eq!(conf.score, 20);
        assert_eq!(conf.level, ConfidenceLevel::Unlikely);

        conf.add_evidence(30, "Test2");
        assert_eq!(conf.score, 50);
        assert_eq!(conf.level, ConfidenceLevel::Likely);

        conf.add_evidence(20, "Test3");
        assert_eq!(conf.score, 70);
        assert_eq!(conf.level, ConfidenceLevel::Confirmed);
    }
}
