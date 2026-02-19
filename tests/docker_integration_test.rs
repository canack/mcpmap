use mcpmap::cli::{ScanMode, SchemeMode};
use mcpmap::mcp::prober::McpProber;
use mcpmap::scanner::engine::{ScanConfig, ScanEngine};
use mcpmap::scanner::target::ScanTarget;
use std::time::Duration;
use testcontainers::core::{IntoContainerPort, WaitFor};
use testcontainers::runners::AsyncRunner;
use testcontainers::{ContainerAsync, GenericImage, ImageExt};

/// MCP-compatible HTTP server script (simulates real MCP server behavior)
const MCP_HTTP_SERVER: &str = r#"
const http = require('http');
const SERVER_NAME = process.env.MCP_SERVER_NAME || 'test-server';
const SERVER_VERSION = process.env.MCP_SERVER_VERSION || '1.0.0';
const CAPABILITIES = (process.env.MCP_CAPABILITIES || 'tools').split(',');

const server = http.createServer((req, res) => {
    if (req.method !== 'POST') {
        res.writeHead(200);
        res.end('MCP Server');
        return;
    }

    let body = '';
    req.on('data', chunk => body += chunk);
    req.on('end', () => {
        try {
            const request = JSON.parse(body);

            if (request.method === 'initialize') {
                const caps = {};
                CAPABILITIES.forEach(c => caps[c.trim()] = {});

                const response = {
                    jsonrpc: '2.0',
                    id: request.id,
                    result: {
                        protocolVersion: '2024-11-05',
                        serverInfo: {
                            name: SERVER_NAME,
                            version: SERVER_VERSION
                        },
                        capabilities: caps
                    }
                };

                res.writeHead(200, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify(response));
            } else {
                res.writeHead(200, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ jsonrpc: '2.0', id: request.id, result: {} }));
            }
        } catch (e) {
            res.writeHead(400);
            res.end('Invalid JSON');
        }
    });
});

server.listen(3000, '0.0.0.0', () => {
    console.log('MCP HTTP Server ready on port 3000');
});
"#;

/// Test configuration for MCP servers
#[allow(dead_code)]
struct McpTestServer {
    name: &'static str,
    version: &'static str,
    capabilities: &'static [&'static str],
}

/// Top 10 MCP servers to simulate
const MCP_SERVERS: &[McpTestServer] = &[
    McpTestServer {
        name: "everything-server",
        version: "1.0.0",
        capabilities: &["tools", "resources", "prompts"],
    },
    McpTestServer {
        name: "memory-server",
        version: "0.6.2",
        capabilities: &["tools"],
    },
    McpTestServer {
        name: "filesystem-server",
        version: "0.6.2",
        capabilities: &["tools", "resources"],
    },
    McpTestServer {
        name: "time-server",
        version: "0.6.2",
        capabilities: &["tools"],
    },
    McpTestServer {
        name: "fetch-server",
        version: "0.6.2",
        capabilities: &["tools"],
    },
    McpTestServer {
        name: "sequential-thinking-server",
        version: "0.6.2",
        capabilities: &["tools"],
    },
    McpTestServer {
        name: "sqlite-server",
        version: "0.6.2",
        capabilities: &["tools", "resources"],
    },
    McpTestServer {
        name: "git-server",
        version: "0.6.2",
        capabilities: &["tools"],
    },
    McpTestServer {
        name: "postgres-mcp",
        version: "0.6.2",
        capabilities: &["tools", "resources"],
    },
    McpTestServer {
        name: "github-mcp",
        version: "0.6.2",
        capabilities: &["tools"],
    },
];

/// Start a Docker container running an MCP-compatible HTTP server
async fn start_mcp_container(
    server: &McpTestServer,
) -> Result<ContainerAsync<GenericImage>, Box<dyn std::error::Error + Send + Sync>> {
    let script_escaped = MCP_HTTP_SERVER.replace('\'', "'\\''");

    let image = GenericImage::new("node", "20-alpine")
        .with_exposed_port(3000.tcp())
        .with_wait_for(WaitFor::message_on_stdout("MCP HTTP Server ready"))
        .with_entrypoint("sh")
        .with_cmd(vec![
            "-c".to_string(),
            format!(
                "echo '{}' > /tmp/server.js && node /tmp/server.js",
                script_escaped
            ),
        ]);

    let container = image
        .with_env_var("MCP_SERVER_NAME", server.name)
        .with_env_var("MCP_SERVER_VERSION", server.version)
        .with_env_var("MCP_CAPABILITIES", server.capabilities.join(","))
        .start()
        .await?;

    Ok(container)
}

/// Probe a container and return the result
async fn probe_container(
    container: &ContainerAsync<GenericImage>,
) -> Result<mcpmap::mcp::prober::McpProbeResult, Box<dyn std::error::Error + Send + Sync>> {
    let host = container.get_host().await?;
    let port = container.get_host_port_ipv4(3000.tcp()).await?;

    // Resolve hostname to IP (testcontainers may return "localhost" or similar)
    let ip = resolve_host(&host.to_string())?;

    let prober = McpProber::new(Duration::from_secs(10)).unwrap();
    let target = ScanTarget::new(ip, port);

    Ok(prober.probe(&target).await)
}

/// Resolve a hostname to an IP address
fn resolve_host(host: &str) -> Result<std::net::IpAddr, Box<dyn std::error::Error + Send + Sync>> {
    // Try parsing as IP first
    if let Ok(ip) = host.parse() {
        return Ok(ip);
    }

    // DNS lookup
    use std::net::ToSocketAddrs;
    let addr = format!("{}:0", host)
        .to_socket_addrs()?
        .next()
        .ok_or("Failed to resolve host")?;

    Ok(addr.ip())
}

// ============================================================================
// Real Docker Container Tests - Top 10 MCP Servers
// ============================================================================

#[tokio::test]

async fn test_docker_everything_server() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let server = &MCP_SERVERS[0];
    let container = start_mcp_container(server).await?;
    let result = probe_container(&container).await?;

    assert!(result.is_mcp_server(), "Should detect MCP server");
    assert_eq!(result.server_name(), Some("everything-server"));
    let caps = result
        .server_info
        .as_ref()
        .map(|i| i.capabilities.clone())
        .unwrap_or_default();
    assert!(caps.contains(&"tools".to_string()));
    assert!(caps.contains(&"resources".to_string()));
    assert!(caps.contains(&"prompts".to_string()));

    Ok(())
}

#[tokio::test]

async fn test_docker_memory_server() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let server = &MCP_SERVERS[1];
    let container = start_mcp_container(server).await?;
    let result = probe_container(&container).await?;

    assert!(result.is_mcp_server(), "Should detect MCP server");
    assert_eq!(result.server_name(), Some("memory-server"));

    Ok(())
}

#[tokio::test]

async fn test_docker_filesystem_server() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let server = &MCP_SERVERS[2];
    let container = start_mcp_container(server).await?;
    let result = probe_container(&container).await?;

    assert!(result.is_mcp_server(), "Should detect MCP server");
    assert_eq!(result.server_name(), Some("filesystem-server"));

    Ok(())
}

#[tokio::test]

async fn test_docker_time_server() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let server = &MCP_SERVERS[3];
    let container = start_mcp_container(server).await?;
    let result = probe_container(&container).await?;

    assert!(result.is_mcp_server(), "Should detect MCP server");
    assert_eq!(result.server_name(), Some("time-server"));

    Ok(())
}

#[tokio::test]

async fn test_docker_fetch_server() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let server = &MCP_SERVERS[4];
    let container = start_mcp_container(server).await?;
    let result = probe_container(&container).await?;

    assert!(result.is_mcp_server(), "Should detect MCP server");
    assert_eq!(result.server_name(), Some("fetch-server"));

    Ok(())
}

#[tokio::test]

async fn test_docker_sequential_thinking_server()
-> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let server = &MCP_SERVERS[5];
    let container = start_mcp_container(server).await?;
    let result = probe_container(&container).await?;

    assert!(result.is_mcp_server(), "Should detect MCP server");
    assert_eq!(result.server_name(), Some("sequential-thinking-server"));

    Ok(())
}

#[tokio::test]

async fn test_docker_sqlite_server() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let server = &MCP_SERVERS[6];
    let container = start_mcp_container(server).await?;
    let result = probe_container(&container).await?;

    assert!(result.is_mcp_server(), "Should detect MCP server");
    assert_eq!(result.server_name(), Some("sqlite-server"));

    Ok(())
}

#[tokio::test]

async fn test_docker_git_server() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let server = &MCP_SERVERS[7];
    let container = start_mcp_container(server).await?;
    let result = probe_container(&container).await?;

    assert!(result.is_mcp_server(), "Should detect MCP server");
    assert_eq!(result.server_name(), Some("git-server"));

    Ok(())
}

#[tokio::test]

async fn test_docker_postgres_server() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let server = &MCP_SERVERS[8];
    let container = start_mcp_container(server).await?;
    let result = probe_container(&container).await?;

    assert!(result.is_mcp_server(), "Should detect MCP server");
    assert_eq!(result.server_name(), Some("postgres-mcp"));

    Ok(())
}

#[tokio::test]

async fn test_docker_github_server() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let server = &MCP_SERVERS[9];
    let container = start_mcp_container(server).await?;
    let result = probe_container(&container).await?;

    assert!(result.is_mcp_server(), "Should detect MCP server");
    assert_eq!(result.server_name(), Some("github-mcp"));

    Ok(())
}

// ============================================================================
// Scan Engine Integration Tests with Docker
// ============================================================================

#[tokio::test]

async fn test_docker_scan_engine() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let server = &MCP_SERVERS[0];
    let container = start_mcp_container(server).await?;

    let host = container.get_host().await?;
    let port = container.get_host_port_ipv4(3000.tcp()).await?;

    let scan_config = ScanConfig {
        mode: ScanMode::Fast,
        threads: 10,
        timeout: Duration::from_secs(10),
        show_progress: false,
        rate_limit: 0,
        enumerate: false,
        show_all: false,
        min_confidence: 0,
        deep_probe: false,
        insecure: false,
        scheme: SchemeMode::Http,
        ..Default::default()
    };

    let engine = ScanEngine::new(scan_config, tokio_util::sync::CancellationToken::new())?;
    let ip = resolve_host(&host.to_string())?;
    let results = engine.scan(vec![ip], vec![port]).await;

    assert_eq!(results.len(), 1, "Should find one MCP server");
    assert!(
        results[0]
            .mcp_result
            .as_ref()
            .is_some_and(|m| m.is_mcp_server()),
        "Should detect as MCP server"
    );

    Ok(())
}

// ============================================================================
// Multiple Containers Test
// ============================================================================

#[tokio::test]

async fn test_docker_multiple_servers() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Start 3 different servers
    let servers = [&MCP_SERVERS[0], &MCP_SERVERS[2], &MCP_SERVERS[3]];
    let mut containers = Vec::new();
    let mut targets = Vec::new();

    for server in servers {
        let container = start_mcp_container(server).await?;
        let host = container.get_host().await?;
        let port = container.get_host_port_ipv4(3000.tcp()).await?;
        targets.push((host.to_string(), port));
        containers.push(container);
    }

    let scan_config = ScanConfig {
        mode: ScanMode::Fast,
        threads: 10,
        timeout: Duration::from_secs(10),
        show_progress: false,
        rate_limit: 0,
        enumerate: false,
        show_all: false,
        min_confidence: 0,
        deep_probe: false,
        insecure: false,
        scheme: SchemeMode::Http,
        ..Default::default()
    };

    let engine = ScanEngine::new(scan_config, tokio_util::sync::CancellationToken::new())?;

    // Scan all targets
    let ips: Vec<_> = targets
        .iter()
        .map(|(h, _)| resolve_host(h).unwrap())
        .collect();
    let ports: Vec<_> = targets.iter().map(|(_, p)| *p).collect();

    let results = engine.scan(ips, ports).await;

    assert!(results.len() >= 3, "Should find at least 3 MCP servers");

    Ok(())
}

// ============================================================================
// Auth Detection Test
// ============================================================================

#[tokio::test]
async fn test_docker_auth_without_mcp_hints() -> Result<(), Box<dyn std::error::Error + Send + Sync>>
{
    // Server that returns plain 401 without MCP hints
    // This should NOT be detected as MCP server (prevents false positives)
    let auth_server_script = r#"
        const http = require('http');
        http.createServer((req, res) => {
            res.writeHead(401);
            res.end('Unauthorized');
        }).listen(3000, '0.0.0.0', () => console.log('Auth server ready'));
    "#
    .replace('\'', "'\\''");

    let container = GenericImage::new("node", "20-alpine")
        .with_exposed_port(3000.tcp())
        .with_wait_for(WaitFor::message_on_stdout("Auth server ready"))
        .with_entrypoint("sh")
        .with_cmd(vec![
            "-c".to_string(),
            format!(
                "echo '{}' > /tmp/server.js && node /tmp/server.js",
                auth_server_script
            ),
        ])
        .start()
        .await?;

    let result = probe_container(&container).await?;

    // Without MCP hints, should NOT be confirmed as MCP server
    assert!(
        !result.is_mcp_server(),
        "Plain 401 without MCP hints should not be detected as MCP"
    );
    assert!(result.auth_required, "Should still detect auth requirement");
    assert!(
        result.confidence.score < 30,
        "Should have low confidence without MCP hints"
    );

    Ok(())
}

#[tokio::test]
async fn test_docker_auth_with_mcp_hints() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Server that returns 401 WITH MCP hints (Bearer auth + JSON-RPC error)
    let auth_server_script = r#"
        const http = require('http');
        http.createServer((req, res) => {
            res.writeHead(401, {
                'WWW-Authenticate': 'Bearer realm="MCP Server"',
                'Content-Type': 'application/json'
            });
            res.end(JSON.stringify({
                jsonrpc: '2.0',
                error: { code: -32000, message: 'Unauthorized' }
            }));
        }).listen(3000, '0.0.0.0', () => console.log('Auth MCP server ready'));
    "#
    .replace('\'', "'\\''");

    let container = GenericImage::new("node", "20-alpine")
        .with_exposed_port(3000.tcp())
        .with_wait_for(WaitFor::message_on_stdout("Auth MCP server ready"))
        .with_entrypoint("sh")
        .with_cmd(vec![
            "-c".to_string(),
            format!(
                "echo '{}' > /tmp/server.js && node /tmp/server.js",
                auth_server_script
            ),
        ])
        .start()
        .await?;

    let result = probe_container(&container).await?;

    // With MCP hints, should be detected as likely MCP server
    assert!(result.auth_required, "Should detect auth requirement");
    assert!(
        result.confidence.score >= 30,
        "Should have meaningful confidence with MCP hints"
    );

    Ok(())
}
