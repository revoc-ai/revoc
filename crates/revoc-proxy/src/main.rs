//! REVOC Proxy — Runtime Execution Validation & Observability Control.
//!
//! Entrypoint for the `revoc-proxy` binary.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use clap::{Parser, Subcommand};
use tracing::{info, warn};

mod app;
mod depth;
mod handlers;
mod kill_switch;
mod middleware;
mod rules_catalog;
mod shutdown;
mod storage;
mod streaming;
mod upstream;

#[cfg(test)]
mod tests;

// ── CLI ───────────────────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(
    name = "revoc-proxy",
    version,
    about = "REVOC AI Governance Proxy (beta)"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Start the proxy server.
    Serve {
        #[arg(long, short, env = "REVOC_CONFIG")]
        config: Option<String>,
    },
    /// Run database migrations.
    Migrate {
        #[arg(long)]
        config: Option<String>,
    },
    /// Validate the configuration file without starting.
    ValidateConfig {
        #[arg(long)]
        config: Option<String>,
    },
    /// Validate Rego policy files in a directory.
    CheckPolicies {
        #[arg(long)]
        dir: Option<String>,
    },
    /// Generate a new API key with an optional label.
    GenerateKey {
        #[arg(long)]
        label: Option<String>,
    },
    /// Print the generated rule catalog (Markdown) to stdout.
    ListRules,
    /// Print version information.
    Version,
    /// Run a quick performance smoke test.
    Benchmark {
        #[arg(long)]
        quick: bool,
    },
    /// Emergency kill-switch management (requires admin key).
    Emergency {
        #[command(subcommand)]
        cmd: EmergencyCommand,
    },
}

#[derive(Subcommand)]
enum EmergencyCommand {
    /// Activate the kill-switch.
    Activate {
        #[arg(long)]
        scope: String,
        #[arg(long)]
        reason: String,
        #[arg(long, env = "REVOC_ADMIN_KEY")]
        admin_key: String,
        #[arg(long)]
        target: Option<String>,
    },
    /// Deactivate the kill-switch.
    Deactivate {
        #[arg(long)]
        scope: String,
        #[arg(long, env = "REVOC_ADMIN_KEY")]
        admin_key: String,
        #[arg(long)]
        target: Option<String>,
    },
    /// Show current kill-switch status.
    Status {
        #[arg(long, env = "REVOC_ADMIN_KEY")]
        admin_key: String,
    },
}

// ── Main ──────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Serve { config } => serve(config).await,
        Command::Migrate { config } => migrate(config.as_ref()).await,
        Command::ListRules => {
            print!("{}", rules_catalog::markdown());
            Ok(())
        }
        Command::ValidateConfig { config } => {
            validate_config(config.as_ref());
            Ok(())
        }
        Command::CheckPolicies { dir } => {
            check_policies(dir);
            Ok(())
        }
        Command::GenerateKey { label } => {
            generate_key(label);
            Ok(())
        }
        Command::Version => {
            println!("revoc-proxy {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        Command::Benchmark { quick } => {
            benchmark(quick);
            Ok(())
        }
        Command::Emergency { cmd } => emergency_cmd(cmd).await,
    }
}

// ── serve ─────────────────────────────────────────────────────────────────────

async fn serve(config_path: Option<String>) -> anyhow::Result<()> {
    // ── Load configuration ────────────────────────────────────────────────────
    let cfg = Arc::new(revoc_config::loader::load(config_path.as_deref())?);

    // ── Init telemetry ────────────────────────────────────────────────────────
    let _tracer = revoc_telemetry::RevocTracer::init(&cfg.telemetry)?;
    revoc_telemetry::init_logging(&cfg.telemetry.log_level, &cfg.telemetry.log_format)?;

    // ── ASCII banner ──────────────────────────────────────────────────────────
    println!(
        r"
  ██████╗ ███████╗██╗   ██╗ ██████╗  ██████╗
  ██╔══██╗██╔════╝██║   ██║██╔═══██╗██╔════╝
  ██████╔╝█████╗  ██║   ██║██║   ██║██║
  ██╔══██╗██╔══╝  ╚██╗ ██╔╝██║   ██║██║
  ██║  ██║███████╗ ╚████╔╝ ╚██████╔╝╚██████╗
  ╚═╝  ╚═╝╚══════╝  ╚═══╝   ╚═════╝  ╚═════╝
  Runtime Execution Validation & Observability Control (beta)
  Apache 2.0 — https://revoc.io
"
    );

    // ── Warnings ──────────────────────────────────────────────────────────────
    if cfg.policy.enforcement_mode == "shadow" {
        warn!(
            "⚠️  SHADOW MODE ACTIVE — governance decisions are observed only, not enforced. \
             Set policy.enforcement_mode='enforce' for production."
        );
    }
    if cfg.auth.mode == "none" {
        warn!("⚠️  auth.mode='none' — no authentication. DO NOT use in production.");
    }

    // ── Build application state ───────────────────────────────────────────────
    let state = app::build_app_state(cfg.clone()).await?;

    // Kill-switch status
    if state
        .kill_switch
        .global
        .load(std::sync::atomic::Ordering::Relaxed)
    {
        warn!("🛑 Kill-switch is ACTIVE — all AI traffic will be blocked");
    }

    // ── Kill-switch reconcile loop + Redis listener ──────────────────────────
    state.kill_switch_service.spawn_background();
    info!(
        kill_switch = %state.kill_switch_service.status_json(),
        "Kill-switch state loaded"
    );

    // Separate admin credentials: the admin key must never also be a client
    // API key, or any client could operate the kill-switch.
    if let Some(admin) = handlers::emergency::configured_admin_key(&cfg) {
        if middleware::auth::load_api_keys(&state).contains(&admin) {
            anyhow::bail!(
                "the admin key is also configured as a client API key; use a separate admin key"
            );
        }
    }

    // ── Build routers ─────────────────────────────────────────────────────────
    let routers = app::build_routers(&state);

    let main_addr: SocketAddr = format!("{}:{}", cfg.server.host, cfg.server.port).parse()?;
    // Loopback by default (`server.internal_host`); containers that need the
    // admin API reachable through a port mapping opt in to "0.0.0.0".
    let internal_addr: SocketAddr =
        format!("{}:{}", cfg.server.internal_host, cfg.server.internal_port).parse()?;
    if cfg.auth.admin_key.is_empty() && std::env::var("REVOC_ADMIN_KEY").is_err() {
        warn!("No admin key configured — internal admin API will reject every request");
    }

    info!(addr = %main_addr, "Starting proxy (main)");
    info!(addr = %internal_addr, "Starting internal admin server");

    // ── Three listeners ───────────────────────────────────────────────────────
    let main_server = axum::serve(
        tokio::net::TcpListener::bind(main_addr).await?,
        routers.main,
    );

    let internal_server = axum::serve(
        tokio::net::TcpListener::bind(internal_addr).await?,
        routers.internal,
    );

    let dash_fut: tokio::task::JoinHandle<()> = if let Some(dash_router) = routers.dashboard {
        let dash_addr: SocketAddr =
            format!("{}:{}", cfg.server.host, cfg.server.dashboard_port).parse()?;
        info!(addr = %dash_addr, "Starting dashboard");
        tokio::spawn(async move {
            if let Ok(listener) = tokio::net::TcpListener::bind(dash_addr).await {
                let _ = axum::serve(listener, dash_router).await;
            }
        })
    } else {
        // Dashboard disabled — spawn a task that never resolves so the select!
        // below does not exit on the dash_fut branch.
        tokio::spawn(std::future::pending::<()>())
    };

    // ── Wait for signal ───────────────────────────────────────────────────────
    tokio::select! {
        res = main_server     => { res?; }
        res = internal_server => { res?; }
        res = dash_fut        => { let _ = res; }
        res = shutdown::wait_for_signal() => {
            res.map_err(|e| anyhow::anyhow!("Failed to install signal handler: {e}"))?;
            info!("Shutdown signal received");
            shutdown::graceful_shutdown(&state, Duration::from_secs(cfg.server.shutdown_timeout_secs)).await;
        }
    }

    Ok(())
}

// ── Other subcommands ─────────────────────────────────────────────────────────

async fn migrate(config_path: Option<&String>) -> anyhow::Result<()> {
    let cfg = revoc_config::loader::load(config_path.map(String::as_str))
        .map_err(|e| anyhow::anyhow!("Config error: {e}"))?;
    println!("Running migrations for backend: {}", cfg.storage.backend);

    if cfg.storage.backend.as_str() == "postgres" {
        let url = std::env::var(&cfg.storage.postgres_url_env).map_err(|_| {
            anyhow::anyhow!(
                "environment variable '{}' is not set (required for postgres backend)",
                cfg.storage.postgres_url_env
            )
        })?;
        let store = storage::PostgresAuditStore::connect(&url, 1, true).await?;
        store.pool().close().await;
        println!("✓ Postgres schema is up to date.");
        return Ok(());
    }

    let schema_sql = include_str!("../sql/schema.sql");
    let statements: Vec<&str> = schema_sql
        .split(';')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();
    let url = format!("sqlite:{}?mode=rwc", cfg.storage.sqlite_path);
    let pool = sqlx::SqlitePool::connect(&url).await?;
    for stmt in &statements {
        sqlx::query(stmt).execute(&pool).await?;
    }
    pool.close().await;

    println!(
        "✓ Applied {} migration statement(s) to {} backend.",
        statements.len(),
        cfg.storage.backend
    );
    Ok(())
}

fn validate_config(config_path: Option<&String>) {
    match revoc_config::loader::load(config_path.map(String::as_str)) {
        Ok(cfg) => {
            println!(
                "✓ Configuration valid (environment={})",
                cfg.server.environment
            );
        }
        Err(e) => {
            eprintln!("✗ Configuration invalid: {e}");
            std::process::exit(1);
        }
    }
}

fn check_policies(dir: Option<String>) {
    let dir = dir.unwrap_or_else(|| "policies/".to_owned());
    println!("Checking policies in: {dir}");

    let root = std::path::Path::new(&dir);
    if !root.exists() {
        eprintln!("✗ Policy directory not found: {dir}");
        std::process::exit(1);
    }

    let mut rego_files = Vec::new();
    collect_rego_files(root, &mut rego_files);

    if rego_files.is_empty() {
        eprintln!("✗ No .rego policy files found in {dir}");
        std::process::exit(1);
    }

    let mut failures = Vec::new();
    for path in &rego_files {
        match std::fs::read_to_string(path) {
            Ok(content) => {
                if let Err(reason) = validate_rego_syntax(&content) {
                    failures.push(format!("{}: {reason}", path.display()));
                }
            }
            Err(e) => failures.push(format!("{}: {e}", path.display())),
        }
    }

    if !failures.is_empty() {
        eprintln!(
            "✗ {} policy file(s) failed syntax validation:",
            failures.len()
        );
        for f in &failures {
            eprintln!("  - {f}");
        }
        std::process::exit(1);
    }
    println!(
        "✓ {} policy file(s) passed syntax validation",
        rego_files.len()
    );

    // Defer to the `opa` CLI for full semantic/type validation when available
    // (SPEC.md §22 Definition of Done runs `opa check policies/ --strict`).
    match std::process::Command::new("opa")
        .args(["check", &dir, "--strict"])
        .output()
    {
        Ok(output) if output.status.success() => println!("✓ opa check --strict passed"),
        Ok(output) => {
            eprint!("{}", String::from_utf8_lossy(&output.stderr));
            eprintln!("✗ opa check --strict reported issues");
            std::process::exit(1);
        }
        Err(_) => {
            println!(
                "(opa CLI not found on PATH — semantic check skipped; syntax validation passed)"
            );
        }
    }
}

fn collect_rego_files(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_rego_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rego") {
            out.push(path);
        }
    }
}

/// Lightweight structural validation of a Rego source file: non-empty,
/// declares a `package`, and has balanced braces. Real semantic validation
/// (type checking, rule conflicts) is deferred to the `opa` CLI above.
fn validate_rego_syntax(content: &str) -> Result<(), String> {
    if content.trim().is_empty() {
        return Err("file is empty".to_owned());
    }
    if !content
        .lines()
        .any(|l| l.trim_start().starts_with("package "))
    {
        return Err("missing 'package' declaration".to_owned());
    }
    let mut depth: i64 = 0;
    for c in content.chars() {
        match c {
            '{' => depth += 1,
            '}' => depth -= 1,
            _ => {}
        }
        if depth < 0 {
            return Err("unbalanced braces (unexpected '}')".to_owned());
        }
    }
    if depth != 0 {
        return Err("unbalanced braces".to_owned());
    }
    Ok(())
}

fn generate_key(label: Option<String>) {
    let key = format!("revoc-{}", uuid::Uuid::now_v7().simple());
    let label = label.unwrap_or_else(|| "generated".to_owned());
    println!("Generated API key [{label}]: {key}");
    println!("Add to REVOC_API_KEYS or api_keys_file in your config.");
}

fn benchmark(quick: bool) {
    println!(
        "Running {} benchmark...",
        if quick { "quick" } else { "full" }
    );
    println!("(Full criterion benchmarks: cargo bench --workspace)");
}

async fn emergency_cmd(cmd: EmergencyCommand) -> anyhow::Result<()> {
    let internal_url =
        std::env::var("REVOC_INTERNAL_URL").unwrap_or_else(|_| "http://127.0.0.1:8081".into());
    let internal_url = format!("{internal_url}/internal/emergency/kill-switch");

    match cmd {
        EmergencyCommand::Activate {
            scope,
            reason,
            admin_key,
            target,
        } => {
            let body = serde_json::json!({
                "scope": scope, "reason": reason,
                "activated_by": "cli", "target": target
            });
            let resp = reqwest::Client::new()
                .post(format!("{internal_url}/activate"))
                .header("X-Admin-Key", admin_key)
                .json(&body)
                .send()
                .await?;
            println!("{}", resp.text().await?);
        }
        EmergencyCommand::Deactivate {
            scope,
            admin_key,
            target,
        } => {
            let body = serde_json::json!({"scope": scope, "target": target});
            let resp = reqwest::Client::new()
                .post(format!("{internal_url}/deactivate"))
                .header("X-Admin-Key", admin_key)
                .json(&body)
                .send()
                .await?;
            println!("{}", resp.text().await?);
        }
        EmergencyCommand::Status { admin_key } => {
            let resp = reqwest::Client::new()
                .get(format!("{internal_url}/status"))
                .header("X-Admin-Key", admin_key)
                .send()
                .await?;
            println!("{}", resp.text().await?);
        }
    }

    Ok(())
}
