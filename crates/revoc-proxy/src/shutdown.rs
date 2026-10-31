//! Graceful shutdown for the REVOC proxy.

use std::time::Duration;

use revoc_core::RevocError;
use tracing::{info, warn};

use crate::app::AppState;

/// Wait for SIGTERM or SIGINT.
///
/// Returns when either signal is received. Returns an error if the OS
/// signal handlers cannot be installed (e.g. file-descriptor exhaustion);
/// callers should treat this as fatal and exit rather than run un-shutdownable.
pub async fn wait_for_signal() -> Result<(), RevocError> {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};

        let mut sigterm = signal(SignalKind::terminate()).map_err(RevocError::Io)?;
        let mut sigint = signal(SignalKind::interrupt()).map_err(RevocError::Io)?;

        tokio::select! {
            _ = sigterm.recv() => { info!("SIGTERM received — initiating graceful shutdown"); }
            _ = sigint.recv()  => { info!("SIGINT received — initiating graceful shutdown"); }
        }
    }

    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c().await.map_err(RevocError::Io)?;
        info!("Ctrl-C received — initiating graceful shutdown");
    }

    Ok(())
}

/// Perform a graceful shutdown sequence.
///
/// 1. Stop accepting new requests (handled by axum's graceful-shutdown)
/// 2. Wait for in-flight requests to complete (up to `timeout`)
/// 3. Drain in-flight async audit writes
/// 4. Log "Shutdown complete"
pub async fn graceful_shutdown(state: &AppState, timeout: Duration) {
    info!("Graceful shutdown started (timeout: {}s)", timeout.as_secs());

    // Give in-flight requests time to complete
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Drain in-flight audit-event writes (SPEC.md §23 Rule 25/26 — async,
    // batched writes must not be dropped on the floor at shutdown).
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let pending = state.pending_audit_writes.load(std::sync::atomic::Ordering::SeqCst);
        if pending == 0 {
            break;
        }
        if tokio::time::Instant::now() >= deadline {
            warn!(pending, "Shutdown timeout reached with audit writes still in flight");
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    info!("Shutdown complete.");
}
