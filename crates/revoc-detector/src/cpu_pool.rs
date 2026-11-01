//! Bounded pool for CPU-bound detection work.
//!
//! Regex and ONNX scans run on Tokio's blocking threads, gated by a semaphore
//! sized to the number of CPUs, so they never occupy the async workers and a
//! burst of large bodies queues instead of spawning unbounded threads.

use std::sync::{Arc, LazyLock};

use tokio::sync::Semaphore;

use revoc_core::RevocError;

static CPU_PERMITS: LazyLock<Arc<Semaphore>> = LazyLock::new(|| {
    let n = std::thread::available_parallelism().map_or(4, std::num::NonZeroUsize::get);
    Arc::new(Semaphore::new(n))
});

/// Run `f` on the blocking pool once a CPU permit is free.
///
/// # Errors
/// [`RevocError::Detection`] if the task panics or the pool is shut down.
pub async fn run<F, T>(f: F) -> Result<T, RevocError>
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    let permit = Arc::clone(&CPU_PERMITS)
        .acquire_owned()
        .await
        .map_err(|e| RevocError::Detection(format!("CPU pool closed: {e}")))?;
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        f()
    })
    .await
    .map_err(|e| RevocError::Detection(format!("detection task failed: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn runs_closure_and_returns_value() {
        assert_eq!(run(|| 2 + 2).await.expect("ok"), 4);
    }

    #[tokio::test]
    async fn panicking_task_is_an_error() {
        let res: Result<(), _> = run(|| panic!("boom")).await;
        assert!(matches!(res, Err(RevocError::Detection(_))));
    }
}
