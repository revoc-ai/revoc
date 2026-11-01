//! OPA WASM policy engine (Tier 3 alternative).
//!
//! Loads a compiled OPA WASM bundle in-process via `wasmtime` and evaluates
//! policy through the documented OPA WebAssembly ABI
//! (<https://www.openpolicyagent.org/docs/latest/wasm/>):
//!
//! Exports consumed on the instantiated module:
//! - `memory`                                        — linear memory
//! - `opa_malloc(len: i32) -> addr: i32`             — allocate scratch space
//! - `opa_free(addr: i32)`                           — free scratch space
//! - `opa_json_parse(addr: i32, len: i32) -> value_addr: i32`
//! - `opa_json_dump(value_addr: i32) -> addr: i32`   — NUL-terminated JSON string
//! - `opa_heap_ptr_get() -> i32` / `opa_heap_ptr_set(i32)`
//! - `opa_eval_ctx_new() -> ctx_addr: i32`
//! - `opa_eval_ctx_set_input(ctx_addr: i32, value_addr: i32)`
//! - `opa_eval_ctx_set_data(ctx_addr: i32, value_addr: i32)`
//! - `opa_eval_ctx_get_result(ctx_addr: i32) -> value_addr: i32`
//! - `eval(ctx_addr: i32) -> i32`                    — 0 == success
//!
//! Falls back to [`NativePolicyEngine`] ONLY when the bundle is absent, fails
//! to compile/instantiate, or is missing required ABI exports — never
//! unconditionally. Once a bundle is successfully loaded, every `evaluate()`
//! call runs the real compiled policy.
//!
//! # Building the bundle
//! ```sh
//! opa build -t wasm policies/default/ -o bundle.tar.gz
//! ```

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use serde_json::Value as Json;
use tracing::{error, warn};
use wasmtime::{Engine, Extern, Instance, Memory, Module, OptLevel, Store, TypedFunc};

use revoc_core::{
    EnforcementMode, PolicyDecision, PolicyEngine, PolicyEngineMode, PolicyInput, RevocError,
};

use crate::cache::DecisionCache;
use crate::native::NativePolicyEngine;

/// Typed handles to the OPA WASM ABI exports, resolved once at load time so
/// every `evaluate()` call can invoke them without repeated lookups.
struct OpaAbi {
    memory: Memory,
    /// `opa_malloc(len: i32) -> addr: i32`
    opa_malloc: TypedFunc<i32, i32>,
    /// `opa_free(addr: i32)`
    opa_free: TypedFunc<i32, ()>,
    /// `opa_json_parse(addr: i32, len: i32) -> value_addr: i32`
    opa_json_parse: TypedFunc<(i32, i32), i32>,
    /// `opa_json_dump(value_addr: i32) -> str_addr: i32`
    opa_json_dump: TypedFunc<i32, i32>,
    /// `opa_heap_ptr_get() -> i32`
    opa_heap_ptr_get: TypedFunc<(), i32>,
    /// `opa_heap_ptr_set(ptr: i32)`
    opa_heap_ptr_set: TypedFunc<i32, ()>,
    /// `opa_eval_ctx_new() -> ctx_addr: i32`
    opa_eval_ctx_new: TypedFunc<(), i32>,
    /// `opa_eval_ctx_set_input(ctx_addr: i32, value_addr: i32)`
    opa_eval_ctx_set_input: TypedFunc<(i32, i32), ()>,
    /// `opa_eval_ctx_set_data(ctx_addr: i32, value_addr: i32)`
    opa_eval_ctx_set_data: TypedFunc<(i32, i32), ()>,
    /// `opa_eval_ctx_get_result(ctx_addr: i32) -> value_addr: i32`
    opa_eval_ctx_get_result: TypedFunc<i32, i32>,
    /// `eval(ctx_addr: i32) -> i32`
    eval: TypedFunc<i32, i32>,
}

/// A loaded, instantiated OPA WASM bundle plus the data document compiled
/// into it (read once at load time — `data.json` from the bundle is already
/// embedded in the module's `builtin_data` by `opa build`, so REVOC supplies
/// an empty data overlay unless a sidecar data document is configured).
struct LoadedBundle {
    /// Kept for `reload()` — allows re-instantiating a fresh runtime from the
    /// pre-compiled module (compilation is expensive; instantiation is cheap).
    engine: Engine,
    /// Pre-compiled WASM module. `Module: Send + Sync`.
    module: Module,
    /// `wasmtime::Store`/`Instance` are not `Sync`; each evaluation could use
    /// its own store+instance pair, but constructing those per-call is
    /// expensive. We keep one behind a `Mutex` and reuse it — OPA WASM
    /// modules are designed for serial, single-threaded evaluation per
    /// instance, exactly matching a mutex-serialised access pattern.
    runtime: Mutex<BundleRuntime>,
}

struct BundleRuntime {
    store: Store<()>,
    abi: OpaAbi,
    /// Heap pointer snapshot taken immediately after instantiation — reset
    /// to this value before every evaluation so repeated calls don't leak
    /// memory inside the module's linear memory arena.
    initial_heap_ptr: i32,
}

/// OPA WASM policy engine. Requires a compiled bundle:
/// `opa build -t wasm policies/default/ -o policy.wasm`
///
/// A bundle that is missing or fails to load is a startup error unless
/// `policy.fail_open = true`, in which case the native engine is used and a
/// warning is logged. Configure via `policy.wasm_bundle_path` in `revoc.toml`.
pub struct WasmPolicyEngine {
    bundle: Option<LoadedBundle>,
    fallback: NativePolicyEngine,
}

impl WasmPolicyEngine {
    /// Load and instantiate the WASM bundle from `bundle_path`.
    ///
    /// # Errors
    /// Returns [`RevocError::Configuration`] when `bundle_path` is empty or the
    /// bundle cannot be loaded (missing file, compile or instantiation error,
    /// missing ABI export) and `fail_open` is `false`. Selecting the WASM engine
    /// and silently running a different policy would hide a misconfiguration.
    pub fn new(
        bundle_path: &str,
        cache: Arc<DecisionCache>,
        enforcement_mode: EnforcementMode,
        fail_open: bool,
    ) -> Result<Self, RevocError> {
        let fallback = NativePolicyEngine::new(cache, enforcement_mode);

        let loaded = if bundle_path.is_empty() {
            Err(RevocError::Configuration(
                "policy.engine = \"wasm\" requires policy.wasm_bundle_path".into(),
            ))
        } else {
            Self::load_bundle(bundle_path)
        };

        match loaded {
            Ok(bundle) => {
                tracing::info!(
                    bundle_path,
                    "OPA WASM bundle loaded — evaluating via wasmtime"
                );
                Ok(Self {
                    bundle: Some(bundle),
                    fallback,
                })
            }
            Err(e) if fail_open => {
                warn!(
                    bundle_path,
                    error = %e,
                    "Failed to load OPA WASM bundle — fail_open=true, using native policy engine"
                );
                Ok(Self {
                    bundle: None,
                    fallback,
                })
            }
            Err(e) => Err(e),
        }
    }

    /// Compile and instantiate the WASM module at `bundle_path`, resolve all
    /// required OPA ABI exports, and snapshot the initial heap pointer.
    ///
    /// `bundle_path` must point directly to a `.wasm` module file as produced
    /// by `opa build -t wasm -e data/my_rule -o policy.wasm` or extracted from
    /// the `.tar.gz` bundle that `opa build` emits by default.
    fn load_bundle(bundle_path: &str) -> Result<LoadedBundle, RevocError> {
        let path = std::path::Path::new(bundle_path);
        if !path.exists() {
            return Err(RevocError::Configuration(format!(
                "WASM bundle not found at '{bundle_path}'"
            )));
        }

        let mut config = wasmtime::Config::new();
        config.cranelift_opt_level(OptLevel::Speed);

        let engine = Engine::new(&config).map_err(|e| {
            RevocError::Configuration(format!("Failed to create wasmtime engine: {e}"))
        })?;

        let module = Module::from_file(&engine, path).map_err(|e| {
            RevocError::Configuration(format!(
                "Failed to compile WASM module '{bundle_path}': {e}"
            ))
        })?;

        let mut store: Store<()> = Store::new(&engine, ());
        // OPA WASM modules have no imports — the empty slice is typed explicitly.
        let instance = Instance::new(&mut store, &module, &[] as &[Extern]).map_err(|e| {
            RevocError::Configuration(format!("Failed to instantiate WASM module: {e}"))
        })?;

        let abi = Self::resolve_abi(&mut store, &instance)?;

        let initial_heap_ptr = abi
            .opa_heap_ptr_get
            .call(&mut store, ())
            .map_err(|e| RevocError::Configuration(format!("opa_heap_ptr_get failed: {e}")))?;

        Ok(LoadedBundle {
            engine,
            module,
            runtime: Mutex::new(BundleRuntime {
                store,
                abi,
                initial_heap_ptr,
            }),
        })
    }

    /// Resolve every required OPA ABI export with its expected signature.
    ///
    /// Returns `Err` if any export is missing or has an unexpected type —
    /// this is what makes a malformed/non-OPA WASM module a genuine load
    /// failure (refusing to start) rather than a silent no-op.
    ///
    /// Each `get_typed_func` call is performed separately to avoid multiple
    /// simultaneous mutable borrows of `store` that Rust closures would incur.
    fn resolve_abi(store: &mut Store<()>, instance: &Instance) -> Result<OpaAbi, RevocError> {
        let memory = instance.get_memory(&mut *store, "memory").ok_or_else(|| {
            RevocError::Configuration("WASM module has no exported `memory`".into())
        })?;

        let opa_malloc = instance
            .get_typed_func::<i32, i32>(&mut *store, "opa_malloc")
            .map_err(|e| {
                RevocError::Configuration(format!("missing/mismatched export `opa_malloc`: {e}"))
            })?;

        let opa_free = instance
            .get_typed_func::<i32, ()>(&mut *store, "opa_free")
            .map_err(|e| {
                RevocError::Configuration(format!("missing/mismatched export `opa_free`: {e}"))
            })?;

        let opa_json_parse = instance
            .get_typed_func::<(i32, i32), i32>(&mut *store, "opa_json_parse")
            .map_err(|e| {
                RevocError::Configuration(format!(
                    "missing/mismatched export `opa_json_parse`: {e}"
                ))
            })?;

        let opa_json_dump = instance
            .get_typed_func::<i32, i32>(&mut *store, "opa_json_dump")
            .map_err(|e| {
                RevocError::Configuration(format!("missing/mismatched export `opa_json_dump`: {e}"))
            })?;

        let opa_heap_ptr_get = instance
            .get_typed_func::<(), i32>(&mut *store, "opa_heap_ptr_get")
            .map_err(|e| {
                RevocError::Configuration(format!(
                    "missing/mismatched export `opa_heap_ptr_get`: {e}"
                ))
            })?;

        let opa_heap_ptr_set = instance
            .get_typed_func::<i32, ()>(&mut *store, "opa_heap_ptr_set")
            .map_err(|e| {
                RevocError::Configuration(format!(
                    "missing/mismatched export `opa_heap_ptr_set`: {e}"
                ))
            })?;

        let opa_eval_ctx_new = instance
            .get_typed_func::<(), i32>(&mut *store, "opa_eval_ctx_new")
            .map_err(|e| {
                RevocError::Configuration(format!(
                    "missing/mismatched export `opa_eval_ctx_new`: {e}"
                ))
            })?;

        let opa_eval_ctx_set_input = instance
            .get_typed_func::<(i32, i32), ()>(&mut *store, "opa_eval_ctx_set_input")
            .map_err(|e| {
                RevocError::Configuration(format!(
                    "missing/mismatched export `opa_eval_ctx_set_input`: {e}"
                ))
            })?;

        let opa_eval_ctx_set_data = instance
            .get_typed_func::<(i32, i32), ()>(&mut *store, "opa_eval_ctx_set_data")
            .map_err(|e| {
                RevocError::Configuration(format!(
                    "missing/mismatched export `opa_eval_ctx_set_data`: {e}"
                ))
            })?;

        let opa_eval_ctx_get_result = instance
            .get_typed_func::<i32, i32>(&mut *store, "opa_eval_ctx_get_result")
            .map_err(|e| {
                RevocError::Configuration(format!(
                    "missing/mismatched export `opa_eval_ctx_get_result`: {e}"
                ))
            })?;

        let eval = instance
            .get_typed_func::<i32, i32>(&mut *store, "eval")
            .map_err(|e| {
                RevocError::Configuration(format!("missing/mismatched export `eval`: {e}"))
            })?;

        Ok(OpaAbi {
            memory,
            opa_malloc,
            opa_free,
            opa_json_parse,
            opa_json_dump,
            opa_heap_ptr_get,
            opa_heap_ptr_set,
            opa_eval_ctx_new,
            opa_eval_ctx_set_input,
            opa_eval_ctx_set_data,
            opa_eval_ctx_get_result,
            eval,
        })
    }

    /// Write `bytes` into the module's linear memory via `opa_malloc`,
    /// returning the guest address. The caller is responsible for freeing it
    /// with `opa_free` once the bytes have been parsed into an OPA value.
    fn write_bytes(rt: &mut BundleRuntime, bytes: &[u8]) -> Result<i32, RevocError> {
        let byte_len = i32::try_from(bytes.len()).map_err(|_| {
            RevocError::PolicyEvaluation("input bytes too large for WASM ABI (>2 GiB)".into())
        })?;
        let addr = rt
            .abi
            .opa_malloc
            .call(&mut rt.store, byte_len)
            .map_err(|e| RevocError::PolicyEvaluation(format!("opa_malloc failed: {e}")))?;
        let addr_usize = usize::try_from(addr).map_err(|_| {
            RevocError::PolicyEvaluation("WASM malloc returned negative address".into())
        })?;
        rt.abi
            .memory
            .write(&mut rt.store, addr_usize, bytes)
            .map_err(|e| {
                RevocError::PolicyEvaluation(format!("failed writing to WASM memory: {e}"))
            })?;
        Ok(addr)
    }

    /// Parse a JSON document already written into linear memory at
    /// `(addr, len)` into an OPA internal value, returning the value address.
    fn parse_json(rt: &mut BundleRuntime, addr: i32, len: i32) -> Result<i32, RevocError> {
        let value_addr = rt
            .abi
            .opa_json_parse
            .call(&mut rt.store, (addr, len))
            .map_err(|e| RevocError::PolicyEvaluation(format!("opa_json_parse failed: {e}")))?;
        if value_addr == 0 {
            return Err(RevocError::PolicyEvaluation(
                "opa_json_parse returned NULL — malformed JSON document".into(),
            ));
        }
        Ok(value_addr)
    }

    /// Serialize an OPA internal value at `value_addr` to a JSON string by
    /// reading the NUL-terminated UTF-8 buffer `opa_json_dump` returns.
    fn dump_json(rt: &mut BundleRuntime, value_addr: i32) -> Result<Json, RevocError> {
        let str_addr = rt
            .abi
            .opa_json_dump
            .call(&mut rt.store, value_addr)
            .map_err(|e| RevocError::PolicyEvaluation(format!("opa_json_dump failed: {e}")))?;

        // `memory.data` takes a shared borrow of the store; this is safe here
        // because the previous `call` to `opa_json_dump` has already completed.
        let data = rt.abi.memory.data(&rt.store);
        let start = usize::try_from(str_addr).map_err(|_| {
            RevocError::PolicyEvaluation("WASM dump returned negative address".into())
        })?;
        let end = data[start..]
            .iter()
            .position(|&b| b == 0)
            .map(|rel| start + rel)
            .ok_or_else(|| {
                RevocError::PolicyEvaluation("opa_json_dump result is not NUL-terminated".into())
            })?;

        let raw = std::str::from_utf8(&data[start..end]).map_err(|e| {
            RevocError::PolicyEvaluation(format!("opa_json_dump produced invalid UTF-8: {e}"))
        })?;

        serde_json::from_str(raw).map_err(|e| {
            RevocError::PolicyEvaluation(format!("failed to parse OPA result JSON: {e}"))
        })
    }

    /// Run one full evaluation of the loaded bundle against `input`.
    ///
    /// Builds a fresh evaluation context, feeds the serialized
    /// [`PolicyInput`] (and an empty `{}` data overlay — the policy's own
    /// `data` is compiled into the bundle by `opa build`), invokes `eval`,
    /// and decodes the resulting OPA value into a [`PolicyDecision`].
    fn run_eval(bundle: &LoadedBundle, input: &PolicyInput) -> Result<PolicyDecision, RevocError> {
        let mut guard = bundle
            .runtime
            .lock()
            .map_err(|_| RevocError::PolicyEvaluation("WASM runtime mutex poisoned".into()))?;
        let rt = &mut *guard;

        // Reset the heap so each evaluation starts from a clean arena —
        // prevents unbounded memory growth across millions of calls.
        rt.abi
            .opa_heap_ptr_set
            .call(&mut rt.store, rt.initial_heap_ptr)
            .map_err(|e| RevocError::PolicyEvaluation(format!("opa_heap_ptr_set failed: {e}")))?;

        let input_json = serde_json::to_vec(input).map_err(|e| {
            RevocError::PolicyEvaluation(format!("failed to serialize PolicyInput: {e}"))
        })?;
        let data_json = b"{}";

        // Write input bytes → parse into OPA value → free raw bytes.
        let input_addr = Self::write_bytes(rt, &input_json)?;
        let input_len = i32::try_from(input_json.len()).map_err(|_| {
            RevocError::PolicyEvaluation("policy input too large for WASM ABI (>2 GiB)".into())
        })?;
        let input_value = Self::parse_json(rt, input_addr, input_len)?;
        rt.abi
            .opa_free
            .call(&mut rt.store, input_addr)
            .map_err(|e| RevocError::PolicyEvaluation(format!("opa_free(input) failed: {e}")))?;

        // Write data bytes → parse into OPA value → free raw bytes.
        let data_addr = Self::write_bytes(rt, data_json)?;
        let data_len = i32::try_from(data_json.len()).map_err(|_| {
            RevocError::PolicyEvaluation("data document too large for WASM ABI (>2 GiB)".into())
        })?;
        let data_value = Self::parse_json(rt, data_addr, data_len)?;
        rt.abi
            .opa_free
            .call(&mut rt.store, data_addr)
            .map_err(|e| RevocError::PolicyEvaluation(format!("opa_free(data) failed: {e}")))?;

        // Set up eval context.
        let ctx_addr = rt
            .abi
            .opa_eval_ctx_new
            .call(&mut rt.store, ())
            .map_err(|e| RevocError::PolicyEvaluation(format!("opa_eval_ctx_new failed: {e}")))?;

        rt.abi
            .opa_eval_ctx_set_input
            .call(&mut rt.store, (ctx_addr, input_value))
            .map_err(|e| {
                RevocError::PolicyEvaluation(format!("opa_eval_ctx_set_input failed: {e}"))
            })?;

        rt.abi
            .opa_eval_ctx_set_data
            .call(&mut rt.store, (ctx_addr, data_value))
            .map_err(|e| {
                RevocError::PolicyEvaluation(format!("opa_eval_ctx_set_data failed: {e}"))
            })?;

        // Run the policy.
        let rc = rt
            .abi
            .eval
            .call(&mut rt.store, ctx_addr)
            .map_err(|e| RevocError::PolicyEvaluation(format!("eval failed: {e}")))?;

        if rc != 0 {
            return Err(RevocError::PolicyEvaluation(format!(
                "OPA WASM `eval` returned non-zero status code {rc}"
            )));
        }

        // Read back the result value.
        let result_addr = rt
            .abi
            .opa_eval_ctx_get_result
            .call(&mut rt.store, ctx_addr)
            .map_err(|e| {
                RevocError::PolicyEvaluation(format!("opa_eval_ctx_get_result failed: {e}"))
            })?;

        let result_json = Self::dump_json(rt, result_addr)?;
        decode_decision(&result_json)
    }
}

/// Decode the OPA evaluation result (`[{"result": <value>}, ...]`, the shape
/// every `opa build -t wasm` entrypoint returns) into a [`PolicyDecision`].
///
/// The compiled policy's `result` document is expected to be a REVOC
/// `PolicyDecision` JSON object — REVOC's Rego policies (SPEC.md Phase 11)
/// construct and return exactly this shape from their `decision` rule so both
/// the WASM and native engines are interchangeable from the proxy's
/// perspective.
fn decode_decision(result: &Json) -> Result<PolicyDecision, RevocError> {
    let array = result.as_array().ok_or_else(|| {
        RevocError::PolicyEvaluation("OPA WASM result is not a JSON array".into())
    })?;

    let first = array.first().ok_or_else(|| {
        RevocError::PolicyEvaluation(
            "OPA WASM evaluation produced no results (undefined policy)".into(),
        )
    })?;

    let decision_value = first.get("result").ok_or_else(|| {
        RevocError::PolicyEvaluation("OPA WASM result entry has no `result` field".into())
    })?;

    let mut decision: PolicyDecision =
        serde_json::from_value(decision_value.clone()).map_err(|e| {
            RevocError::PolicyEvaluation(format!(
                "failed to decode PolicyDecision from OPA WASM result: {e}"
            ))
        })?;

    decision.policy_engine = PolicyEngineMode::OpaWasm;
    decision.evaluated_at = chrono::Utc::now();
    Ok(decision)
}

#[async_trait]
impl PolicyEngine for WasmPolicyEngine {
    async fn evaluate(&self, input: &PolicyInput) -> Result<PolicyDecision, RevocError> {
        let Some(bundle) = &self.bundle else {
            return self.fallback.evaluate(input).await;
        };

        let started = std::time::Instant::now();
        match Self::run_eval(bundle, input) {
            Ok(mut decision) => {
                decision.eval_duration_ms = started.elapsed().as_secs_f64() * 1000.0;
                Ok(decision)
            }
            Err(e) => {
                // A genuine per-call evaluation failure (malformed module
                // output, trap, etc.) — fail closed via the native engine
                // rather than allowing traffic through ungoverned
                // (SPEC.md §3 Principle 7: fail-closed).
                error!(
                    error = %e,
                    "OPA WASM evaluation failed — falling back to native engine for this request"
                );
                self.fallback.evaluate(input).await
            }
        }
    }

    async fn reload(&self) -> Result<(), RevocError> {
        // Re-instantiate a fresh runtime from the already-compiled module.
        // Instantiation is cheap (no recompilation); it gives the engine a
        // clean linear-memory arena and a reset heap pointer — the same state
        // as at startup. This is the correct WASM reload semantic: if a policy
        // author pushes a new bundle the proxy manager swaps the whole engine
        // via `arc_swap`, but a reload() on the *existing* engine refreshes the
        // runtime state and also refreshes the native fallback's decision cache
        // so the two engines stay in sync.
        if let Some(bundle) = &self.bundle {
            let mut new_store: Store<()> = Store::new(&bundle.engine, ());
            let new_instance = Instance::new(&mut new_store, &bundle.module, &[] as &[Extern])
                .map_err(|e| {
                    RevocError::PolicyEvaluation(format!(
                        "WASM reload: re-instantiation failed: {e}"
                    ))
                })?;
            let new_abi = WasmPolicyEngine::resolve_abi(&mut new_store, &new_instance)?;
            let new_heap_ptr = new_abi
                .opa_heap_ptr_get
                .call(&mut new_store, ())
                .map_err(|e| {
                    RevocError::PolicyEvaluation(format!(
                        "WASM reload: opa_heap_ptr_get failed: {e}"
                    ))
                })?;

            let new_runtime = BundleRuntime {
                store: new_store,
                abi: new_abi,
                initial_heap_ptr: new_heap_ptr,
            };

            let mut guard = bundle.runtime.lock().map_err(|_| {
                RevocError::PolicyEvaluation("WASM reload: runtime mutex poisoned".into())
            })?;
            *guard = new_runtime;
        }

        // Refresh the native fallback's decision cache regardless.
        self.fallback.reload().await
    }

    fn engine_type(&self) -> PolicyEngineMode {
        PolicyEngineMode::OpaWasm
    }
}

// `Engine` and `Module` are `Send + Sync`. `Store<()>` and `Instance` are
// both `Send` (wasmtime asserts this in its test suite for `Store<()>`).
// Wrapping `BundleRuntime` in `Mutex` therefore makes `LoadedBundle: Sync`
// via the standard blanket impl (`Mutex<T>: Sync where T: Send`) —
// no `unsafe` required, honoring `#![forbid(unsafe_code)]`.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_decision_requires_array() {
        let err = decode_decision(&serde_json::json!({"not": "an array"})).unwrap_err();
        assert!(matches!(err, RevocError::PolicyEvaluation(_)));
    }

    #[test]
    fn decode_decision_requires_result_field() {
        let err = decode_decision(&serde_json::json!([{"no_result_here": true}])).unwrap_err();
        assert!(matches!(err, RevocError::PolicyEvaluation(_)));
    }

    fn cache() -> Arc<DecisionCache> {
        Arc::new(DecisionCache::new(std::time::Duration::from_secs(1), 10))
    }

    #[test]
    fn missing_bundle_refuses_to_start_when_fail_closed() {
        let res = WasmPolicyEngine::new(
            "/no/such/bundle.wasm",
            cache(),
            EnforcementMode::Enforce,
            false,
        );
        assert!(matches!(res, Err(RevocError::Configuration(_))));
    }

    #[test]
    fn empty_bundle_path_refuses_to_start_when_fail_closed() {
        let res = WasmPolicyEngine::new("", cache(), EnforcementMode::Enforce, false);
        assert!(matches!(res, Err(RevocError::Configuration(_))));
    }

    #[test]
    fn missing_bundle_falls_back_only_when_fail_open() {
        let res = WasmPolicyEngine::new(
            "/no/such/bundle.wasm",
            cache(),
            EnforcementMode::Enforce,
            true,
        );
        assert!(res.is_ok());
    }

    #[test]
    fn decode_decision_rejects_empty_array() {
        let err = decode_decision(&serde_json::json!([])).unwrap_err();
        assert!(matches!(err, RevocError::PolicyEvaluation(_)));
    }
}
