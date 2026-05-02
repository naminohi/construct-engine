/// Thin bridge from construct-engine to construct-core's `Orchestrator`.
///
/// The `Orchestrator` is a sync, in-memory state machine — it never does I/O.
/// We wrap it in `Arc<StdMutex>` so the tokio event loop can share it across
/// async handler functions without holding the lock across `.await` points.
///
/// Usage pattern (always release the lock before any `.await`):
/// ```rust
/// let actions = {
///     let mut orch = core.lock().unwrap();
///     orch.handle_event(event)
/// };
/// // process actions (no lock held here)
/// ```
use std::sync::{Arc, Mutex};

use construct_core::{
    cfe::{CfeMessageType, CfePrivateKeysV1, decode_as},
    crypto::{client_api::ClassicClient, suites::classic::ClassicSuiteProvider},
    orchestration::{Action, Orchestrator},
};

use crate::error::EngineError;

pub use construct_core::orchestration::Action as CoreAction;
pub use construct_core::orchestration::IncomingEvent as CoreEvent;

/// Shared handle to the Orchestrator — clone-able, thread-safe.
pub type CoreHandle = Arc<Mutex<Orchestrator>>;

/// Build an `Orchestrator` from a CFE-encoded private key blob.
///
/// Returns `Err` if the blob is malformed or the keys are invalid.
/// Returns `Ok(None)` if `keys_cfe_data` is empty (fresh install / unregistered).
pub fn build_core(keys_cfe_data: &[u8], user_id: &str) -> Result<Option<CoreHandle>, EngineError> {
    if keys_cfe_data.is_empty() {
        return Ok(None);
    }

    let decoded = decode_as::<CfePrivateKeysV1>(keys_cfe_data, CfeMessageType::PrivateKeys)
        .map_err(|e| EngineError::crypto(format!("decode private keys: {e}")))?;

    let client = ClassicClient::<ClassicSuiteProvider>::from_keys(
        decoded.ik_priv.into_vec(),
        decoded.sk_priv.into_vec(),
        decoded.spk_priv.into_vec(),
        decoded.spk_sig.into_vec(),
    )
    .map_err(|e| EngineError::crypto(format!("build crypto client: {e}")))?;

    let orchestrator = Orchestrator::new(client, user_id.to_string());
    tracing::info!(user_id, "OrchestratorCore initialised");
    Ok(Some(Arc::new(Mutex::new(orchestrator))))
}

/// Feed an event into the orchestrator and collect resulting actions.
/// The lock is acquired and released within this function — safe to call
/// from async context as long as the calling code does not hold other locks.
pub fn dispatch_to_core(core: &CoreHandle, event: CoreEvent) -> Vec<Action> {
    let mut orch = core.lock().unwrap_or_else(|p| p.into_inner());
    orch.handle_event(event)
}
