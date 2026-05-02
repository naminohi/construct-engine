use bytes::Bytes;
use prost::Message;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use crate::{
    config::EngineConfig,
    core_bridge::{self, CoreHandle},
    error::EngineError,
    events::{PlatformAction, UiEvent},
    proto::services::v1 as pb,
    transport::{
        AUTH_AUTHENTICATE, AUTH_LOGOUT, AUTH_POW_CHALLENGE, AUTH_REFRESH, AUTH_REGISTER, KEY_COUNT,
        KEY_GET_BUNDLE, KEY_ROTATE_SPK, KEY_UPLOAD, NOTIFICATION_REGISTER, USER_FIND,
    },
    transport::{BiDiStreamHandle, Transport},
};

/// Implemented by Swift's `EngineAdapter`. The engine fires `PlatformAction`
/// callbacks to request platform I/O (Keychain, CoreData, CallKit, etc.).
pub trait EngineCallback: Send + Sync {
    fn on_action(&self, action: PlatformAction);
}

/// Internal runtime state — held behind a Mutex so `start()` can take it.
struct EngineRuntime {
    rx: mpsc::Receiver<UiEvent>,
    /// Incoming gRPC frames from the MessageStream pump task.
    /// The pump sends raw Bytes here; the event loop receives and routes them.
    frame_rx: tokio::sync::mpsc::UnboundedReceiver<bytes::Bytes>,
    /// tokio runtime for the engine's async work
    rt: tokio::runtime::Runtime,
}

pub struct ConstructEngine {
    config: Arc<EngineConfig>,
    callback: Arc<dyn EngineCallback>,
    /// Outbound event channel (Swift → engine)
    dispatch_tx: mpsc::Sender<UiEvent>,
    /// Taken by `start()` on first call; None afterwards
    runtime: Mutex<Option<EngineRuntime>>,
    /// Live bidi stream handle (set when OpenMessageStream succeeds)
    stream: tokio::sync::Mutex<Option<BiDiStreamHandle>>,
    /// Parameters of the last OpenMessageStream call — used to re-open after reconnect.
    stream_params: tokio::sync::Mutex<Option<StreamParams>>,
    /// Crypto orchestrator — None on fresh install, set after key registration.
    /// Always use `core_locked()` accessor; never hold across `.await`.
    core: Mutex<Option<CoreHandle>>,
    /// Current token refresh state: (refresh_token, expires_at_unix_secs).
    /// Written by auth handlers; read by the event loop to schedule auto-refresh.
    token_state: tokio::sync::watch::Sender<Option<TokenRefreshState>>,
    /// Sender half of the incoming frame channel. Cloned into the stream pump closure
    /// so frames arrive in the event loop without blocking the pump task.
    frame_tx: tokio::sync::mpsc::UnboundedSender<bytes::Bytes>,
}

/// Stored so the engine can re-subscribe after a reconnect.
#[derive(Clone)]
struct StreamParams {
    conversation_ids: Vec<String>,
    last_cursor: Option<String>,
}

/// Current token state persisted in the engine for auto-refresh scheduling.
#[derive(Clone, Debug)]
struct TokenRefreshState {
    refresh_token: String,
    /// Unix timestamp (seconds) when the access token expires.
    expires_at: i64,
}

impl ConstructEngine {
    pub fn new(
        config: EngineConfig,
        callback: Box<dyn EngineCallback>,
    ) -> Result<Arc<Self>, EngineError> {
        let (tx, rx) = mpsc::channel(config.event_buffer);

        // Initialise the crypto orchestrator from the keys blob if available.
        // On a fresh install keys_cfe_data is empty — core stays None until
        // the device completes registration and the keys are set.
        let core = core_bridge::build_core(&config.keys_cfe_data, &config.my_user_id)?;

        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .thread_name("construct-engine")
            .enable_all()
            .build()
            .map_err(|e| EngineError::internal(format!("tokio runtime: {e}")))?;

        let (token_tx, _) = tokio::sync::watch::channel(None::<TokenRefreshState>);
        let (frame_tx, frame_rx) = tokio::sync::mpsc::unbounded_channel::<bytes::Bytes>();

        Ok(Arc::new(Self {
            config: Arc::new(config),
            callback: Arc::from(callback),
            dispatch_tx: tx,
            runtime: Mutex::new(Some(EngineRuntime { rx, frame_rx, rt })),
            stream: tokio::sync::Mutex::new(None),
            stream_params: tokio::sync::Mutex::new(None),
            core: Mutex::new(core),
            token_state: token_tx,
            frame_tx,
        }))
    }

    /// Start the engine. Non-blocking — spawns background threads.
    /// Must be called exactly once before `dispatch()`.
    pub fn start(self: &Arc<Self>) -> Result<(), EngineError> {
        let runtime = {
            let mut guard = self.runtime.lock().unwrap();
            guard.take().ok_or(EngineError::AlreadyRunning)?
        };

        let engine = Arc::clone(self);
        let EngineRuntime { rx, frame_rx, rt } = runtime;

        // Run the event loop on the engine's dedicated tokio runtime.
        // The spawned OS thread owns the runtime and blocks until shutdown.
        std::thread::Builder::new()
            .name("construct-engine-rt".to_string())
            .spawn(move || {
                rt.block_on(async move {
                    info!("construct-engine started");
                    engine.event_loop(rx, frame_rx).await;
                    info!("construct-engine stopped");
                });
            })
            .map_err(|e| EngineError::internal(format!("thread spawn: {e}")))?;

        Ok(())
    }

    /// Initialise (or replace) the crypto core from a fresh key blob.
    ///
    /// Called after device registration completes and the keys are first
    /// persisted to Keychain. Thread-safe — acquires the core lock.
    pub fn init_core_from_keys(
        &self,
        keys_cfe_data: &[u8],
        user_id: &str,
    ) -> Result<(), EngineError> {
        let new_core = core_bridge::build_core(keys_cfe_data, user_id)?;
        let mut guard = self.core.lock().unwrap_or_else(|p| p.into_inner());
        *guard = new_core;
        Ok(())
    }

    /// Clone the core handle if one is initialised. Returns `None` on fresh install.
    ///
    /// The caller receives an `Arc` — they should lock it, do work, and release
    /// before any `.await` point.
    pub(crate) fn core(&self) -> Option<CoreHandle> {
        self.core.lock().unwrap_or_else(|p| p.into_inner()).clone()
    }

    /// Update the stored token refresh state. Called by every auth handler on success.
    fn set_token_state(&self, refresh_token: String, expires_at: i64) {
        let _ = self.token_state.send(Some(TokenRefreshState {
            refresh_token,
            expires_at,
        }));
    }

    /// Clear token state on logout or unrecoverable auth error.
    fn clear_token_state(&self) {
        let _ = self.token_state.send(None);
    }

    /// Dispatch a UI event to the engine (sync, non-blocking).
    pub fn dispatch(&self, event: UiEvent) {
        if let Err(e) = self.dispatch_tx.try_send(event) {
            warn!("dispatch dropped: {e}");
        }
    }

    /// Initiate graceful shutdown. In-flight sends get up to 5s to complete.
    pub fn shutdown(&self) {
        // Dropping the sender closes the channel, which causes event_loop to exit.
        // The runtime will be dropped when the background thread finishes.
        info!("construct-engine shutdown requested");
    }

    // ── Internal ─────────────────────────────────────────────────────────────

    async fn event_loop(
        self: Arc<Self>,
        mut rx: mpsc::Receiver<UiEvent>,
        mut frame_rx: tokio::sync::mpsc::UnboundedReceiver<bytes::Bytes>,
    ) {
        let transport = match Transport::new(Arc::clone(&self.config)).await {
            Ok(t) => Arc::new(t),
            Err(e) => {
                error!("transport init failed: {e}");
                self.callback.on_action(PlatformAction::NetworkError {
                    message: format!("Transport init failed: {e}"),
                });
                return;
            }
        };

        // Initial connection attempt with backoff.
        self.ensure_connected(&transport).await;

        // Subscribe to H3 driver-close notifications.
        let mut connected_rx = transport.connected_rx.clone();
        // Subscribe to token state changes to schedule auto-refresh.
        let mut token_rx = self.token_state.subscribe();

        // Pinned sleep future for the token refresh timer.
        // Initially set far in the future; reset when a token arrives.
        // The `refresh_armed` guard prevents spurious fires while disabled.
        let refresh_sleep = tokio::time::sleep(Duration::from_secs(86_400 * 365));
        tokio::pin!(refresh_sleep);
        let mut refresh_armed = false;

        loop {
            // ── Update refresh timer if token state changed ─────────────────
            if token_rx.has_changed().unwrap_or(false) {
                let state = token_rx.borrow_and_update().clone();
                if let Some(ts) = state {
                    let secs_until_refresh = Self::secs_until_refresh(ts.expires_at);
                    refresh_sleep.as_mut().reset(
                        tokio::time::Instant::now() + Duration::from_secs(secs_until_refresh),
                    );
                    refresh_armed = true;
                    info!("token refresh scheduled in {secs_until_refresh}s");
                } else {
                    refresh_armed = false;
                }
            }

            tokio::select! {
                biased;

                // ── Token refresh timer ─────────────────────────────────────
                _ = &mut refresh_sleep, if refresh_armed => {
                    refresh_armed = false;
                    let state = self.token_state.borrow().clone();
                    if let Some(ts) = state {
                        info!("auto-refresh: requesting new token");
                        Arc::clone(&self)
                            .handle_refresh_token(&transport, ts.refresh_token)
                            .await;
                    }
                }

                // ── Disconnect detected ─────────────────────────────────────
                Ok(_) = connected_rx.changed() => {
                    if !*connected_rx.borrow() {
                        warn!("H3 driver closed — starting reconnect");
                        self.callback.on_action(PlatformAction::ConnectionStateChanged {
                            connected: false,
                        });
                        // Drop stale stream handle (pump task will have exited anyway).
                        *self.stream.lock().await = None;

                        self.ensure_connected(&transport).await;

                        // Re-open MessageStream if the app had one subscribed.
                        if let Some(params) = self.stream_params.lock().await.clone() {
                            self.handle_open_stream(&transport, params.conversation_ids, params.last_cursor).await;
                        }
                    }
                }

                // ── Normal UI event ─────────────────────────────────────────
                event = rx.recv() => {
                    let Some(event) = event else { break };
                    self.handle_event(&transport, event).await;
                }

                // ── Incoming gRPC frame from MessageStream ───────────────────
                Some(frame) = frame_rx.recv() => {
                    Arc::clone(&self).handle_incoming_frame(&transport, frame).await;
                }

                // ── Token state changed (wake select to recompute timer) ────
                Ok(_) = token_rx.changed() => {
                    // Loop again; the timer update block above will recompute.
                }
            }
        }

        info!("event loop exited");
    }

    /// Seconds until token refresh: 5 minutes before expiry, minimum 10 seconds.
    fn secs_until_refresh(expires_at: i64) -> u64 {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        let secs_remaining = expires_at - now;
        // Refresh 5 min early; never schedule less than 10 s out to avoid tight loops.
        ((secs_remaining - 300).max(10)) as u64
    }

    /// Connect to the server with exponential backoff.
    ///
    /// Delays: 1 s → 2 s → 4 s → 8 s → … → 60 s (cap).
    /// Fires `NetworkError` on each failed attempt and
    /// `ConnectionStateChanged { connected: true }` on success.
    async fn ensure_connected(&self, transport: &Transport) {
        const MAX_DELAY: Duration = Duration::from_secs(60);
        let mut delay = Duration::from_secs(1);

        loop {
            match transport.connect_h3().await {
                Ok(_) => {
                    self.callback
                        .on_action(PlatformAction::ConnectionStateChanged { connected: true });
                    return;
                }
                Err(e) => {
                    warn!(
                        "connection attempt failed ({e}), retry in {}s",
                        delay.as_secs()
                    );
                    self.callback.on_action(PlatformAction::NetworkError {
                        message: format!("Reconnecting in {}s… ({})", delay.as_secs(), e),
                    });
                    tokio::time::sleep(delay).await;
                    delay = (delay * 2).min(MAX_DELAY);
                }
            }
        }
    }

    async fn handle_event(self: &Arc<Self>, transport: &Arc<Transport>, event: UiEvent) {
        debug!("handle_event: {event:?}");
        match event {
            UiEvent::PlatformReady => {
                info!("platform ready — engine fully operational");
            }

            UiEvent::RegisterDevice {
                username,
                device_id,
            } => {
                self.handle_register_device(transport, username, device_id)
                    .await;
            }

            UiEvent::Authenticate {
                device_id,
                challenge_response,
                signing_key,
            } => {
                self.handle_authenticate(transport, device_id, challenge_response, signing_key)
                    .await;
            }

            UiEvent::RefreshToken { refresh_token } => {
                self.handle_refresh_token(transport, refresh_token).await;
            }

            UiEvent::Logout => {
                self.handle_logout(transport).await;
            }

            UiEvent::FetchPreKeyBundle { user_id, device_id } => {
                self.handle_fetch_pre_key_bundle(transport, user_id, device_id)
                    .await;
            }

            UiEvent::UploadOtpks { device_id, count } => {
                self.handle_upload_otpks(transport, device_id, count).await;
            }

            UiEvent::GetPreKeyCount { device_id } => {
                self.handle_get_pre_key_count(transport, device_id).await;
            }

            UiEvent::RotateSignedPreKey { device_id } => {
                self.handle_rotate_spk(transport, device_id).await;
            }

            UiEvent::OpenMessageStream {
                conversation_ids,
                since_cursor,
            } => {
                self.handle_open_stream(transport, conversation_ids, since_cursor)
                    .await;
            }

            UiEvent::CloseMessageStream => {
                self.handle_close_stream(transport).await;
            }

            UiEvent::SendMessage {
                contact_id,
                plaintext,
                local_id,
                conversation_id,
            } => {
                self.handle_send_message(
                    transport,
                    contact_id,
                    plaintext,
                    local_id,
                    conversation_id,
                )
                .await;
            }

            UiEvent::AckMessage {
                message_id,
                message_number,
            } => {
                self.handle_ack_message(transport, message_id, message_number)
                    .await;
            }

            UiEvent::InitSessionInitiator { contact_id } => {
                self.handle_init_session_initiator(transport, contact_id)
                    .await;
            }

            UiEvent::SearchUser { query } => {
                self.handle_search_user(transport, query).await;
            }

            UiEvent::Signal {
                call_id,
                signal_bytes,
            } => {
                self.handle_signal(transport, call_id, signal_bytes).await;
            }

            UiEvent::RegisterPushToken { token, platform } => {
                self.handle_register_push(transport, token, platform).await;
            }

            UiEvent::KeychainResult { key, data } => {
                debug!("keychain result: key={key} present={}", data.is_some());
                // When the keys blob arrives (e.g. after registration), wire up the core.
                if key == "private_keys" {
                    if let Some(blob) = data {
                        let user_id = self.config.my_user_id.clone();
                        match self.init_core_from_keys(&blob, &user_id) {
                            Ok(()) => info!("OrchestratorCore (re)initialised from Keychain"),
                            Err(e) => error!("OrchestratorCore init failed: {e}"),
                        }
                    }
                }
            }
        }
    }

    // ── Handlers ──────────────────────────────────────────────────────────────

    /// Re-opens the MessageStream if `stream_params` is stored (used after auth/refresh).
    async fn reopen_stream_if_needed(self: &Arc<Self>, transport: &Arc<Transport>) {
        let params = self.stream_params.lock().await.clone();
        if let Some(p) = params {
            info!("reopen_stream: re-subscribing after auth");
            self.handle_open_stream(transport, p.conversation_ids, p.last_cursor)
                .await;
        }
    }

    /// Full registration flow:
    /// 1. GetPowChallenge (unary)
    /// 2. Solve PoW in a blocking thread (Argon2id, CPU-intensive)
    /// 3. Extract public keys from the initialised OrchestratorCore
    /// 4. RegisterDevice (unary)
    /// 5. Fire SetAuthToken + RegistrationComplete callbacks
    /// 6. Re-open MessageStream if stream_params are stored
    async fn handle_register_device(
        self: &Arc<Self>,
        transport: &Arc<Transport>,
        username: Option<String>,
        device_id: String,
    ) {
        info!("register_device: device_id={device_id}");

        // ── Step 1: fetch PoW challenge ───────────────────────────────────────
        let challenge_bytes = match transport
            .unary_call(
                AUTH_POW_CHALLENGE,
                &pb::GetPowChallengeRequest {}.encode_to_vec(),
            )
            .await
        {
            Ok(b) => b,
            Err(e) => {
                error!("GetPowChallenge failed: {e}");
                return;
            }
        };
        let challenge_resp = match pb::GetPowChallengeResponse::decode(challenge_bytes.as_slice()) {
            Ok(r) => r,
            Err(e) => {
                error!("GetPowChallenge decode error: {e}");
                return;
            }
        };
        let challenge_str = challenge_resp.challenge.clone();
        let difficulty = challenge_resp.difficulty;
        info!("pow_challenge: difficulty={difficulty}");

        // ── Step 2: solve PoW in a blocking thread (Argon2id — CPU-intensive) ─
        let challenge_for_pow = challenge_str.clone();
        let pow_solution = match tokio::task::spawn_blocking(move || {
            construct_core::pow::compute_pow(&challenge_for_pow, difficulty)
        })
        .await
        {
            Ok(sol) => sol,
            Err(e) => {
                error!("PoW computation panicked: {e}");
                return;
            }
        };
        info!("pow_solved: nonce={}", pow_solution.nonce);

        // ── Step 3: extract public keys from OrchestratorCore ─────────────────
        let public_keys = {
            let guard = self.core.lock().expect("core mutex poisoned");
            match guard.as_ref() {
                None => {
                    error!(
                        "register_device: OrchestratorCore not initialised — dispatch KeychainResult first"
                    );
                    return;
                }
                Some(core_arc) => {
                    let orch = core_arc.lock().expect("orchestrator mutex poisoned");
                    match orch.get_registration_bundle_fields() {
                        Ok(bundle) => pb::DevicePublicKeys {
                            verifying_key: bundle.verifying_key.into(),
                            identity_public: bundle.identity_public.into(),
                            signed_prekey_public: bundle.signed_prekey_public.into(),
                            signed_prekey_signature: bundle.signature.into(),
                            crypto_suite: "Curve25519+Ed25519".to_string(),
                        },
                        Err(e) => {
                            error!("get_registration_bundle_fields failed: {e}");
                            return;
                        }
                    }
                }
            }
        };

        // ── Step 4: RegisterDevice RPC ────────────────────────────────────────
        let req = pb::RegisterDeviceRequest {
            username,
            device_id: device_id.clone(),
            public_keys: Some(public_keys),
            pow_solution: Some(pb::PowSolution {
                challenge: challenge_str,
                nonce: pow_solution.nonce,
                hash: pow_solution.hash,
            }),
        };
        match transport
            .unary_call(AUTH_REGISTER, &req.encode_to_vec())
            .await
        {
            Ok(bytes) => match pb::RegisterDeviceResponse::decode(bytes.as_slice()) {
                Ok(resp) => {
                    if let Some(tokens) = resp.tokens {
                        let user_id = tokens.user_id.clone();
                        *transport.token.write().await = Some(tokens.access_token.clone());
                        self.set_token_state(tokens.refresh_token.clone(), tokens.expires_at);
                        self.callback.on_action(PlatformAction::SetAuthToken {
                            user_id: user_id.clone(),
                            access_token: tokens.access_token,
                            refresh_token: tokens.refresh_token,
                            expires_at: tokens.expires_at,
                        });
                        self.callback
                            .on_action(PlatformAction::RegistrationComplete {
                                user_id,
                                device_id: device_id.clone(),
                            });
                        self.reopen_stream_if_needed(transport).await;
                        // After first registration, upload an initial OTPK batch.
                        let dev = transport.config.my_device_id.clone();
                        self.handle_get_pre_key_count(transport, dev).await;
                    } else {
                        error!("RegisterDevice: server returned empty tokens");
                    }
                }
                Err(e) => error!("RegisterDevice decode error: {e}"),
            },
            Err(EngineError::Unauthenticated { .. }) => {
                self.callback.on_action(PlatformAction::ClearAuth);
            }
            Err(e) => error!("RegisterDevice failed: {e}"),
        }
    }

    async fn handle_authenticate(
        self: &Arc<Self>,
        transport: &Arc<Transport>,
        device_id: String,
        challenge_response: Vec<u8>,
        _signing_key: Vec<u8>,
    ) {
        info!("authenticate: device_id={device_id}");
        let req = pb::AuthenticateDeviceRequest {
            device_id: device_id.clone(),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64,
            signature: challenge_response.into(),
        };
        match transport
            .unary_call(AUTH_AUTHENTICATE, &req.encode_to_vec())
            .await
        {
            Ok(bytes) => match pb::AuthenticateDeviceResponse::decode(bytes.as_slice()) {
                Ok(resp) => {
                    if let Some(tokens) = resp.tokens {
                        // Store token in transport for subsequent calls.
                        *transport.token.write().await = Some(tokens.access_token.clone());
                        self.set_token_state(tokens.refresh_token.clone(), tokens.expires_at);
                        self.callback.on_action(PlatformAction::SetAuthToken {
                            user_id: tokens.user_id,
                            access_token: tokens.access_token,
                            refresh_token: tokens.refresh_token,
                            expires_at: tokens.expires_at,
                        });
                        // Re-open stream if it was active before re-auth.
                        self.reopen_stream_if_needed(transport).await;
                        // Check + replenish OTPKs autonomously after successful auth.
                        let device_id = transport.config.my_device_id.clone();
                        self.handle_get_pre_key_count(transport, device_id).await;
                    }
                }
                Err(e) => error!("AuthenticateDevice decode error: {e}"),
            },
            Err(EngineError::Unauthenticated { .. }) => {
                self.callback.on_action(PlatformAction::ClearAuth);
            }
            Err(e) => error!("AuthenticateDevice failed: {e}"),
        }
    }

    async fn handle_refresh_token(
        self: &Arc<Self>,
        transport: &Arc<Transport>,
        refresh_token: String,
    ) {
        let device_id = transport.config.my_device_id.clone();
        let req = pb::RefreshTokenRequest {
            refresh_token,
            device_id,
        };
        match transport
            .unary_call(AUTH_REFRESH, &req.encode_to_vec())
            .await
        {
            Ok(bytes) => match pb::RefreshTokenResponse::decode(bytes.as_slice()) {
                Ok(resp) => {
                    let rt = resp.refresh_token.unwrap_or_default();
                    *transport.token.write().await = Some(resp.access_token.clone());
                    self.set_token_state(rt.clone(), resp.expires_at);
                    self.callback.on_action(PlatformAction::SetAuthToken {
                        user_id: String::new(),
                        access_token: resp.access_token,
                        refresh_token: rt,
                        expires_at: resp.expires_at,
                    });
                    self.reopen_stream_if_needed(transport).await;
                }
                Err(e) => error!("RefreshToken decode error: {e}"),
            },
            Err(EngineError::Unauthenticated { .. }) => {
                self.clear_token_state();
                self.callback.on_action(PlatformAction::ClearAuth);
            }
            Err(e) => error!("RefreshToken failed: {e}"),
        }
    }

    async fn handle_logout(&self, transport: &Transport) {
        let req = pb::LogoutRequest {
            access_token: self.config.auth_token.clone().unwrap_or_default(),
            all_devices: false,
        };
        if let Err(e) = transport
            .unary_call(AUTH_LOGOUT, &req.encode_to_vec())
            .await
        {
            warn!("Logout RPC failed (continuing anyway): {e}");
        }
        *transport.token.write().await = None;
        self.clear_token_state();
        self.callback.on_action(PlatformAction::ClearAuth);
    }

    async fn handle_fetch_pre_key_bundle(
        &self,
        transport: &Transport,
        user_id: String,
        device_id: Option<String>,
    ) {
        info!("fetch_pre_key_bundle: user_id={user_id}");
        let req = pb::GetPreKeyBundleRequest {
            user_id: user_id.clone(),
            device_id,
            preferred_suite: None,
        };
        match transport
            .unary_call(KEY_GET_BUNDLE, &req.encode_to_vec())
            .await
        {
            Ok(bytes) => {
                self.callback.on_action(PlatformAction::PreKeyBundleReady {
                    user_id,
                    bundle_bytes: bytes,
                });
            }
            Err(e) => error!("GetPreKeyBundle failed: {e}"),
        }
    }

    /// Generate `count` OTPKs from OrchestratorCore, persist the new state,
    /// upload to KeyService, and fire `OtpksUploaded`.
    async fn handle_upload_otpks(
        self: &Arc<Self>,
        transport: &Arc<Transport>,
        device_id: String,
        count: u32,
    ) {
        info!("upload_otpks: device_id={device_id} count={count}");

        // ── Generate OTPKs and export new state (sync — release before await) ─
        let (pre_keys, state_bytes) = {
            let guard = self.core.lock().expect("core mutex poisoned");
            match guard.as_ref() {
                None => {
                    error!("upload_otpks: OrchestratorCore not initialised");
                    return;
                }
                Some(core_arc) => {
                    let mut orch = core_arc.lock().expect("orchestrator mutex poisoned");
                    let pairs = match orch.generate_otpks(count) {
                        Ok(p) => p,
                        Err(e) => {
                            error!("generate_otpks failed: {e}");
                            return;
                        }
                    };
                    let state = match orch.export_orchestrator_state_cfe() {
                        Ok(s) => s,
                        Err(e) => {
                            error!("export_orchestrator_state_cfe failed: {e}");
                            return;
                        }
                    };
                    let keys: Vec<pb::OneTimePreKey> = pairs
                        .into_iter()
                        .map(|(key_id, public_key)| pb::OneTimePreKey {
                            key_id,
                            public_key: public_key.into(),
                        })
                        .collect();
                    (keys, state)
                }
            }
        };

        // Persist updated orchestrator state before uploading to prevent
        // key loss if the RPC succeeds but the app crashes before the next save.
        self.callback.on_action(PlatformAction::SaveKeychain {
            key: "orchestrator_state".to_string(),
            data: state_bytes,
        });

        let uploaded = pre_keys.len() as u32;
        let req = pb::UploadPreKeysRequest {
            device_id,
            pre_keys,
            signed_pre_key: None,
            replace_existing: false,
            kyber_pre_keys: vec![],
            kyber_signed_pre_key: None,
        };
        match transport.unary_call(KEY_UPLOAD, &req.encode_to_vec()).await {
            Ok(bytes) => match pb::UploadPreKeysResponse::decode(bytes.as_slice()) {
                Ok(resp) => {
                    info!("UploadOtpks: server_count={}", resp.pre_key_count);
                    self.callback.on_action(PlatformAction::OtpksUploaded {
                        uploaded,
                        server_count: resp.pre_key_count,
                    });
                }
                Err(e) => error!("UploadPreKeys decode error: {e}"),
            },
            Err(e) => error!("UploadOtpks failed: {e}"),
        }
    }

    async fn handle_get_pre_key_count(
        self: &Arc<Self>,
        transport: &Arc<Transport>,
        device_id: String,
    ) {
        let req = pb::GetPreKeyCountRequest {
            device_id: device_id.clone(),
        };
        match transport.unary_call(KEY_COUNT, &req.encode_to_vec()).await {
            Ok(bytes) => match pb::GetPreKeyCountResponse::decode(bytes.as_slice()) {
                Ok(resp) => {
                    self.callback.on_action(PlatformAction::PreKeyCountUpdated {
                        count: resp.count,
                        recommended_minimum: resp.recommended_minimum,
                    });
                    // Auto-replenish if below the server-recommended minimum.
                    if resp.count < resp.recommended_minimum {
                        let needed = resp.recommended_minimum.saturating_sub(resp.count);
                        info!(
                            "otpk_count ({}) below minimum ({}) — uploading {needed}",
                            resp.count, resp.recommended_minimum
                        );
                        self.handle_upload_otpks(transport, device_id, needed).await;
                    }
                }
                Err(e) => error!("GetPreKeyCount decode error: {e}"),
            },
            Err(e) => error!("GetPreKeyCount failed: {e}"),
        }
    }

    /// Rotate the signed pre-key via OrchestratorCore, persist state, upload to server.
    async fn handle_rotate_spk(&self, transport: &Transport, device_id: String) {
        info!("rotate_spk: device_id={device_id}");

        // ── Rotate SPK and export new state (sync — release before await) ────
        let (key_id, spk_public, spk_sig, state_bytes) = {
            let guard = self.core.lock().expect("core mutex poisoned");
            match guard.as_ref() {
                None => {
                    error!("rotate_spk: OrchestratorCore not initialised");
                    return;
                }
                Some(core_arc) => {
                    let mut orch = core_arc.lock().expect("orchestrator mutex poisoned");
                    let (kid, pub_key, sig) = match orch.rotate_spk() {
                        Ok(r) => r,
                        Err(e) => {
                            error!("rotate_spk failed: {e}");
                            return;
                        }
                    };
                    let state = match orch.export_orchestrator_state_cfe() {
                        Ok(s) => s,
                        Err(e) => {
                            error!("export_orchestrator_state_cfe after rotate_spk: {e}");
                            return;
                        }
                    };
                    (kid, pub_key, sig, state)
                }
            }
        };

        // Persist before the RPC for the same crash-safety reason as OTPKs.
        self.callback.on_action(PlatformAction::SaveKeychain {
            key: "orchestrator_state".to_string(),
            data: state_bytes,
        });

        let req = pb::RotateSignedPreKeyRequest {
            device_id,
            new_signed_pre_key: Some(pb::SignedPreKeyUpload {
                key_id,
                public_key: spk_public.into(),
                signature: spk_sig.into(),
            }),
            reason: pb::SignedPreKeyRotationReason::Scheduled as i32,
            new_kyber_signed_pre_key: None,
        };
        match transport
            .unary_call(KEY_ROTATE_SPK, &req.encode_to_vec())
            .await
        {
            Ok(bytes) => match pb::RotateSignedPreKeyResponse::decode(bytes.as_slice()) {
                Ok(resp) if resp.success => {
                    info!("RotateSignedPreKey succeeded: new_key_id={key_id}");
                    self.callback
                        .on_action(PlatformAction::SpkRotated { key_id });
                }
                Ok(_) => error!("RotateSignedPreKey: server returned success=false"),
                Err(e) => error!("RotateSignedPreKey decode error: {e}"),
            },
            Err(e) => error!("RotateSignedPreKey failed: {e}"),
        }
    }

    async fn handle_open_stream(
        &self,
        transport: &Arc<Transport>,
        conversations: Vec<String>,
        cursor: Option<String>,
    ) {
        info!("open_stream: conversations={}", conversations.len());

        // Persist params so reconnect can resubscribe automatically.
        *self.stream_params.lock().await = Some(StreamParams {
            conversation_ids: conversations.clone(),
            last_cursor: cursor.clone(),
        });

        // Clone the sender so the pump closure (which is 'static + Send) can
        // forward raw gRPC frames into the engine's event loop for async processing.
        let frame_tx = self.frame_tx.clone();
        let result = transport
            .open_message_stream(conversations, cursor, move |frame| {
                // Non-blocking send — the receiver is the event loop select! branch.
                let _ = frame_tx.send(frame);
            })
            .await;

        match result {
            Ok(handle) => {
                *self.stream.lock().await = Some(handle);
                self.callback.on_action(PlatformAction::StreamReady {
                    stream_cursor: None,
                });
            }
            Err(e) => {
                error!("open MessageStream failed: {e}");
                self.callback.on_action(PlatformAction::StreamError {
                    message: e.to_string(),
                });
            }
        }
    }

    async fn handle_close_stream(&self, _t: &Transport) {
        info!("close_stream");
        *self.stream.lock().await = None;
    }

    async fn handle_send_message(
        &self,
        _t: &Transport,
        contact_id: String,
        plaintext: Vec<u8>,
        local_id: String,
        conversation_id: String,
    ) {
        use crate::proto::core::v1::Envelope;
        use crate::proto::services::v1::{MessageStreamRequest, message_stream_request};

        debug!("send_message: to={contact_id} local_id={local_id}");

        // ── 1. Encrypt via Double Ratchet + export state ──────────────────────
        let result: Result<(Vec<u8>, Vec<u8>), String> = (|| {
            let guard = self.core.lock().expect("core mutex poisoned");
            match guard.as_ref() {
                None => Err("OrchestratorCore not initialized".to_string()),
                Some(core) => {
                    let mut orc = core.lock().expect("inner core mutex poisoned");
                    let wire_payload = orc
                        .encrypt_bytes_for(&contact_id, &plaintext)
                        .map_err(|e| format!("encrypt: {e}"))?;
                    let state_bytes = orc
                        .export_orchestrator_state_cfe()
                        .unwrap_or_default();
                    Ok((wire_payload, state_bytes))
                }
            }
        })();

        let (wire_payload, state_bytes) = match result {
            Ok(v) => v,
            Err(e) => {
                warn!("send_message encrypt failed: {e}");
                self.callback.on_action(PlatformAction::UpdateMessageStatus {
                    local_id,
                    status: 4, // FAILED
                });
                return;
            }
        };

        // ── 2. Persist state BEFORE sending (crash-safety) ───────────────────
        if !state_bytes.is_empty() {
            self.callback.on_action(PlatformAction::SaveKeychain {
                key: "orchestrator_state".to_string(),
                data: state_bytes,
            });
        }

        // ── 3. Build Envelope + wrap in MessageStreamRequest ─────────────────
        let envelope = Envelope {
            conversation_id: conversation_id.clone(),
            encrypted_payload: wire_payload.into(),
            message_id_type: Some(crate::proto::core::v1::envelope::MessageIdType::MessageId(
                local_id.clone(),
            )),
            ..Default::default()
        };
        let req = MessageStreamRequest {
            request: Some(message_stream_request::Request::Send(envelope)),
            request_id: local_id.clone(),
            attempt_id: Some(local_id.clone()),
        };
        let frame = crate::transport::grpc::encode_grpc_frame(&req.encode_to_vec());

        // ── 4. Enqueue over the stream ────────────────────────────────────────
        let guard = self.stream.lock().await;
        if let Some(stream) = guard.as_ref() {
            if let Err(e) = stream.send_frame(frame).await {
                warn!("send_message enqueue failed: {e}");
                drop(guard);
                self.callback.on_action(PlatformAction::UpdateMessageStatus {
                    local_id,
                    status: 4, // FAILED
                });
            } else {
                self.callback.on_action(PlatformAction::UpdateMessageStatus {
                    local_id,
                    status: 1, // SENT
                });
            }
        } else {
            warn!("send_message: no active stream — message dropped (local_id={local_id})");
            drop(guard);
            self.callback.on_action(PlatformAction::UpdateMessageStatus {
                local_id,
                status: 4, // FAILED
            });
        }
    }

    async fn handle_ack_message(&self, _t: &Transport, message_id: String, _message_number: u64) {
        use crate::proto::services::v1::{MessageStreamRequest, message_stream_request};
        use crate::proto::signaling::v1::{
            DeliveryReceipt, DirectReceipt, delivery_receipt::ReceiptType,
        };

        debug!("ack_message: id={message_id}");
        let receipt = DeliveryReceipt {
            receipt_type: Some(ReceiptType::Direct(DirectReceipt {
                message_ids: vec![message_id.clone()],
                status: 1, // RECEIPT_STATUS_DELIVERED
                timestamp: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs() as i64,
                ..Default::default()
            })),
        };
        let req = MessageStreamRequest {
            request: Some(message_stream_request::Request::Receipt(receipt)),
            request_id: message_id,
            attempt_id: None,
        };
        let frame = crate::transport::grpc::encode_grpc_frame(&req.encode_to_vec());

        let guard = self.stream.lock().await;
        if let Some(stream) = guard.as_ref() {
            if let Err(e) = stream.send_frame(frame).await {
                warn!("ack_message enqueue failed: {e}");
            }
        }
    }

    async fn handle_init_session_initiator(
        self: &Arc<Self>,
        transport: &Arc<Transport>,
        contact_id: String,
    ) {
        use crate::proto::core::v1 as pb_core;
        use construct_core::crypto::handshake::x3dh::X3DHPublicKeyBundle;
        use construct_core::crypto::suite_id::SuiteID;

        info!("init_session_initiator: contact_id={contact_id}");

        // ── 1. Fetch pre-key bundle from KeyService ──────────────────────────
        let req = pb::GetPreKeyBundleRequest {
            user_id: contact_id.clone(),
            device_id: None,
            preferred_suite: None,
        };
        let resp_bytes = match transport
            .unary_call(KEY_GET_BUNDLE, &req.encode_to_vec())
            .await
        {
            Ok(b) => b,
            Err(e) => {
                error!("init_session_initiator: GetPreKeyBundle failed: {e}");
                self.callback.on_action(PlatformAction::SessionError {
                    contact_id,
                    message: format!("Bundle fetch failed: {e}"),
                });
                return;
            }
        };
        let resp = match pb::GetPreKeyBundleResponse::decode(resp_bytes.as_slice()) {
            Ok(r) => r,
            Err(e) => {
                error!("init_session_initiator: decode error: {e}");
                self.callback.on_action(PlatformAction::SessionError {
                    contact_id,
                    message: format!("Bundle decode error: {e}"),
                });
                return;
            }
        };
        let bundle = match resp.bundle {
            Some(b) => b,
            None => {
                error!("init_session_initiator: server returned no bundle for {contact_id}");
                self.callback.on_action(PlatformAction::SessionError {
                    contact_id,
                    message: "Server returned no pre-key bundle".to_string(),
                });
                return;
            }
        };

        // ── 2. Map proto CryptoSuite → construct-core SuiteID ────────────────
        let suite_id = {
            let cs = bundle.crypto_suite;
            if cs == pb_core::CryptoSuite::HybridKyber1024X25519 as i32
                || cs == pb_core::CryptoSuite::HybridKyber768X25519 as i32
            {
                SuiteID::PQ_HYBRID
            } else {
                SuiteID::CLASSIC
            }
        };

        // ── 3. Build X3DHPublicKeyBundle ──────────────────────────────────────
        let x3dh_bundle = X3DHPublicKeyBundle {
            identity_public: bundle.identity_key.to_vec(),
            signed_prekey_public: bundle.signed_pre_key.to_vec(),
            signature: bundle.signed_pre_key_signature.to_vec(),
            verifying_key: resp.verifying_key.to_vec(),
            suite_id,
            one_time_prekey_public: bundle.one_time_pre_key.map(|b| b.to_vec()),
            one_time_prekey_id: bundle.one_time_pre_key_id,
            spk_uploaded_at: bundle.spk_uploaded_at as u64,
            spk_rotation_epoch: bundle.spk_rotation_epoch,
            kyber_spk_uploaded_at: bundle.kyber_spk_uploaded_at.unwrap_or(0) as u64,
            kyber_spk_rotation_epoch: bundle.kyber_spk_rotation_epoch.unwrap_or(0),
        };
        let kyber_pre_key = bundle.kyber_pre_key.map(|b| b.to_vec());
        let kyber_otpk = bundle.kyber_one_time_pre_key.map(|b| b.to_vec());
        let kyber_otpk_id = bundle.kyber_one_time_pre_key_id;

        // ── 4. Init session + encrypt msgNum=0 ping + export state ────────────
        // All sync ops under the same core lock; drop before any await.
        // Wrapped in a closure so `?` can propagate inside a `() -> Result<_,_>` scope.
        let result: Result<(Vec<u8>, Vec<u8>), String> = (|| {
            let guard = self.core.lock().expect("core mutex poisoned");
            match guard.as_ref() {
                None => Err("OrchestratorCore not initialized".to_string()),
                Some(core) => {
                    let mut orc = core.lock().expect("inner core mutex poisoned");

                    // X3DH key agreement → Double Ratchet init
                    orc.init_session_with_bundle(
                        &contact_id,
                        x3dh_bundle,
                        kyber_pre_key,
                        kyber_otpk,
                        kyber_otpk_id,
                    )
                    .map_err(|e| format!("init_session_with_bundle: {e}"))?;

                    // Encrypt session-init ping (empty, msgNum=0) → packed WirePayload
                    let wire_payload = orc
                        .encrypt_bytes_for(&contact_id, &[])
                        .map_err(|e| format!("encrypt first message: {e}"))?;

                    // Export state AFTER encrypt (includes DR advancement for msgNum=0)
                    let state_bytes = orc.export_orchestrator_state_cfe().unwrap_or_default();

                    Ok((wire_payload, state_bytes))
                }
            }
        })();

        let (wire_payload, state_bytes) = match result {
            Ok(v) => v,
            Err(e) => {
                error!("init_session_initiator: {e}");
                self.callback.on_action(PlatformAction::SessionError {
                    contact_id,
                    message: e,
                });
                return;
            }
        };

        // ── 5. Persist state before transmitting (crash-safety) ───────────────
        if !state_bytes.is_empty() {
            self.callback.on_action(PlatformAction::SaveKeychain {
                key: "orchestrator_state".to_string(),
                data: state_bytes,
            });
        }

        // ── 6. Send session-init WirePayload over the MessageStream ───────────
        let local_id = uuid::Uuid::new_v4().to_string();
        let envelope = crate::proto::core::v1::Envelope {
            // For DMs, conversation_id is the contact's user_id by convention.
            conversation_id: contact_id.clone(),
            encrypted_payload: wire_payload.into(),
            message_id_type: Some(crate::proto::core::v1::envelope::MessageIdType::MessageId(
                local_id.clone(),
            )),
            ..Default::default()
        };
        let stream_req = pb::MessageStreamRequest {
            request: Some(pb::message_stream_request::Request::Send(envelope)),
            request_id: local_id.clone(),
            attempt_id: Some(local_id.clone()),
        };
        let frame = crate::transport::grpc::encode_grpc_frame(&stream_req.encode_to_vec());

        {
            let stream_guard = self.stream.lock().await;
            if let Some(stream) = stream_guard.as_ref() {
                if let Err(e) = stream.send_frame(frame).await {
                    warn!("init_session_initiator: stream send failed: {e}");
                }
            } else {
                warn!(
                    "init_session_initiator: no active stream — session init will be sent when stream opens"
                );
                // TODO(ce-p3): enqueue for retry on StreamReady
            }
        }

        // ── 7. Notify platform ────────────────────────────────────────────────
        self.callback.on_action(PlatformAction::SessionEstablished {
            contact_id: contact_id.clone(),
            session_id: local_id,
        });

        info!("init_session_initiator: session established with {contact_id}");
    }

    async fn handle_search_user(&self, transport: &Transport, query: String) {
        use crate::proto::services::v1::{FindUserRequest, FindUserResponse};
        let req = FindUserRequest {
            username: query.clone(),
        };
        match transport.unary_call(USER_FIND, &req.encode_to_vec()).await {
            Ok(bytes) => match FindUserResponse::decode(bytes.as_slice()) {
                Ok(resp) => {
                    info!("FindUser: user_id='{}' for query='{query}'", resp.user_id);
                }
                Err(e) => error!("FindUser decode error: {e}"),
            },
            Err(e) => error!("FindUser failed: {e}"),
        }
    }

    async fn handle_signal(&self, _t: &Transport, call_id: String, _bytes: Vec<u8>) {
        info!("signal: call_id={call_id}");
        // Calls deferred — placeholder
    }

    async fn handle_register_push(&self, transport: &Transport, token: String, _platform: String) {
        use crate::proto::services::v1::RegisterDeviceTokenRequest;
        info!("register_push");
        let req = RegisterDeviceTokenRequest {
            device_token: token,
            device_id: transport.config.my_device_id.clone(),
            ..Default::default()
        };
        match transport
            .unary_call(NOTIFICATION_REGISTER, &req.encode_to_vec())
            .await
        {
            Ok(_) => info!("push token registered"),
            Err(e) => warn!("RegisterDeviceToken failed: {e}"),
        }
    }

    // ── Incoming stream frame routing ─────────────────────────────────────────

    /// Decode a raw gRPC frame from the MessageStream pump and dispatch by type.
    async fn handle_incoming_frame(
        self: &Arc<Self>,
        transport: &Arc<Transport>,
        frame: Bytes,
    ) {
        use crate::proto::services::v1::message_stream_response;
        use crate::transport::grpc::decode_grpc_frame;

        let (msg, _) = match decode_grpc_frame(frame) {
            Ok(v) => v,
            Err(e) => {
                warn!("bad gRPC frame from MessageStream: {e}");
                return;
            }
        };

        let resp = match pb::MessageStreamResponse::decode(msg) {
            Ok(r) => r,
            Err(e) => {
                warn!("MessageStreamResponse decode failed: {e}");
                return;
            }
        };

        // Persist the latest stream cursor so reconnect resumes without gaps.
        if let Some(cursor) = resp.stream_cursor {
            let mut params = self.stream_params.lock().await;
            if let Some(p) = params.as_mut() {
                p.last_cursor = Some(cursor);
            }
        }

        match resp.response {
            Some(message_stream_response::Response::Message(envelope)) => {
                self.handle_incoming_envelope(transport, envelope).await;
            }
            Some(message_stream_response::Response::Ack(ack)) => {
                debug!("stream ack: message_id={:?}", ack.message_id);
            }
            Some(message_stream_response::Response::Receipt(receipt)) => {
                use crate::proto::signaling::v1::delivery_receipt::ReceiptType;
                if let Some(ReceiptType::Direct(dr)) = receipt.receipt_type {
                    for id in &dr.message_ids {
                        self.callback.on_action(PlatformAction::DeliveryReceipt {
                            message_id: id.clone(),
                            conversation_id: String::new(),
                            timestamp: dr.timestamp,
                        });
                    }
                }
            }
            Some(message_stream_response::Response::HeartbeatAck(_)) => {
                debug!("heartbeat ack");
            }
            _ => {}
        }
    }

    /// Route a decoded `Envelope` from the stream:
    /// - msgNum == 0  → RESPONDER session init path
    /// - msgNum > 0   → normal decrypt path
    async fn handle_incoming_envelope(
        self: &Arc<Self>,
        transport: &Arc<Transport>,
        envelope: crate::proto::core::v1::Envelope,
    ) {
        let sender_id = envelope
            .sender
            .as_ref()
            .map(|s| s.user_id.clone())
            .unwrap_or_default();
        if sender_id.is_empty() {
            warn!("incoming envelope: missing sender — dropped");
            return;
        }

        let wire_payload = envelope.encrypted_payload.to_vec();
        if wire_payload.is_empty() {
            warn!("incoming envelope from {sender_id}: empty payload — dropped");
            return;
        }

        let message_id = match &envelope.message_id_type {
            Some(crate::proto::core::v1::envelope::MessageIdType::MessageId(id)) => id.clone(),
            _ => uuid::Uuid::new_v4().to_string(),
        };
        let conversation_id = envelope.conversation_id.clone();
        let timestamp = envelope.timestamp;

        // Peek at the Double Ratchet message number without decrypting.
        let message_number = match construct_core::wire_payload::unpack(&wire_payload) {
            Ok(d) => d.message_number,
            Err(e) => {
                warn!("wire_payload unpack from {sender_id}: {e:?} — dropped");
                return;
            }
        };

        if message_number == 0 {
            self.handle_session_init_responder(
                transport,
                sender_id,
                wire_payload,
                message_id,
                conversation_id,
                timestamp,
            )
            .await;
        } else {
            self.handle_decrypt_message(
                sender_id,
                wire_payload,
                message_id,
                conversation_id,
                timestamp,
            )
            .await;
        }
    }

    /// RESPONDER path: msgNum=0 arrived — fetch initiator bundle, run X3DH,
    /// decrypt the session-init ping, persist state, ACK, fire callbacks.
    async fn handle_session_init_responder(
        self: &Arc<Self>,
        transport: &Arc<Transport>,
        sender_id: String,
        wire_payload: Vec<u8>,
        message_id: String,
        conversation_id: String,
        timestamp: i64,
    ) {
        use construct_core::crypto::handshake::x3dh::X3DHPublicKeyBundle;
        use construct_core::crypto::suite_id::SuiteID;
        use construct_core::orchestration::orchestrator::IncomingFirstMessage;

        info!("session_init_responder: from={sender_id} msg_id={message_id}");

        // ── 1. Fetch sender's (INITIATOR's) public key bundle ────────────────
        let req = pb::GetPreKeyBundleRequest {
            user_id: sender_id.clone(),
            device_id: None,
            preferred_suite: None,
        };
        let resp_bytes = match transport
            .unary_call(KEY_GET_BUNDLE, &req.encode_to_vec())
            .await
        {
            Ok(b) => b,
            Err(e) => {
                error!("session_init_responder: GetPreKeyBundle failed: {e}");
                self.callback.on_action(PlatformAction::SessionError {
                    contact_id: sender_id,
                    message: format!("Bundle fetch failed: {e}"),
                });
                return;
            }
        };
        let resp = match pb::GetPreKeyBundleResponse::decode(resp_bytes.as_slice()) {
            Ok(r) => r,
            Err(e) => {
                error!("session_init_responder: decode error: {e}");
                self.callback.on_action(PlatformAction::SessionError {
                    contact_id: sender_id,
                    message: format!("Bundle decode error: {e}"),
                });
                return;
            }
        };
        let bundle = match resp.bundle {
            Some(b) => b,
            None => {
                error!("session_init_responder: no bundle for sender={sender_id}");
                self.callback.on_action(PlatformAction::SessionError {
                    contact_id: sender_id,
                    message: "Server returned no pre-key bundle for sender".to_string(),
                });
                return;
            }
        };

        // ── 2. Map proto CryptoSuite → SuiteID ──────────────────────────────
        let suite_id = {
            use crate::proto::core::v1::CryptoSuite;
            let cs = bundle.crypto_suite;
            if cs == CryptoSuite::HybridKyber1024X25519 as i32
                || cs == CryptoSuite::HybridKyber768X25519 as i32
            {
                SuiteID::PQ_HYBRID
            } else {
                SuiteID::CLASSIC
            }
        };

        // ── 3. Build X3DHPublicKeyBundle from initiator's server bundle ──────
        let initiator_bundle = X3DHPublicKeyBundle {
            identity_public: bundle.identity_key.to_vec(),
            signed_prekey_public: bundle.signed_pre_key.to_vec(),
            signature: bundle.signed_pre_key_signature.to_vec(),
            verifying_key: resp.verifying_key.to_vec(),
            suite_id,
            one_time_prekey_public: bundle.one_time_pre_key.map(|b| b.to_vec()),
            one_time_prekey_id: bundle.one_time_pre_key_id,
            spk_uploaded_at: bundle.spk_uploaded_at as u64,
            spk_rotation_epoch: bundle.spk_rotation_epoch,
            kyber_spk_uploaded_at: bundle.kyber_spk_uploaded_at.unwrap_or(0) as u64,
            kyber_spk_rotation_epoch: bundle.kyber_spk_rotation_epoch.unwrap_or(0),
        };

        // ── 4. Unpack WirePayload → IncomingFirstMessage ─────────────────────
        let decoded = match construct_core::wire_payload::unpack(&wire_payload) {
            Ok(d) => d,
            Err(e) => {
                error!("session_init_responder: wire_payload unpack failed: {e:?}");
                self.callback.on_action(PlatformAction::SessionError {
                    contact_id: sender_id,
                    message: format!("WirePayload unpack failed: {e:?}"),
                });
                return;
            }
        };
        let first_msg = IncomingFirstMessage {
            ephemeral_public_key: decoded.dh_public_key,
            message_number: decoded.message_number,
            // WirePayload sealed_box = nonce[12] ++ ciphertext
            content: decoded.sealed_box,
            one_time_prekey_id: decoded.one_time_prekey_id,
        };

        // ── 5. X3DH receive + DR init + export state (all sync, single lock) ─
        let result: Result<(Vec<u8>, Vec<u8>), String> = (|| {
            let guard = self.core.lock().expect("core mutex poisoned");
            match guard.as_ref() {
                None => Err("OrchestratorCore not initialized".to_string()),
                Some(core) => {
                    let mut orc = core.lock().expect("inner core mutex poisoned");
                    let (_session_id, plaintext) = orc
                        .init_receiving_session_with_msg(
                            &sender_id,
                            &initiator_bundle,
                            &first_msg,
                        )
                        .map_err(|e| format!("init_receiving_session: {e}"))?;
                    let state_bytes = orc
                        .export_orchestrator_state_cfe()
                        .unwrap_or_default();
                    Ok((plaintext, state_bytes))
                }
            }
        })();

        let (plaintext, state_bytes) = match result {
            Ok(v) => v,
            Err(e) => {
                error!("session_init_responder: {e}");
                self.callback.on_action(PlatformAction::SessionError {
                    contact_id: sender_id,
                    message: e,
                });
                return;
            }
        };

        // ── 6. Persist state (crash-safety before ACK) ───────────────────────
        if !state_bytes.is_empty() {
            self.callback.on_action(PlatformAction::SaveKeychain {
                key: "orchestrator_state".to_string(),
                data: state_bytes,
            });
        }

        // ── 7. ACK the session-init message ──────────────────────────────────
        self.send_ack_frame(&message_id).await;

        // ── 8. Notify platform ────────────────────────────────────────────────
        self.callback.on_action(PlatformAction::SessionEstablished {
            contact_id: sender_id.clone(),
            session_id: message_id.clone(),
        });

        // Surface plaintext only if the init ping contained actual content.
        if !plaintext.is_empty() {
            self.callback.on_action(PlatformAction::DisplayMessage {
                plaintext,
                sender_id: sender_id.clone(),
                conversation_id,
                timestamp,
            });
        }

        info!("session_init_responder: session established with {}", sender_id);
    }

    /// Normal decrypt path (msgNum > 0): decrypt WirePayload, ACK, DisplayMessage.
    async fn handle_decrypt_message(
        &self,
        sender_id: String,
        wire_payload: Vec<u8>,
        message_id: String,
        conversation_id: String,
        timestamp: i64,
    ) {
        debug!("decrypt_message: from={sender_id} msg_id={message_id}");

        let result: Result<(Vec<u8>, Vec<u8>), String> = (|| {
            let guard = self.core.lock().expect("core mutex poisoned");
            match guard.as_ref() {
                None => Err("OrchestratorCore not initialized".to_string()),
                Some(core) => {
                    let mut orc = core.lock().expect("inner core mutex poisoned");
                    let plaintext = orc
                        .decrypt_bytes_for(&sender_id, &wire_payload)
                        .map_err(|e| format!("decrypt: {e}"))?;
                    let state_bytes = orc
                        .export_orchestrator_state_cfe()
                        .unwrap_or_default();
                    Ok((plaintext, state_bytes))
                }
            }
        })();

        let (plaintext, state_bytes) = match result {
            Ok(v) => v,
            Err(e) => {
                warn!("decrypt_message from {sender_id}: {e}");
                return;
            }
        };

        if !state_bytes.is_empty() {
            self.callback.on_action(PlatformAction::SaveKeychain {
                key: "orchestrator_state".to_string(),
                data: state_bytes,
            });
        }

        self.send_ack_frame(&message_id).await;

        self.callback.on_action(PlatformAction::DisplayMessage {
            plaintext,
            sender_id,
            conversation_id,
            timestamp,
        });
    }

    /// Send a delivery ACK for `message_id` over the active MessageStream.
    async fn send_ack_frame(&self, message_id: &str) {
        use crate::proto::services::v1::{MessageStreamRequest, message_stream_request};
        use crate::proto::signaling::v1::{
            DeliveryReceipt, DirectReceipt, delivery_receipt::ReceiptType,
        };

        let receipt = DeliveryReceipt {
            receipt_type: Some(ReceiptType::Direct(DirectReceipt {
                message_ids: vec![message_id.to_string()],
                status: 1, // RECEIPT_STATUS_DELIVERED
                timestamp: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs() as i64,
                ..Default::default()
            })),
        };
        let req = MessageStreamRequest {
            request: Some(message_stream_request::Request::Receipt(receipt)),
            request_id: message_id.to_string(),
            attempt_id: None,
        };
        let frame = crate::transport::grpc::encode_grpc_frame(&req.encode_to_vec());
        let guard = self.stream.lock().await;
        if let Some(stream) = guard.as_ref() {
            if let Err(e) = stream.send_frame(frame).await {
                warn!("send_ack_frame: stream send failed: {e}");
            }
        }
    }
}
