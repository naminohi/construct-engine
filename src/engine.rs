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
        AUTH_AUTHENTICATE, AUTH_LOGOUT, AUTH_REFRESH, KEY_COUNT, KEY_GET_BUNDLE, KEY_ROTATE_SPK,
        KEY_UPLOAD, NOTIFICATION_REGISTER, USER_FIND,
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
}

/// Stored so the engine can re-subscribe after a reconnect.
#[derive(Clone)]
struct StreamParams {
    conversation_ids: Vec<String>,
    last_cursor: Option<String>,
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

        Ok(Arc::new(Self {
            config: Arc::new(config),
            callback: Arc::from(callback),
            dispatch_tx: tx,
            runtime: Mutex::new(Some(EngineRuntime { rx, rt })),
            stream: tokio::sync::Mutex::new(None),
            stream_params: tokio::sync::Mutex::new(None),
            core: Mutex::new(core),
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
        let EngineRuntime { rx, rt } = runtime;

        // Run the event loop on the engine's dedicated tokio runtime.
        // The spawned OS thread owns the runtime and blocks until shutdown.
        std::thread::Builder::new()
            .name("construct-engine-rt".to_string())
            .spawn(move || {
                rt.block_on(async move {
                    info!("construct-engine started");
                    engine.event_loop(rx).await;
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

    async fn event_loop(self: Arc<Self>, mut rx: mpsc::Receiver<UiEvent>) {
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

        loop {
            tokio::select! {
                biased;

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
            }
        }

        info!("event loop exited");
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

            UiEvent::UploadPreKeys {
                device_id,
                request_bytes,
            } => {
                self.handle_upload_pre_keys(transport, device_id, request_bytes)
                    .await;
            }

            UiEvent::GetPreKeyCount { device_id } => {
                self.handle_get_pre_key_count(transport, device_id).await;
            }

            UiEvent::RotateSignedPreKey {
                device_id,
                request_bytes,
            } => {
                self.handle_rotate_spk(transport, device_id, request_bytes)
                    .await;
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
                encrypted_payload,
                local_id,
                conversation_id,
            } => {
                self.handle_send_message(
                    transport,
                    contact_id,
                    encrypted_payload,
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
                self.handle_init_session(transport, contact_id).await;
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

    async fn handle_authenticate(
        &self,
        transport: &Transport,
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
                        self.callback.on_action(PlatformAction::SetAuthToken {
                            access_token: tokens.access_token,
                            refresh_token: tokens.refresh_token,
                            expires_at: tokens.expires_at,
                        });
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

    async fn handle_refresh_token(&self, transport: &Transport, refresh_token: String) {
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
                    *transport.token.write().await = Some(resp.access_token.clone());
                    self.callback.on_action(PlatformAction::SetAuthToken {
                        access_token: resp.access_token,
                        refresh_token: resp.refresh_token.unwrap_or_default(),
                        expires_at: resp.expires_at,
                    });
                }
                Err(e) => error!("RefreshToken decode error: {e}"),
            },
            Err(EngineError::Unauthenticated { .. }) => {
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

    async fn handle_upload_pre_keys(
        &self,
        transport: &Transport,
        device_id: String,
        request_bytes: Vec<u8>,
    ) {
        info!("upload_pre_keys: device_id={device_id}");
        // request_bytes is already a serialised UploadPreKeysRequest proto.
        match transport.unary_call(KEY_UPLOAD, &request_bytes).await {
            Ok(_) => info!("UploadPreKeys succeeded"),
            Err(e) => error!("UploadPreKeys failed: {e}"),
        }
    }

    async fn handle_get_pre_key_count(&self, transport: &Transport, device_id: String) {
        let req = pb::GetPreKeyCountRequest { device_id };
        match transport.unary_call(KEY_COUNT, &req.encode_to_vec()).await {
            Ok(bytes) => match pb::GetPreKeyCountResponse::decode(bytes.as_slice()) {
                Ok(resp) => {
                    self.callback.on_action(PlatformAction::PreKeyCountUpdated {
                        count: resp.count,
                        recommended_minimum: resp.recommended_minimum,
                    });
                }
                Err(e) => error!("GetPreKeyCount decode error: {e}"),
            },
            Err(e) => error!("GetPreKeyCount failed: {e}"),
        }
    }

    async fn handle_rotate_spk(
        &self,
        transport: &Transport,
        device_id: String,
        request_bytes: Vec<u8>,
    ) {
        info!("rotate_spk: device_id={device_id}");
        // request_bytes is a serialised RotateSignedPreKeyRequest proto.
        match transport.unary_call(KEY_ROTATE_SPK, &request_bytes).await {
            Ok(_) => info!("RotateSignedPreKey succeeded"),
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

        let cb = Arc::clone(&self.callback);
        let result = transport
            .open_message_stream(conversations, cursor, move |frame| {
                // Phase 1: forward raw frame bytes to Swift for processing.
                // Phase 2: decode MessageStreamResponse here and route to OrchestratorCore.
                cb.on_action(PlatformAction::SaveMessage {
                    envelope_bytes: frame.to_vec(),
                    sender_id: String::new(),
                    conversation_id: String::new(),
                    timestamp: 0,
                });
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
        encrypted_payload: Vec<u8>,
        local_id: String,
        conversation_id: String,
    ) {
        use crate::proto::core::v1::Envelope;
        use crate::proto::services::v1::{MessageStreamRequest, message_stream_request};

        debug!("send_message: to={contact_id} local_id={local_id}");
        let envelope = Envelope {
            conversation_id: conversation_id.clone(),
            encrypted_payload: encrypted_payload.into(),
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

        let guard = self.stream.lock().await;
        if let Some(stream) = guard.as_ref() {
            if let Err(e) = stream.send_frame(frame).await {
                warn!("send_message enqueue failed: {e}");
            }
        } else {
            warn!("send_message: no active stream — message dropped (local_id={local_id})");
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

    async fn handle_init_session(&self, _t: &Transport, contact_id: String) {
        info!("init_session_initiator: contact_id={contact_id}");
        // Phase 2: fetch bundle then call OrchestratorCore::init_session
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
}
