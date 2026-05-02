/// Events dispatched from Swift UI → Rust engine.
///
/// Each variant corresponds to a user or system action. The engine processes
/// them on its internal tokio executor and fires `PlatformAction` callbacks
/// back to Swift when platform I/O is required.
#[derive(Debug)]
pub enum UiEvent {
    // ── Auth ─────────────────────────────────────────────────────────────────
    /// Register a new device. Engine fetches a PoW challenge, solves it, and
    /// calls `AuthService/RegisterDevice`. On success fires `SetAuthToken` +
    /// `RegistrationComplete`. The `OrchestratorCore` must already be initialised
    /// (i.e. `keys_cfe_data` supplied at construction or via `KeychainResult`).
    RegisterDevice {
        /// Optional display name for the new identity (may be empty).
        username: Option<String>,
        /// Client-assigned device ID derived from the signing key fingerprint.
        device_id: String,
    },

    /// Authenticate an existing device. Called on app launch after Keychain load.
    Authenticate {
        device_id: String,
        /// Ed25519 signature over the server-issued PoW challenge
        challenge_response: Vec<u8>,
        /// Raw Ed25519 signing key bytes (64 bytes)
        signing_key: Vec<u8>,
    },

    /// Refresh the access token using the stored refresh token.
    RefreshToken { refresh_token: String },

    /// Log out and revoke all tokens on the server.
    Logout,

    // ── Keys ─────────────────────────────────────────────────────────────────
    /// Fetch the X3DH pre-key bundle for a contact.
    /// Engine calls back with `PlatformAction::PreKeyBundleReady`.
    FetchPreKeyBundle {
        user_id: String,
        device_id: Option<String>,
    },

    /// Generate `count` new one-time pre-keys from OrchestratorCore and upload
    /// them to KeyService. Engine persists the updated orchestrator state via
    /// `SaveKeychain` before making the RPC, then fires `OtpksUploaded`.
    UploadOtpks {
        device_id: String,
        count: u32,
    },

    /// Check how many one-time pre-keys remain on the server.
    /// Engine auto-uploads if the count is below `recommended_minimum`.
    GetPreKeyCount { device_id: String },

    /// Rotate the signed pre-key. Engine calls `Orchestrator::rotate_spk()`,
    /// persists the new state, and fires `SpkRotated` on success.
    RotateSignedPreKey { device_id: String },

    // ── Messaging ────────────────────────────────────────────────────────────
    /// Open the bidirectional `MessageStream` gRPC call.
    /// Subscribes to the given conversations; engine fires
    /// `PlatformAction::StreamReady` when the stream is established.
    OpenMessageStream {
        conversation_ids: Vec<String>,
        /// Opaque server cursor from the last session (for gapless resume)
        since_cursor: Option<String>,
    },

    /// Close the bidirectional stream (graceful half-close).
    CloseMessageStream,

    /// Send a message. Engine enqueues into the open MessageStream.
    SendMessage {
        contact_id: String,
        /// Sealed-box ciphertext (binary, no base64)
        encrypted_payload: Vec<u8>,
        /// Client-assigned UUID for correlation
        local_id: String,
        conversation_id: String,
    },

    /// Acknowledge delivery of an incoming message.
    AckMessage {
        message_id: String,
        message_number: u64,
    },

    // ── Session ──────────────────────────────────────────────────────────────
    /// Initiate a new X3DH session as INITIATOR with the given contact.
    /// Engine fetches the pre-key bundle then calls back with
    /// `PlatformAction::SessionInitiatorReady(contact_id, wire_payload)`.
    InitSessionInitiator { contact_id: String },

    // ── Users ─────────────────────────────────────────────────────────────────
    /// Search for a user by username or display name.
    SearchUser { query: String },

    // ── Signaling ────────────────────────────────────────────────────────────
    /// Send a WebRTC signal (SDP offer/answer, ICE candidate).
    Signal {
        call_id: String,
        /// Serialised `SignalRequest` proto bytes
        signal_bytes: Vec<u8>,
    },

    // ── Push notifications ────────────────────────────────────────────────────
    /// Register an APNs or FCM push token with the server.
    RegisterPushToken {
        token: String,
        /// "apns" | "fcm"
        platform: String,
    },

    // ── Platform responses ────────────────────────────────────────────────────
    /// Swift Keychain read result delivered back to the engine.
    /// `data` is None if the key was not found.
    KeychainResult { key: String, data: Option<Vec<u8>> },

    /// Swift signals that all platform services are initialised and
    /// the engine may begin network activity.
    PlatformReady,
}

/// Actions the engine requests from the Swift platform layer.
///
/// The engine never does platform I/O directly — it fires these actions and
/// Swift's `EngineAdapter` executes them (Keychain, CoreData, CallKit, etc.).
#[derive(Debug)]
pub enum PlatformAction {
    // ── Keychain ─────────────────────────────────────────────────────────────
    /// Persist binary data in Keychain under the given key.
    SaveKeychain { key: String, data: Vec<u8> },

    /// Request a Keychain value. Swift reads it and dispatches
    /// `UiEvent::KeychainResult` back to the engine.
    LoadKeychain { key: String },

    /// Delete a Keychain item.
    DeleteKeychain { key: String },

    // ── Auth ─────────────────────────────────────────────────────────────────
    /// Store new auth tokens (access + refresh) received from the server.
    SetAuthToken {
        /// Present after `RegisterDevice`; empty string for re-auth / token refresh.
        user_id: String,
        access_token: String,
        refresh_token: String,
        /// Unix timestamp (seconds) when the access token expires
        expires_at: i64,
    },

    /// Clear all auth state (on logout or unauthenticated error).
    ClearAuth,

    /// Device successfully registered. Swift should store the user ID and
    /// transition from the registration screen to the main UI.
    RegistrationComplete {
        user_id: String,
        device_id: String,
    },

    // ── Messaging ────────────────────────────────────────────────────────────
    /// Persist a received message envelope for display in the chat.
    /// `envelope_bytes` is the serialised protobuf `PendingMessage`.
    SaveMessage {
        envelope_bytes: Vec<u8>,
        sender_id: String,
        conversation_id: String,
        timestamp: i64,
    },

    /// Update the delivery status of a sent message.
    /// `status`: 0=pending, 1=sent, 2=delivered, 3=read
    UpdateMessageStatus { local_id: String, status: u8 },

    /// A decrypted message is ready to display. Swift should persist
    /// and render it. `plaintext` is raw KNST protobuf bytes.
    DisplayMessage {
        plaintext: Vec<u8>,
        sender_id: String,
        conversation_id: String,
        timestamp: i64,
    },

    /// A delivery receipt arrived for a previously sent message.
    DeliveryReceipt {
        message_id: String,
        conversation_id: String,
        timestamp: i64,
    },

    // ── Session ──────────────────────────────────────────────────────────────
    /// A new E2EE session with a contact has been established successfully.
    SessionEstablished {
        contact_id: String,
        session_id: String,
    },

    /// A session operation failed. Swift should surface this appropriately.
    SessionError { contact_id: String, message: String },

    // ── Keys ─────────────────────────────────────────────────────────────────
    /// A pre-key bundle was fetched from the server. Swift passes it
    /// to OrchestratorCore via `CfeIncomingEvent::KeyBundleFetched`.
    PreKeyBundleReady {
        user_id: String,
        /// Serialised `PreKeyBundle` proto bytes (binary, no JSON)
        bundle_bytes: Vec<u8>,
    },

    /// One-time pre-keys were successfully uploaded to the server.
    OtpksUploaded {
        /// Number of keys uploaded in this batch.
        uploaded: u32,
        /// Total server-side OTPK count after upload.
        server_count: u32,
    },

    /// Current one-time pre-key count from the server.
    PreKeyCountUpdated {
        count: u32,
        recommended_minimum: u32,
    },

    /// Signed pre-key was rotated. Swift should update UI indicators if shown.
    SpkRotated {
        /// New key ID assigned by the Orchestrator.
        key_id: u32,
    },

    // ── Stream ────────────────────────────────────────────────────────────────
    /// The bidirectional MessageStream QUIC stream is open and ready.
    StreamReady {
        /// Opaque cursor for the next reconnect's `SubscribeRequest.since_cursor`
        stream_cursor: Option<String>,
    },

    /// The MessageStream closed unexpectedly. Engine will reconnect automatically.
    StreamError { message: String },

    // ── Calls ────────────────────────────────────────────────────────────────
    /// Incoming call signal received. Swift hands off to CallKit.
    IncomingCall {
        call_id: String,
        caller_id: String,
        /// Serialised SDP/ICE signal proto bytes
        signal_bytes: Vec<u8>,
    },

    /// A call signal (SDP answer, ICE candidate) arrived mid-call.
    CallSignalReceived {
        call_id: String,
        signal_bytes: Vec<u8>,
    },

    // ── Network / Debug ───────────────────────────────────────────────────────
    /// Transport connection state changed.
    /// `connected: true` — H3 is live and ready.
    /// `connected: false` — connection lost, engine is reconnecting.
    ConnectionStateChanged { connected: bool },

    /// Unrecoverable network error. Swift should show the user a reconnecting UI.
    NetworkError { message: String },

    /// Debug log line (level: "DEBUG"|"INFO"|"WARN"|"ERROR").
    Log { level: String, message: String },
}
