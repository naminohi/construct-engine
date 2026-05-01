fn main() {
    // UniFFI scaffolding generation — required for iOS/Android bindings.
    uniffi::generate_scaffolding("src/construct_engine.udl")
        .expect("Failed to generate UniFFI scaffolding");

    // Proto compilation — gRPC types for all Phase 1 services.
    // Set CONSTRUCT_PROTOS_DIR to point at construct-server/shared/proto/.
    compile_protos();
}

fn compile_protos() {
    let protos_dir = std::env::var("CONSTRUCT_PROTOS_DIR")
        .unwrap_or_else(|_| "../construct-server/shared/proto".to_string());

    // Tell cargo to re-run this script if any proto file changes.
    println!("cargo:rerun-if-env-changed=CONSTRUCT_PROTOS_DIR");
    println!("cargo:rerun-if-changed={protos_dir}");

    let proto_files: Vec<String> = vec![
        // Core types (Envelope, Identity, Crypto, Pagination)
        format!("{protos_dir}/core/crypto.proto"),
        format!("{protos_dir}/core/envelope.proto"),
        format!("{protos_dir}/core/identity.proto"),
        format!("{protos_dir}/core/pagination.proto"),
        // Messaging wire types
        format!("{protos_dir}/messaging/content.proto"),
        format!("{protos_dir}/messaging/e2ee.proto"),
        // Signaling types (DeliveryReceipt, PresenceUpdate referenced by messaging)
        format!("{protos_dir}/signaling/presence.proto"),
        format!("{protos_dir}/signaling/webrtc.proto"),
        // Phase 1 services
        format!("{protos_dir}/services/auth_service.proto"),
        format!("{protos_dir}/services/key_service.proto"),
        format!("{protos_dir}/services/messaging_service.proto"),
        format!("{protos_dir}/services/user_service.proto"),
        format!("{protos_dir}/services/notification_service.proto"),
    ];

    // Check that the proto directory exists; skip gracefully if offline/CI.
    if !std::path::Path::new(&protos_dir).exists() {
        println!(
            "cargo:warning=CONSTRUCT_PROTOS_DIR '{protos_dir}' not found — skipping proto compilation"
        );
        return;
    }

    let mut cfg = prost_build::Config::new();
    // Emit `prost::bytes::Bytes` for proto `bytes` fields (avoids Vec<u8> copies).
    cfg.bytes(["."]);

    if let Err(e) = cfg.compile_protos(
        &proto_files.iter().map(|s| s.as_str()).collect::<Vec<_>>(),
        &[protos_dir.as_str()],
    ) {
        println!("cargo:warning=Proto compilation failed: {e}");
    }
}
