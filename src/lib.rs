// Public modules
pub mod config;
pub mod engine;
pub mod error;
pub mod events;
pub mod proto;
pub mod transport;

// Re-export the public surface
pub use config::EngineConfig;
pub use engine::{ConstructEngine, EngineCallback};
pub use error::EngineError;
pub use events::{PlatformAction, UiEvent};

// UniFFI scaffolding — included only for iOS/Android binary targets.
// When building with `--features ios`, UniFFI generates the Swift/Kotlin bindings.
#[cfg(feature = "ios")]
uniffi::include_scaffolding!("construct_engine");
