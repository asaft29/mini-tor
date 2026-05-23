use rust_embed::RustEmbed;

/// Embedded web UI assets compiled from services/web-ui via Trunk.
/// Run `cd services/web-ui && trunk build --release` to populate web-dist/
/// before building the discovery binary.
#[derive(RustEmbed)]
#[folder = "web-dist/"]
pub struct Asset;
