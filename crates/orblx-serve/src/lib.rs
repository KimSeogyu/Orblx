//! orblx serve and funnel.
//!
//! `orblx serve PORT` publishes `127.0.0.1:PORT` over HTTPS on the overlay address.
//! The TLS certificate is the node X.509-SVID. The orblx.local CA signs it.
//! The policy file controls which overlay sources can reach the HTTPS port.
//! The default is deny.
//!
//! `orblx funnel on --listen ADDR` publishes the same port on an outside address.
//! Funnel is off by default. Only an explicit `funnel on` opens the outside listener.
//! Each serve, serve off, funnel on, and funnel off change appends one record
//! to the config audit chain `serve-audit.jsonl` in the node state directory.

mod config;
mod server;

pub use config::{
    disable_serve, enable_serve, set_funnel, ServeChange, ServeConfig, DEFAULT_HTTPS_PORT,
    SERVE_AUDIT_FILE, SERVE_FILE,
};
pub use server::spawn_serve;
