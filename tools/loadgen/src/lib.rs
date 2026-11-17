//! Load generator for echo-mtproxy: fake Telegram clients on one side of the
//! proxy and a fake DC on the other.
//!
//! The clients only ever talk to the fake DC. The proxy under test must have
//! its DCs overridden to point at it; a run stops at its first connection if
//! the far end does not answer like the fake DC, so a misconfigured proxy is
//! never used to send load to Telegram.

pub mod client;
pub mod dc;
pub mod proto;
pub mod stats;
