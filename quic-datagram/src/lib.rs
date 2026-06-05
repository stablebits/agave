#![doc = include_str!("../README.md")]
#![cfg(feature = "agave-unstable-api")]

pub mod allowlist;
pub mod error;

#[cfg(any(test, feature = "dev-context-only-utils"))]
pub mod testutils;

pub(crate) use error::close_codes;
pub mod endpoint;
pub(crate) mod inbound;
pub(crate) mod outbound;
pub(crate) mod read_loop;
pub(crate) mod stats;
pub(crate) mod subnet_rate_limit;
pub(crate) mod transport;

use std::time::Duration;
pub use {
    allowlist::{Allowlist, StakedNodesAllowlist},
    endpoint::{KeyUpdater, QuicDatagramEndpoint},
    error::Error,
    solana_net_utils::banlist::Banlist,
};

/// Ban duration applied HANDOVER trigger.
/// Not long since peer may legitimately be retrying a hot-spare promotion.
pub const BAN_DURATION_SHORT: Duration = Duration::from_secs(5);

/// Hard ceiling on total live connections in either direction (the outbound
/// dialer map and the inbound acceptor each cap at this). Sized for the
/// maximum expected alpenglow staked-node count.
pub const MAX_PEERS: u64 = 4000;

/// Maximum simultaneous inbound connections accepted from a single peer
/// identity. Kept low so that no one allowlisted sender can fill the global
/// inbound budget ([`MAX_PEERS`]) and starve honest peers; >1 tolerates a
/// redial racing an idle connection that has not yet timed out. A sender needs
/// only one inbound connection to deliver to us, so this is generous.
pub const MAX_CONNECTIONS_PER_PEER: u32 = 2;

/// Capacity of the egress channel held by [`QuicDatagramEndpoint`]. Senders
/// must `try_send` and accept drop-on-full.
///
/// Sized to absorb a full slot's burst with headroom - `MAX_PEERS` peers
/// × ~4 messages/slot = ~8 K items, doubled for safety against bursty
/// drainers. Production steady-state pressure is far lower (per-validator
/// vote rate is ~1 message/slot).
pub const EGRESS_CHANNEL_CAP: usize = 16384;

/// Per-peer receive-side rate limit.
pub const MAX_DATAGRAMS_PER_SECOND_PER_PEER: f64 = 30.0;

/// Per-peer receive side burst limit.
pub const PEER_RATE_LIMIT_BURST: u64 = 100;

/// Per-peer receive side DOS protection limit.
/// If peer exhausts this burst size they are considered to be attacking and banned.
pub const PEER_RATE_LIMIT_BURST_DOS: u64 = 100000;

/// If peer exceeds DOS budget they get banned.
pub const BAN_DURATION_DOS: Duration = Duration::from_hours(48);

/// How often each connection's read loop re-checks whether the peer is still
/// in the allowlist. Stale (epoch-evicted) connections are closed within one
/// interval after the allowlist snapshot is updated.
pub const ALLOWLIST_CHECK_INTERVAL: Duration = Duration::from_secs(10);
