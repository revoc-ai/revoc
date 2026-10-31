//! Configuration schema, loading, and validation for REVOC.
//!
//! The single source of truth for every runtime-configurable property.
//! Load via [`loader::load`] or [`loader::load_or_default`]; validate via
//! [`schema::Config::validate`].

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod loader;
pub mod schema;

pub use schema::{
    AuditConfig, AuthConfig, CacheConfig, Config, DashboardConfig, DetectionConfig,
    GovernanceConfig, HttpPluginConfig, KillSwitchConfig, McpConfig, PolicyConfig, ProviderConfig,
    ServerConfig, SessionConfig, StorageConfig, StreamConfig, TelemetryConfig, TrustedMcpServer,
    UpstreamConfig, WebhookEndpoint, WebhooksConfig,
};
