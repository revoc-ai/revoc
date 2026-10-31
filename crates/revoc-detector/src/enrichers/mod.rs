//! Optional enricher integrations (Presidio, Azure Content Safety).
//!
//! All enrichers are non-blocking: errors are logged as warnings and the
//! enricher returns an empty result. They never fail the request path.

pub mod azure;
pub mod presidio;
