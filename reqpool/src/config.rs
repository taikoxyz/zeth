use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
/// The configuration for the redis-backend request pool
pub struct RedisPoolConfig {
    /// The URL of the Redis database, e.g. "redis://localhost:6379"
    pub redis_url: String,
    /// The TTL of the Redis database
    pub redis_ttl: u64,
}
