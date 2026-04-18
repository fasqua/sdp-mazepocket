//! Configuration for SDP Maze Pocket

use serde::{Deserialize, Serialize};

/// Fee percentage (0.5%)
pub const FEE_PERCENT: f64 = 0.5;

/// Transaction fee per TX in lamports
pub const TX_FEE_LAMPORTS: u64 = 5_000;

/// Minimum transfer amount in SOL
pub const MIN_AMOUNT_SOL: f64 = 0.01;

/// Request expiry in seconds (30 minutes)
pub const EXPIRY_SECONDS: i64 = 1800;

/// Fee wallet address
pub const FEE_WALLET: &str = "Nd5yLUNpZwqQ9GzMt1TmbwBNfR5EYpjrNWuHbQh9SDP";

/// Database path for pocket storage
pub const POCKET_DB_PATH: &str = "pocket.db";

/// Autopurge interval (7 days in seconds) - for deleted pockets
pub const AUTOPURGE_SECONDS: i64 = 604800;

// ============ MAZE PARAMETERS ============

/// Minimum hops in maze
pub const MIN_HOPS: u8 = 5;

/// Maximum hops in maze
pub const MAX_HOPS: u8 = 10;

/// Default hop count
pub const DEFAULT_HOPS: u8 = 7;

/// Minimum split branches per node
pub const MIN_SPLIT: u8 = 2;

/// Maximum split branches per node
pub const MAX_SPLIT: u8 = 4;

/// Amount noise percentage (for obfuscation)
pub const AMOUNT_NOISE_PERCENT: f64 = 0.5;

// ============ ARGON2 PARAMETERS ============

/// Argon2id memory cost (64 MB)
pub const ARGON2_MEMORY_COST: u32 = 65536;

/// Argon2id time cost (iterations)
pub const ARGON2_TIME_COST: u32 = 3;

/// Argon2id parallelism
pub const ARGON2_PARALLELISM: u32 = 4;

/// Maze generation parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MazeParameters {
    /// Random seed for deterministic generation (256-bit)
    pub seed: [u8; 32],
    /// Fibonacci offset for path variation (0-100)
    pub fib_offset: u8,
    /// Split ratio based on golden ratio variant (1.1-3.0)
    pub split_ratio: f64,
    /// Total number of hops/nodes in maze
    pub hop_count: u8,
    /// Merge strategy
    pub merge_strategy: MergeStrategy,
    /// Delay pattern between transactions
    pub delay_pattern: DelayPattern,
    /// Amount variation percentage (0.01% - 1%)
    pub amount_noise: f64,
    /// Base delay in milliseconds (0-5000)
    pub delay_ms: u64,
    /// Delay scope: per node or per level
    pub delay_scope: DelayScope,
    /// Pool address for privacy relay (optional)
    #[serde(default)]
    pub pool_address: Option<String>,
    /// Pool private key bytes for signing (optional, not serialized)
    #[serde(skip)]
    pub pool_private_key_bytes: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum MergeStrategy {
    Early,
    Late,
    Middle,
    Random,
    Fibonacci,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum DelayPattern {
    None,
    Linear,
    Exponential,
    Random,
    Fibonacci,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum DelayScope {
    Node,
    Level,
}

impl Default for MazeParameters {
    fn default() -> Self {
        Self {
            seed: rand::random(),
            fib_offset: rand::random::<u8>() % 100,
            split_ratio: 1.618,
            hop_count: DEFAULT_HOPS,
            merge_strategy: MergeStrategy::Random,
            delay_pattern: DelayPattern::Random,
            amount_noise: AMOUNT_NOISE_PERCENT,
            delay_ms: 500,
            delay_scope: DelayScope::Node,
            pool_address: None,
            pool_private_key_bytes: None,
        }
    }
}

impl MazeParameters {
    pub fn random() -> Self {
        let mut params = Self::default();
        params.seed = rand::random();
        params.fib_offset = rand::random::<u8>() % 100;
        params.split_ratio = 1.1 + (rand::random::<f64>() * 1.9);
        params.merge_strategy = match rand::random::<u8>() % 5 {
            0 => MergeStrategy::Early,
            1 => MergeStrategy::Late,
            2 => MergeStrategy::Middle,
            3 => MergeStrategy::Fibonacci,
            _ => MergeStrategy::Random,
        };
        params.delay_pattern = match rand::random::<u8>() % 5 {
            0 => DelayPattern::None,
            1 => DelayPattern::Linear,
            2 => DelayPattern::Exponential,
            3 => DelayPattern::Fibonacci,
            _ => DelayPattern::Random,
        };
        params
    }
}

/// Application configuration
#[derive(Debug, Clone)]
pub struct Config {
    pub rpc_url: String,
    pub database_path: String,
    pub master_key: String,
    pub port: u16,
    pub admin_api_key: Option<String>,
    pub pool_address: Option<String>,
    pub pool_private_key: Option<String>,
}

impl Config {
    pub fn from_env() -> Self {
        Self {
            rpc_url: std::env::var("SOLANA_RPC_URL")
                .unwrap_or_else(|_| "https://api.mainnet-beta.solana.com".to_string()),
            database_path: std::env::var("POCKET_DB_PATH")
                .unwrap_or_else(|_| POCKET_DB_PATH.to_string()),
            master_key: std::env::var("MASTER_KEY")
                .expect("MASTER_KEY must be set"),
            port: std::env::var("POCKET_PORT")
                .unwrap_or_else(|_| "3033".to_string())
                .parse()
                .unwrap_or(3033),
            admin_api_key: std::env::var("ADMIN_API_KEY").ok(),
            pool_address: std::env::var("POOL_ADDRESS").ok(),
            pool_private_key: std::env::var("POOL_PRIVATE_KEY").ok(),
        }
    }
}
