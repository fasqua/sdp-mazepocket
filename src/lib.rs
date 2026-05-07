//! SDP Maze Pocket - Private Wallet Funding via Maze Routing
//!
//! Provides privacy-enhanced wallet funding using maze topology.
//! Users can create "pockets" - stealth wallets funded via maze routing
//! that can be used freely in any dApp.

pub mod x402;
pub mod mpp;
pub mod payment_router;
pub mod core;
pub mod relay;
pub mod error;
pub mod config;
pub mod tokens;
pub mod swap;
pub mod printr;

// Re-export commonly used types
pub use config::Config;
pub use error::{MazeError, Result};
pub use core::{lamports_to_sol, sol_to_lamports};
