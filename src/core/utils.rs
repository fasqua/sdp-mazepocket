//! Utility functions for SDP Maze Pocket

use sha2::{Sha256, Digest};

/// Convert lamports to SOL
pub fn lamports_to_sol(lamports: u64) -> f64 {
    lamports as f64 / 1_000_000_000.0
}

/// Convert SOL to lamports
pub fn sol_to_lamports(sol: f64) -> u64 {
    (sol * 1_000_000_000.0) as u64
}

/// Generate a deterministic random number from seed
pub fn seeded_random(seed: &[u8], index: u64) -> u64 {
    let mut hasher = Sha256::new();
    hasher.update(seed);
    hasher.update(&index.to_le_bytes());
    let result = hasher.finalize();
    u64::from_le_bytes(result[0..8].try_into().unwrap())
}

/// Get fibonacci number at index (cached for common values)
pub fn fibonacci(n: u8) -> u64 {
    match n {
        0 => 0,
        1 => 1,
        2 => 1,
        3 => 2,
        4 => 3,
        5 => 5,
        6 => 8,
        7 => 13,
        8 => 21,
        9 => 34,
        10 => 55,
        _ => {
            let mut a = 0u64;
            let mut b = 1u64;
            for _ in 0..n {
                let temp = a + b;
                a = b;
                b = temp;
            }
            b
        }
    }
}

/// Add noise to an amount based on seed
pub fn add_noise(amount: u64, noise_percent: f64, seed: &[u8], index: u64) -> u64 {
    let random = seeded_random(seed, index);
    let noise_range = (amount as f64 * noise_percent / 100.0) as u64;
    if noise_range == 0 {
        return amount;
    }
    let noise = (random % (noise_range * 2)) as i64 - noise_range as i64;
    (amount as i64 + noise).max(0) as u64
}

/// Generate a unique pocket ID
pub fn generate_pocket_id() -> String {
    let random_bytes: [u8; 8] = rand::random();
    format!("pocket_{}", hex::encode(random_bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sol_conversion() {
        assert_eq!(sol_to_lamports(1.0), 1_000_000_000);
        assert_eq!(lamports_to_sol(1_000_000_000), 1.0);
    }

    #[test]
    fn test_pocket_id() {
        let id = generate_pocket_id();
        assert!(id.starts_with("pocket_"));
        assert_eq!(id.len(), 24); // "pocket_" (7) + 16 hex chars
    }
}
