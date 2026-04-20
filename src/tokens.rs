//! Curated token list for Maze Pocket Swap
//!
//! Resolves token symbol/name to contract address (mint).
//! Supports direct CA input for tokens not in the curated list.

use serde::{Deserialize, Serialize};

/// Token info for swap
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenInfo {
    pub symbol: String,
    pub name: String,
    pub mint: String,
    pub decimals: u8,
    pub logo_uri: Option<String>,
}

/// Native SOL wrapped mint
pub const SOL_MINT: &str = "So11111111111111111111111111111111111111112";

/// Curated token list (verified, high-liquidity tokens on Solana)
pub fn curated_tokens() -> Vec<TokenInfo> {
    vec![
        TokenInfo {
            symbol: "SOL".into(),
            name: "Solana".into(),
            mint: SOL_MINT.into(),
            decimals: 9,
            logo_uri: None,
        },
        TokenInfo {
            symbol: "USDC".into(),
            name: "USD Coin".into(),
            mint: "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v".into(),
            decimals: 6,
            logo_uri: None,
        },
        TokenInfo {
            symbol: "USDT".into(),
            name: "Tether USD".into(),
            mint: "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB".into(),
            decimals: 6,
            logo_uri: None,
        },
        TokenInfo {
            symbol: "JUP".into(),
            name: "Jupiter".into(),
            mint: "JUPyiwrYJFskUPiHa7hkeR8VUtAeFoSYbKedZNsDvCN".into(),
            decimals: 6,
            logo_uri: None,
        },
        TokenInfo {
            symbol: "JTO".into(),
            name: "Jito".into(),
            mint: "jtojtomepa8beP8AuQc6eXt5FriJwfFMwQx2v2f9mCL".into(),
            decimals: 9,
            logo_uri: None,
        },
        TokenInfo {
            symbol: "PYTH".into(),
            name: "Pyth Network".into(),
            mint: "HZ1JovNiVvGrGNiiYvEozEVgZ58xaU3RKwX8eACQBCt3".into(),
            decimals: 6,
            logo_uri: None,
        },
        TokenInfo {
            symbol: "RAY".into(),
            name: "Raydium".into(),
            mint: "4k3Dyjzvzp8eMZWUXbBCjEvwSkkk59S5iCNLY3QrkX6R".into(),
            decimals: 6,
            logo_uri: None,
        },
        TokenInfo {
            symbol: "ORCA".into(),
            name: "Orca".into(),
            mint: "orcaEKTdK7LKz57vaAYr9QeNsVEPfiu6QeMU1kektZE".into(),
            decimals: 6,
            logo_uri: None,
        },
        TokenInfo {
            symbol: "RENDER".into(),
            name: "Render Token".into(),
            mint: "rndrizKT3MK1iimdxRdWabcF7Zg7AR5T4nud4EkHBof".into(),
            decimals: 8,
            logo_uri: None,
        },
        TokenInfo {
            symbol: "HNT".into(),
            name: "Helium".into(),
            mint: "hntyVP6YFm1Hg25TN9WGLqM12b8TQmcknKrdu1oxWux".into(),
            decimals: 8,
            logo_uri: None,
        },
        TokenInfo {
            symbol: "TRUMP".into(),
            name: "Official Trump".into(),
            mint: "6p6xgHyF7AeE6TZkSmFsko444wqoP15icUSqi2jfGiPN".into(),
            decimals: 6,
            logo_uri: None,
        },
        TokenInfo {
            symbol: "FARTCOIN".into(),
            name: "Fartcoin".into(),
            mint: "9BB6NFEcjBCtnNLFko2FqVQBq8HHM13kCyYcdQbgpump".into(),
            decimals: 6,
            logo_uri: None,
        },
        TokenInfo {
            symbol: "AI16Z".into(),
            name: "ai16z".into(),
            mint: "HeLp6NuQkmYB4pYWo2zYs22mESHXPQYzXbB8n4V98jwC".into(),
            decimals: 9,
            logo_uri: None,
        },
        TokenInfo {
            symbol: "KAUSA".into(),
            name: "KausaLayer".into(),
            mint: "BWXSNRBKMviG68MqavyssnzDq4qSArcN7eNYjqEfpump".into(),
            decimals: 6,
            logo_uri: None,
        },
    ]
}

/// Resolve a token query to TokenInfo
///
/// Accepts:
/// - Symbol (case-insensitive): "USDC", "usdc", "JUP"
/// - Name (case-insensitive, partial match): "jupiter", "bonk"
/// - Direct contract address (mint): "DezXAZ8z7PnrnRJjz3wXBoRgixCa6xjnB7YaB1pPB263"
///
/// Returns None if not found in curated list AND input is not a valid base58 address
pub fn resolve_token(query: &str) -> Option<TokenInfo> {
    let tokens = curated_tokens();
    let query_upper = query.trim().to_uppercase();
    let query_lower = query.trim().to_lowercase();

    // 1. Exact symbol match (case-insensitive)
    if let Some(token) = tokens.iter().find(|t| t.symbol.to_uppercase() == query_upper) {
        return Some(token.clone());
    }

    // 2. Name match (case-insensitive, contains)
    if let Some(token) = tokens.iter().find(|t| t.name.to_lowercase().contains(&query_lower)) {
        return Some(token.clone());
    }

    // 3. Direct mint address match from curated list
    if let Some(token) = tokens.iter().find(|t| t.mint == query.trim()) {
        return Some(token.clone());
    }

    // 4. If query looks like a base58 address (32-44 chars, alphanumeric), treat as direct CA
    let trimmed = query.trim();
    if trimmed.len() >= 32 && trimmed.len() <= 44 && trimmed.chars().all(|c| c.is_alphanumeric()) {
        return Some(TokenInfo {
            symbol: "UNKNOWN".into(),
            name: "Unknown Token".into(),
            mint: trimmed.to_string(),
            decimals: 0, // Will be determined by Jupiter
            logo_uri: None,
        });
    }

    None
}

/// Get the curated token list (for frontend dropdown)
pub fn get_token_list() -> Vec<TokenInfo> {
    curated_tokens()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolve_by_symbol() {
        let token = resolve_token("JUP").unwrap();
        assert_eq!(token.mint, "JUPyiwrYJFskUPiHa7hkeR8VUtAeFoSYbKedZNsDvCN");

        let token = resolve_token("usdc").unwrap();
        assert_eq!(token.mint, "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v");
    }

    #[test]
    fn test_resolve_by_name() {
        let token = resolve_token("jupiter").unwrap();
        assert_eq!(token.symbol, "JUP");
    }

    #[test]
    fn test_resolve_by_ca() {
        let token = resolve_token("DezXAZ8z7PnrnRJjz3wXBoRgixCa6xjnB7YaB1pPB263").unwrap();
        assert_eq!(token.symbol, "UNKNOWN");
    }

    #[test]
    fn test_resolve_unknown_ca() {
        let token = resolve_token("7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU").unwrap();
        assert_eq!(token.symbol, "UNKNOWN");
        assert_eq!(token.mint, "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU");
    }

    #[test]
    fn test_resolve_invalid() {
        assert!(resolve_token("XYZNONEXISTENT").is_none());
    }
}
