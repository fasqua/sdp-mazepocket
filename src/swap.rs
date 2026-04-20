//! Jupiter Ultra API integration for Maze Pocket Swap
//!
//! Handles quote fetching and swap transaction execution
//! using the Jupiter Ultra (lite) API.

use serde::{Deserialize, Serialize};
use std::str::FromStr;
use solana_sdk::{
    pubkey::Pubkey,
    signature::{Keypair, Signer},
    transaction::VersionedTransaction,
};
use tracing::{info, warn};

use crate::error::{MazeError, Result};
use base64::Engine;

/// Jupiter Ultra API base URL
const JUPITER_ULTRA_BASE: &str = "https://lite-api.jup.ag/ultra/v1";

/// Swap quote request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwapQuoteRequest {
    pub input_mint: String,
    pub output_mint: String,
    pub amount: u64,
    pub taker: String,
    pub slippage_bps: Option<u16>,
}

/// Swap quote response (subset of Jupiter Ultra response)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwapQuoteResponse {
    pub success: bool,
    pub input_mint: String,
    pub output_mint: String,
    pub in_amount: String,
    pub out_amount: String,
    pub slippage_bps: u16,
    pub price_impact_pct: Option<String>,
    pub route_plan_count: usize,
    pub total_fees_lamports: u64,
    pub in_usd_value: Option<f64>,
    pub out_usd_value: Option<f64>,
}

/// Jupiter Ultra API raw response
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JupiterUltraResponse {
    pub input_mint: Option<String>,
    pub output_mint: Option<String>,
    pub in_amount: Option<String>,
    pub out_amount: Option<String>,
    pub slippage_bps: Option<serde_json::Value>,
    pub price_impact_pct: Option<String>,
    pub route_plan: Option<Vec<serde_json::Value>>,
    pub transaction: Option<String>,
    pub last_valid_block_height: Option<serde_json::Value>,
    pub request_id: Option<String>,
    pub taker: Option<String>,
    pub in_usd_value: Option<f64>,
    pub out_usd_value: Option<f64>,
    pub signature_fee_lamports: Option<serde_json::Value>,
    pub prioritization_fee_lamports: Option<serde_json::Value>,
    pub rent_fee_lamports: Option<serde_json::Value>,
    // Error fields
    pub error: Option<String>,
    pub success: Option<bool>,
}

/// Parse a JSON value that could be string or number into u64
fn parse_json_u64(val: &Option<serde_json::Value>, default: u64) -> u64 {
    match val {
        Some(serde_json::Value::Number(n)) => n.as_u64().unwrap_or(default),
        Some(serde_json::Value::String(s)) => s.parse::<u64>().unwrap_or(default),
        _ => default,
    }
}

fn parse_json_u16(val: &Option<serde_json::Value>, default: u16) -> u16 {
    match val {
        Some(serde_json::Value::Number(n)) => n.as_u64().unwrap_or(default as u64) as u16,
        Some(serde_json::Value::String(s)) => s.parse::<u16>().unwrap_or(default),
        _ => default,
    }
}

/// Swap execution result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwapResult {
    pub success: bool,
    pub tx_signature: Option<String>,
    pub in_amount: String,
    pub out_amount: String,
    pub input_mint: String,
    pub output_mint: String,
    pub request_id: Option<String>,
    pub error: Option<String>,
}

/// Fetch a swap quote from Jupiter Ultra API (no execution)
pub async fn get_swap_quote(
    http_client: &reqwest::Client,
    req: &SwapQuoteRequest,
) -> Result<SwapQuoteResponse> {
    let slippage = req.slippage_bps.unwrap_or(50); // Default 0.5%

    let url = format!(
        "{}/order?inputMint={}&outputMint={}&amount={}&taker={}&slippageBps={}",
        JUPITER_ULTRA_BASE,
        req.input_mint,
        req.output_mint,
        req.amount,
        req.taker,
        slippage,
    );

    info!("Jupiter quote: {} -> {}, amount={}", req.input_mint, req.output_mint, req.amount);

    let response = http_client
        .get(&url)
        .timeout(std::time::Duration::from_secs(15))
        .send()
        .await
        .map_err(|e| MazeError::RpcError(format!("Jupiter API request failed: {}", e)))?;

    let status = response.status();
    let body = response
        .text()
        .await
        .map_err(|e| MazeError::RpcError(format!("Jupiter API response read failed: {}", e)))?;

    if !status.is_success() {
        return Err(MazeError::RpcError(format!(
            "Jupiter API error ({}): {}",
            status, body
        )));
    }

    let jup: JupiterUltraResponse = serde_json::from_str(&body)
        .map_err(|e| MazeError::RpcError(format!("Jupiter response parse failed: {} | body: {}", e, &body[..200.min(body.len())])))?;

    // Check for error in response
    if let Some(ref err) = jup.error {
        return Err(MazeError::RpcError(format!("Jupiter error: {}", err)));
    }

    let in_amount = jup.in_amount.unwrap_or_default();
    let out_amount = jup.out_amount.unwrap_or_default();

    if in_amount.is_empty() || out_amount.is_empty() {
        return Err(MazeError::RpcError("Jupiter returned empty amounts".into()));
    }

    let route_count = jup.route_plan.as_ref().map(|r| r.len()).unwrap_or(0);
    let sig_fee = parse_json_u64(&jup.signature_fee_lamports, 5000);
    let prio_fee = parse_json_u64(&jup.prioritization_fee_lamports, 0);
    let rent_fee = parse_json_u64(&jup.rent_fee_lamports, 0);
    let total_fees = sig_fee + prio_fee + rent_fee;

    Ok(SwapQuoteResponse {
        success: true,
        input_mint: jup.input_mint.unwrap_or(req.input_mint.clone()),
        output_mint: jup.output_mint.unwrap_or(req.output_mint.clone()),
        in_amount,
        out_amount,
        slippage_bps: parse_json_u16(&jup.slippage_bps, slippage),
        price_impact_pct: jup.price_impact_pct,
        route_plan_count: route_count,
        total_fees_lamports: total_fees,
        in_usd_value: jup.in_usd_value,
        out_usd_value: jup.out_usd_value,
    })
}

/// Execute a swap: fetch order from Jupiter, sign with pocket keypair, submit to RPC
pub async fn execute_swap(
    http_client: &reqwest::Client,
    rpc_client: &solana_client::rpc_client::RpcClient,
    pocket_keypair: &Keypair,
    input_mint: &str,
    output_mint: &str,
    amount: u64,
    slippage_bps: Option<u16>,
) -> Result<SwapResult> {
    let taker = pocket_keypair.pubkey().to_string();
    let slippage = slippage_bps.unwrap_or(50);

    // 1. Get order (quote + transaction) from Jupiter Ultra
    let url = format!(
        "{}/order?inputMint={}&outputMint={}&amount={}&taker={}&slippageBps={}",
        JUPITER_ULTRA_BASE, input_mint, output_mint, amount, taker, slippage,
    );

    info!("Jupiter swap order: {} -> {}, amount={}, taker={}", input_mint, output_mint, amount, &taker[..20.min(taker.len())]);

    let response = http_client
        .get(&url)
        .timeout(std::time::Duration::from_secs(20))
        .send()
        .await
        .map_err(|e| MazeError::RpcError(format!("Jupiter order request failed: {}", e)))?;

    let status = response.status();
    let body = response
        .text()
        .await
        .map_err(|e| MazeError::RpcError(format!("Jupiter order response read failed: {}", e)))?;

    if !status.is_success() {
        return Ok(SwapResult {
            success: false,
            tx_signature: None,
            in_amount: amount.to_string(),
            out_amount: "0".into(),
            input_mint: input_mint.into(),
            output_mint: output_mint.into(),
            request_id: None,
            error: Some(format!("Jupiter API error ({}): {}", status, &body[..300.min(body.len())])),
        });
    }

    let jup: JupiterUltraResponse = serde_json::from_str(&body)
        .map_err(|e| MazeError::RpcError(format!("Jupiter order parse failed: {}", e)))?;

    if let Some(ref err) = jup.error {
        return Ok(SwapResult {
            success: false,
            tx_signature: None,
            in_amount: amount.to_string(),
            out_amount: "0".into(),
            input_mint: input_mint.into(),
            output_mint: output_mint.into(),
            request_id: jup.request_id.clone(),
            error: Some(format!("Jupiter error: {}", err)),
        });
    }

    let tx_base64 = match jup.transaction {
        Some(ref t) if !t.is_empty() => t.clone(),
        _ => {
            return Ok(SwapResult {
                success: false,
                tx_signature: None,
                in_amount: amount.to_string(),
                out_amount: "0".into(),
                input_mint: input_mint.into(),
                output_mint: output_mint.into(),
                request_id: jup.request_id.clone(),
                error: Some("Jupiter returned no transaction".into()),
            });
        }
    };

    let in_amount = jup.in_amount.clone().unwrap_or(amount.to_string());
    let out_amount = jup.out_amount.clone().unwrap_or("0".into());
    let request_id = jup.request_id.clone();

    // 2. Deserialize the transaction
    let tx_bytes = base64::engine::general_purpose::STANDARD.decode(&tx_base64)
        .map_err(|e| MazeError::CryptoError(format!("Base64 decode failed: {}", e)))?;

    let mut versioned_tx: VersionedTransaction = bincode::deserialize(&tx_bytes)
        .map_err(|e| MazeError::CryptoError(format!("Transaction deserialize failed: {}", e)))?;

    // 3. Sign the transaction with pocket keypair
    let message_bytes = versioned_tx.message.serialize();
    let signature = pocket_keypair.sign_message(&message_bytes);
    versioned_tx.signatures[0] = signature;

    // 4. Send the signed transaction with retries
    let mut last_err = String::new();
    let mut tx_sig = None;

    for attempt in 1..=3u8 {
        let config = solana_client::rpc_config::RpcSendTransactionConfig {
            skip_preflight: true,
            preflight_commitment: None,
            encoding: None,
            max_retries: Some(3),
            min_context_slot: None,
        };

        match rpc_client.send_transaction_with_config(&versioned_tx, config) {
            Ok(sig) => {
                if attempt > 1 {
                    info!("Swap TX succeeded on attempt {}/3", attempt);
                }
                tx_sig = Some(sig);
                break;
            }
            Err(e) => {
                let err_str = e.to_string();
                if err_str.contains("connection") || err_str.contains("timeout") || err_str.contains("closed") {
                    warn!("Swap TX attempt {}/3: {}", attempt, err_str);
                    last_err = err_str;
                    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
                    continue;
                }
                last_err = err_str;
                break;
            }
        }
    }

    let sig = match tx_sig {
        Some(s) => s,
        None => {
            return Ok(SwapResult {
                success: false,
                tx_signature: None,
                in_amount,
                out_amount,
                input_mint: input_mint.into(),
                output_mint: output_mint.into(),
                request_id,
                error: Some(format!("TX send failed: {}", last_err)),
            });
        }
    };

    // 5. Wait for confirmation
    let mut confirmed = false;
    for _ in 0..40 {
        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
        if let Ok(Some(result)) = rpc_client.get_signature_status(&sig) {
            if result.is_ok() {
                confirmed = true;
                break;
            } else if let Err(e) = result {
                return Ok(SwapResult {
                    success: false,
                    tx_signature: Some(sig.to_string()),
                    in_amount,
                    out_amount,
                    input_mint: input_mint.into(),
                    output_mint: output_mint.into(),
                    request_id,
                    error: Some(format!("TX failed on-chain: {:?}", e)),
                });
            }
        }
    }

    if !confirmed {
        return Ok(SwapResult {
            success: false,
            tx_signature: Some(sig.to_string()),
            in_amount,
            out_amount,
            input_mint: input_mint.into(),
            output_mint: output_mint.into(),
            request_id,
            error: Some("TX confirmation timeout (20s)".into()),
        });
    }

    info!("Swap completed: {} {} -> {} ({})", in_amount, input_mint, output_mint, sig);

    Ok(SwapResult {
        success: true,
        tx_signature: Some(sig.to_string()),
        in_amount,
        out_amount,
        input_mint: input_mint.into(),
        output_mint: output_mint.into(),
        request_id,
        error: None,
    })
}

/// Resolve token metadata via DexScreener API
/// Used when token is not in curated list (user inputs raw CA)
pub async fn resolve_token_dexscreener(
    http_client: &reqwest::Client,
    mint: &str,
) -> Option<crate::tokens::TokenInfo> {
    let url = format!("https://api.dexscreener.com/tokens/v1/solana/{}", mint);

    let response = match http_client
        .get(&url)
        .timeout(std::time::Duration::from_secs(8))
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            warn!("DexScreener lookup failed for {}: {}", mint, e);
            return None;
        }
    };

    if !response.status().is_success() {
        return None;
    }

    let body = match response.text().await {
        Ok(b) => b,
        Err(_) => return None,
    };

    // DexScreener returns array of pairs, take the first one
    let pairs: Vec<serde_json::Value> = match serde_json::from_str(&body) {
        Ok(p) => p,
        Err(_) => return None,
    };

    let pair = pairs.first()?;
    let base_token = pair.get("baseToken")?;

    let symbol = base_token.get("symbol")?.as_str()?.to_string();
    let name = base_token.get("name")?.as_str()?.to_string().trim().to_string();
    let address = base_token.get("address")?.as_str()?.to_string();

    // DexScreener doesn't return decimals directly, default to 6
    // (most Solana SPL tokens use 6 or 9 decimals)
    Some(crate::tokens::TokenInfo {
        symbol,
        name,
        mint: address,
        decimals: 6,
        logo_uri: None,
    })
}

/// Token balance info for a pocket
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenBalance {
    pub mint: String,
    pub symbol: String,
    pub name: String,
    pub decimals: u8,
    pub balance_raw: u64,
    pub balance_formatted: f64,
    pub token_program: String,
}

/// Scan all SPL token balances in a pocket address
/// Queries both SPL Token (classic) and Token-2022 programs
pub fn scan_token_balances(
    rpc_client: &solana_client::rpc_client::RpcClient,
    owner: &solana_sdk::pubkey::Pubkey,
) -> Vec<(String, u64, String)> {
    use solana_client::rpc_request::TokenAccountsFilter;

    let spl_token_program = Pubkey::from_str("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA").unwrap();
    let token_2022_program = Pubkey::from_str("TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb").unwrap();

    let mut results: Vec<(String, u64, String)> = Vec::new();

    // Query SPL Token classic
    if let Ok(accounts) = rpc_client.get_token_accounts_by_owner(
        owner,
        TokenAccountsFilter::ProgramId(spl_token_program),
    ) {
        for account in accounts {
            if let Some(parsed) = parse_token_account(&account.account.data) {
                if parsed.1 > 0 {
                    results.push((parsed.0, parsed.1, "spl-token".to_string()));
                }
            }
        }
    }

    // Query Token-2022
    if let Ok(accounts) = rpc_client.get_token_accounts_by_owner(
        owner,
        TokenAccountsFilter::ProgramId(token_2022_program),
    ) {
        for account in accounts {
            if let Some(parsed) = parse_token_account(&account.account.data) {
                if parsed.1 > 0 {
                    results.push((parsed.0, parsed.1, "token-2022".to_string()));
                }
            }
        }
    }

    results
}

/// Parse token account data to extract mint and amount
/// Returns (mint_address, amount) or None
fn parse_token_account(data: &solana_account_decoder::UiAccountData) -> Option<(String, u64)> {
    use solana_account_decoder::UiAccountData;

    match data {
        UiAccountData::Json(parsed) => {
            let info = parsed.parsed.get("info")?;
            let mint = info.get("mint")?.as_str()?.to_string();
            let token_amount = info.get("tokenAmount")?;
            let amount_str = token_amount.get("amount")?.as_str()?;
            let amount = amount_str.parse::<u64>().ok()?;
            Some((mint, amount))
        }
        _ => None,
    }
}
