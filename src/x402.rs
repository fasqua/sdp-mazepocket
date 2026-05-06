//! x402 Protocol Client for KausaPay (v2 spec compliant)
//!
//! Implements the client-side of the x402 v2 payment protocol (Coinbase spec).
//! Handles: Base64-decoded challenges, accepts array parsing,
//! building payment payloads, signing SPL token transfers.

use serde::{Deserialize, Serialize};
use solana_sdk::{
    pubkey::Pubkey,
    signature::{Keypair, Signer},
    transaction::Transaction,
};
use std::str::FromStr;
use tracing::{info, warn};
use base64::Engine;

use crate::error::{MazeError, Result};

/// USDC mint on Solana mainnet
pub const USDC_MINT: &str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
/// USDT mint on Solana mainnet
pub const USDT_MINT: &str = "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB";
/// USDC/USDT decimals on Solana
pub const STABLECOIN_DECIMALS: u8 = 6;
/// Solana mainnet CAIP-2 identifier
pub const SOLANA_MAINNET_CAIP2: &str = "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp";

/// Parsed x402 payment challenge from HTTP 402 response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct X402Challenge {
    /// Payment recipient address (Solana pubkey) - "payTo" in v2
    pub recipient: String,
    /// Amount in smallest unit (e.g. 10000 = 0.01 USDC)
    pub amount_raw: u64,
    /// Amount in human-readable form (e.g. 0.01)
    pub amount_display: f64,
    /// Token mint address (USDC or USDT)
    pub token_mint: String,
    /// Token symbol for display
    pub token_symbol: String,
    /// Network identifier from challenge (CAIP-2 format)
    pub network: String,
    /// Original raw header value
    pub raw_header: String,
    /// Optional: extra payload required by the server
    pub extra_payload: Option<String>,
    /// Optional: fee payer address (server-side gas sponsorship)
    pub fee_payer: Option<String>,
}

/// Result of an x402 payment attempt
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct X402PaymentResult {
    pub success: bool,
    pub response_body: Option<String>,
    pub response_status: u16,
    pub tx_signature: Option<String>,
    pub amount_paid: f64,
    pub token_symbol: String,
    pub error: Option<String>,
}

/// Parse x402 v2 challenge from PAYMENT-REQUIRED header.
///
/// x402 v2 spec: header value is Base64-encoded JSON with structure:
/// {
///   "x402Version": 2,
///   "accepts": [
///     {
///       "scheme": "exact",
///       "network": "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp",
///       "amount": "10000",
///       "payTo": "RECIPIENT_PUBKEY",
///       "asset": "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
///       "maxTimeoutSeconds": 60,
///       "extra": { "feePayer": "...", "description": "..." }
///     }
///   ]
/// }
///
/// Also supports v1 format (raw JSON) as fallback.
pub fn parse_x402_challenge(header_value: &str) -> Result<X402Challenge> {
    let trimmed = header_value.trim();

    // Try Base64 decode first (v2 format)
    let json_str = if let Ok(decoded_bytes) = base64::engine::general_purpose::STANDARD.decode(trimmed) {
        if let Ok(s) = String::from_utf8(decoded_bytes) {
            s
        } else {
            trimmed.to_string()
        }
    } else {
        // Not Base64 — try as raw JSON (v1 fallback)
        trimmed.to_string()
    };

    let parsed: serde_json::Value = serde_json::from_str(&json_str)
        .map_err(|e| MazeError::InvalidParameters(
            format!("Failed to parse x402 challenge JSON: {}. Raw: {}", e, &json_str[..200.min(json_str.len())])
        ))?;

    // Check if v2 format with "accepts" array
    if let Some(accepts) = parsed.get("accepts").and_then(|v| v.as_array()) {
        return parse_v2_accepts(accepts, &json_str);
    }

    // Fallback: v1 flat format
    parse_v1_flat(&parsed, trimmed)
}

/// Parse x402 v2 "accepts" array — find the Solana entry
fn parse_v2_accepts(accepts: &[serde_json::Value], raw: &str) -> Result<X402Challenge> {
    // Find the first Solana-compatible entry
    let solana_entry = accepts.iter().find(|entry| {
        if let Some(network) = entry.get("network").and_then(|v| v.as_str()) {
            is_solana_network(network)
        } else {
            false
        }
    });

    let entry = match solana_entry {
        Some(e) => e,
        None => {
            // List available networks for error message
            let networks: Vec<&str> = accepts.iter()
                .filter_map(|e| e.get("network").and_then(|v| v.as_str()))
                .collect();
            return Err(MazeError::InvalidParameters(
                format!("No Solana payment option found. Available networks: {:?}. KausaPay only supports Solana.", networks)
            ));
        }
    };

    // Extract payTo (v2) or recipient (v1)
    let recipient = entry.get("payTo")
        .or_else(|| entry.get("recipient"))
        .or_else(|| entry.get("pay_to"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| MazeError::InvalidParameters("x402 challenge missing 'payTo' field".into()))?
        .to_string();

    // Validate recipient is valid Solana pubkey
    Pubkey::from_str(&recipient)
        .map_err(|_| MazeError::InvalidParameters(format!("x402 payTo is not a valid Solana address: {}", recipient)))?;

    // Extract amount
    let amount_raw = match entry.get("amount").or_else(|| entry.get("maxAmountRequired")) {
        Some(serde_json::Value::String(s)) => s.parse::<u64>()
            .map_err(|_| MazeError::InvalidParameters(format!("x402 amount not valid: {}", s)))?,
        Some(serde_json::Value::Number(n)) => n.as_u64()
            .ok_or_else(|| MazeError::InvalidParameters("x402 amount not a positive integer".into()))?,
        _ => return Err(MazeError::InvalidParameters("x402 challenge missing 'amount' field".into())),
    };

    // Extract asset
    let asset = entry.get("asset")
        .or_else(|| entry.get("token"))
        .and_then(|v| v.as_str())
        .unwrap_or(USDC_MINT);

    let (token_mint, token_symbol) = identify_stablecoin(asset)?;

    // Extract network
    let network = entry.get("network")
        .and_then(|v| v.as_str())
        .unwrap_or(SOLANA_MAINNET_CAIP2)
        .to_string();

    let amount_display = amount_raw as f64 / 10f64.powi(STABLECOIN_DECIMALS as i32);

    // Extract extra
    let extra = entry.get("extra");
    let extra_payload = extra.map(|v| v.to_string());
    let fee_payer = extra
        .and_then(|e| e.get("feePayer"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    Ok(X402Challenge {
        recipient,
        amount_raw,
        amount_display,
        token_mint,
        token_symbol,
        network,
        raw_header: raw.to_string(),
        extra_payload,
        fee_payer,
    })
}

/// Parse v1 flat JSON format (fallback)
fn parse_v1_flat(parsed: &serde_json::Value, raw: &str) -> Result<X402Challenge> {
    let recipient = parsed.get("recipient")
        .or_else(|| parsed.get("payTo"))
        .or_else(|| parsed.get("pay_to"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| MazeError::InvalidParameters("x402 challenge missing 'recipient'/'payTo' field".into()))?
        .to_string();

    Pubkey::from_str(&recipient)
        .map_err(|_| MazeError::InvalidParameters(format!("x402 recipient is not a valid Solana address: {}", recipient)))?;

    let amount_raw = match parsed.get("amount").or_else(|| parsed.get("maxAmountRequired")) {
        Some(serde_json::Value::String(s)) => s.parse::<u64>()
            .map_err(|_| MazeError::InvalidParameters(format!("x402 amount not valid: {}", s)))?,
        Some(serde_json::Value::Number(n)) => n.as_u64()
            .ok_or_else(|| MazeError::InvalidParameters("x402 amount not a positive integer".into()))?,
        _ => return Err(MazeError::InvalidParameters("x402 challenge missing 'amount' field".into())),
    };

    let asset = parsed.get("asset")
        .or_else(|| parsed.get("token"))
        .or_else(|| parsed.get("currency"))
        .and_then(|v| v.as_str())
        .unwrap_or(USDC_MINT);

    let (token_mint, token_symbol) = identify_stablecoin(asset)?;

    let network = parsed.get("network")
        .or_else(|| parsed.get("chain"))
        .and_then(|v| v.as_str())
        .unwrap_or("solana:mainnet")
        .to_string();

    validate_solana_network(&network)?;

    let amount_display = amount_raw as f64 / 10f64.powi(STABLECOIN_DECIMALS as i32);

    let extra_payload = parsed.get("extra")
        .or_else(|| parsed.get("payload"))
        .map(|v| v.to_string());

    Ok(X402Challenge {
        recipient,
        amount_raw,
        amount_display,
        token_mint,
        token_symbol,
        network,
        raw_header: raw.to_string(),
        extra_payload,
        fee_payer: None,
    })
}

/// Check if network string refers to Solana
fn is_solana_network(network: &str) -> bool {
    let net_lower = network.to_lowercase();
    net_lower.starts_with("solana:") || net_lower.contains("solana") || net_lower.contains("sol")
}

/// Identify stablecoin from asset identifier.
fn identify_stablecoin(asset: &str) -> Result<(String, String)> {
    let asset_upper = asset.trim().to_uppercase();

    if asset.trim() == USDC_MINT {
        return Ok((USDC_MINT.to_string(), "USDC".to_string()));
    }
    if asset.trim() == USDT_MINT {
        return Ok((USDT_MINT.to_string(), "USDT".to_string()));
    }

    match asset_upper.as_str() {
        "USDC" | "USD COIN" | "USDCOIN" => Ok((USDC_MINT.to_string(), "USDC".to_string())),
        "USDT" | "TETHER" | "TETHER USD" => Ok((USDT_MINT.to_string(), "USDT".to_string())),
        _ => Err(MazeError::InvalidParameters(
            format!("Unsupported payment token: {}. KausaPay only supports USDC and USDT.", asset)
        )),
    }
}

/// Validate that the network is Solana (v1 format validation)
fn validate_solana_network(network: &str) -> Result<()> {
    if is_solana_network(network) || network.is_empty() || network == "mainnet" {
        return Ok(());
    }
    Err(MazeError::InvalidParameters(
        format!("x402 challenge requires payment on '{}', but KausaPay only supports Solana.", network)
    ))
}

/// Execute x402 v2 payment flow (facilitator-based)
///
/// x402 v2 SVM spec: client builds a transaction with facilitator as fee payer,
/// partially signs it (pocket signs as token authority), then sends the
/// serialized transaction in PAYMENT-SIGNATURE header. The facilitator
/// co-signs as fee payer and submits to the network.
pub async fn execute_x402_payment(
    http_client: &reqwest::Client,
    rpc_client: &solana_client::rpc_client::RpcClient,
    pocket_keypair: &Keypair,
    challenge: &X402Challenge,
    max_amount_usdc: f64,
    original_url: &str,
    method: &str,
    request_body: Option<&str>,
) -> Result<X402PaymentResult> {
    let token_symbol = challenge.token_symbol.clone();

    // Safety check: amount vs max
    if challenge.amount_display > max_amount_usdc {
        return Ok(X402PaymentResult {
            success: false, response_body: None, response_status: 402,
            tx_signature: None, amount_paid: 0.0, token_symbol,
            error: Some(format!(
                "Payment exceeds max_amount_usdc limit. Required: {} {}, Max allowed: {} USDC",
                challenge.amount_display, challenge.token_symbol, max_amount_usdc
            )),
        });
    }

    let pocket_pubkey = pocket_keypair.pubkey();
    let token_mint_pubkey = Pubkey::from_str(&challenge.token_mint)
        .map_err(|e| MazeError::InvalidParameters(format!("Invalid token mint: {}", e)))?;
    let recipient_pubkey = Pubkey::from_str(&challenge.recipient)
        .map_err(|e| MazeError::InvalidParameters(format!("Invalid recipient: {}", e)))?;

    // Get pocket ATA
    let pocket_ata = spl_associated_token_account::get_associated_token_address(
        &pocket_pubkey,
        &token_mint_pubkey,
    );

    // Check token balance
    let token_balance = match rpc_client.get_token_account_balance(&pocket_ata) {
        Ok(balance) => balance.amount.parse::<u64>().unwrap_or(0),
        Err(_) => {
            return Ok(X402PaymentResult {
                success: false, response_body: None, response_status: 402,
                tx_signature: None, amount_paid: 0.0, token_symbol,
                error: Some(format!(
                    "Insufficient {} balance. No token account found. Swap SOL to {} first.",
                    challenge.token_symbol, challenge.token_symbol
                )),
            });
        }
    };

    if token_balance < challenge.amount_raw {
        let current = token_balance as f64 / 10f64.powi(STABLECOIN_DECIMALS as i32);
        return Ok(X402PaymentResult {
            success: false, response_body: None, response_status: 402,
            tx_signature: None, amount_paid: 0.0, token_symbol,
            error: Some(format!(
                "Insufficient {} balance. Have: {:.6}, Need: {:.6}. Swap SOL to {} first.",
                challenge.token_symbol, current, challenge.amount_display, challenge.token_symbol
            )),
        });
    }

    // Determine fee payer: facilitator (from challenge) or pocket (fallback)
    let fee_payer_pubkey = if let Some(ref fp) = challenge.fee_payer {
        Pubkey::from_str(fp).unwrap_or(pocket_pubkey)
    } else {
        pocket_pubkey
    };
    let has_facilitator = challenge.fee_payer.is_some() && fee_payer_pubkey != pocket_pubkey;

    // If no facilitator, check SOL for fees (pocket pays gas)
    if !has_facilitator {
        let sol_balance = rpc_client.get_balance(&pocket_pubkey)
            .map_err(|e| MazeError::RpcError(format!("Failed to get SOL balance: {}", e)))?;
        if sol_balance < 10_000 {
            return Ok(X402PaymentResult {
                success: false, response_body: None, response_status: 402,
                tx_signature: None, amount_paid: 0.0, token_symbol,
                error: Some("Insufficient SOL for transaction fees. Need at least 0.00001 SOL.".into()),
            });
        }
    }

    // Build recipient ATA
    let recipient_ata = spl_associated_token_account::get_associated_token_address(
        &recipient_pubkey,
        &token_mint_pubkey,
    );

    // Get recent blockhash
    let blockhash = rpc_client.get_latest_blockhash()
        .map_err(|e| MazeError::RpcError(format!("Failed to get blockhash: {}", e)))?;

    if has_facilitator {
        // === FACILITATOR MODE: exactly 3 instructions per x402 v2 SVM spec ===
        // 1. SetComputeUnitLimit  2. SetComputeUnitPrice  3. TransferChecked
        let mut instructions = Vec::new();

        instructions.push(
            solana_sdk::compute_budget::ComputeBudgetInstruction::set_compute_unit_limit(40_000)
        );
        instructions.push(
            solana_sdk::compute_budget::ComputeBudgetInstruction::set_compute_unit_price(1)
        );
        instructions.push(
            spl_token::instruction::transfer_checked(
                &spl_token::id(),
                &pocket_ata,           // source
                &token_mint_pubkey,    // mint
                &recipient_ata,        // destination
                &pocket_pubkey,        // authority
                &[],                   // signers
                challenge.amount_raw,  // amount
                STABLECOIN_DECIMALS,   // decimals (6 for USDC/USDT)
            ).map_err(|e| MazeError::TransactionError(format!("Failed to build transfer_checked: {}", e)))?
        );
        // === FACILITATOR MODE (x402 v2 standard) ===
        // Build TX with facilitator as fee payer, pocket partially signs
        // Facilitator will co-sign and submit

        let message = solana_sdk::message::Message::new_with_blockhash(
            &instructions,
            Some(&fee_payer_pubkey),
            &blockhash,
        );
        let mut tx = Transaction::new_unsigned(message);

        // Partially sign: pocket signs as token authority (index may vary)
        // Find pocket's position in account_keys and sign
        tx.partial_sign(&[pocket_keypair], blockhash);

        // Serialize the partially-signed transaction to Base64
        let tx_bytes = bincode::serialize(&tx)
            .map_err(|e| MazeError::TransactionError(format!("Failed to serialize TX: {}", e)))?;
        let tx_b64 = base64::engine::general_purpose::STANDARD.encode(&tx_bytes);

        info!("x402 facilitator mode: built TX for {} {} to {}, fee_payer={}",
            challenge.amount_display, challenge.token_symbol,
            &challenge.recipient[..16.min(challenge.recipient.len())],
            &fee_payer_pubkey.to_string()[..16]);

        // Build v2 PAYMENT-SIGNATURE payload (x402 v2 SVM spec)
        // "accepted" must be deepEqual to the original accepts entry for server matching
        let mut accepted = serde_json::json!({
            "scheme": "exact",
            "network": challenge.network,
            "amount": challenge.amount_raw.to_string(),
            "asset": challenge.token_mint,
            "payTo": challenge.recipient,
            "maxTimeoutSeconds": 300
        });
        if let Some(ref extra) = challenge.extra_payload {
            if let Ok(extra_val) = serde_json::from_str::<serde_json::Value>(extra) {
                accepted["extra"] = extra_val;
            }
        }
        let payment_payload = serde_json::json!({
            "x402Version": 2,
            "scheme": "exact",
            "network": challenge.network,
            "payload": {
                "transaction": tx_b64
            },
            "accepted": accepted
        });
        let payment_b64 = base64::engine::general_purpose::STANDARD.encode(
            payment_payload.to_string().as_bytes()
        );

        // Retry with PAYMENT-SIGNATURE header (use same method as original request)
        let mut retry_req = match method {
            "POST" => http_client.post(original_url),
            "PUT" => http_client.put(original_url),
            "PATCH" => http_client.patch(original_url),
            "DELETE" => http_client.delete(original_url),
            _ => http_client.get(original_url),
        };
        retry_req = retry_req
            .header("PAYMENT-SIGNATURE", &payment_b64)
            .timeout(std::time::Duration::from_secs(30));
        if let Some(body) = request_body {
            retry_req = retry_req.header("Content-Type", "application/json").body(body.to_string());
        }
        let final_response = retry_req
            .send()
            .await
            .map_err(|e| MazeError::RpcError(format!("Failed to fetch paid content: {}", e)))?;

        let final_status = final_response.status().as_u16();

        // Try to extract TX signature from PAYMENT-RESPONSE header
        let payment_response_header = final_response.headers()
            .get("payment-response")
            .or_else(|| final_response.headers().get("PAYMENT-RESPONSE"))
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        let tx_sig_from_response = payment_response_header.as_ref().and_then(|h| {
            if let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(h.trim()) {
                if let Ok(json_str) = String::from_utf8(decoded) {
                    if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&json_str) {
                        return parsed.get("transaction")
                            .or_else(|| parsed.get("signature"))
                            .or_else(|| parsed.get("txHash"))
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string());
                    }
                }
            }
            None
        });

        let response_body = final_response.text().await
            .map_err(|e| MazeError::RpcError(format!("Failed to read paid content: {}", e)))?;

        info!("x402 facilitator retry result: status={}, payment_response_header={:?}, body={}",
            final_status, payment_response_header, &response_body[..500.min(response_body.len())]);

        if final_status >= 200 && final_status < 300 {
            Ok(X402PaymentResult {
                success: true,
                response_body: Some(response_body),
                response_status: final_status,
                tx_signature: tx_sig_from_response,
                amount_paid: challenge.amount_display,
                token_symbol: challenge.token_symbol.clone(),
                error: None,
            })
        } else if final_status == 402 {
            Ok(X402PaymentResult {
                success: false,
                response_body: Some(response_body),
                response_status: final_status,
                tx_signature: tx_sig_from_response,
                amount_paid: challenge.amount_display,
                token_symbol: challenge.token_symbol.clone(),
                error: Some("Payment submitted but server has not verified yet. TX may need more confirmations.".into()),
            })
        } else {
            Ok(X402PaymentResult {
                success: false,
                response_body: Some(response_body),
                response_status: final_status,
                tx_signature: tx_sig_from_response,
                amount_paid: challenge.amount_display,
                token_symbol: challenge.token_symbol.clone(),
                error: Some(format!("Server returned HTTP {} after payment", final_status)),
            })
        }
    } else {
        // === DIRECT MODE (no facilitator, pocket pays gas and submits) ===
        // For simple x402 servers that verify TX on-chain directly
        let mut instructions = Vec::new();

        instructions.push(
            solana_sdk::compute_budget::ComputeBudgetInstruction::set_compute_unit_limit(200_000)
        );
        instructions.push(
            solana_sdk::compute_budget::ComputeBudgetInstruction::set_compute_unit_price(1)
        );

        // Create recipient ATA if needed (pocket pays)
        let recipient_ata_exists = rpc_client.get_account(&recipient_ata).is_ok();
        if !recipient_ata_exists {
            instructions.push(
                spl_associated_token_account::instruction::create_associated_token_account(
                    &pocket_pubkey, &recipient_pubkey, &token_mint_pubkey, &spl_token::id(),
                )
            );
        }

        instructions.push(
            spl_token::instruction::transfer_checked(
                &spl_token::id(),
                &pocket_ata,
                &token_mint_pubkey,
                &recipient_ata,
                &pocket_pubkey,
                &[],
                challenge.amount_raw,
                STABLECOIN_DECIMALS,
            ).map_err(|e| MazeError::TransactionError(format!("Failed to build transfer_checked: {}", e)))?
        );

        let tx = Transaction::new_signed_with_payer(
            &instructions,
            Some(&pocket_pubkey),
            &[pocket_keypair],
            blockhash,
        );

        // Submit transaction
        let tx_signature = send_direct_payment(rpc_client, &tx).await?;

        info!("x402 direct mode: {} {} to {} ({})",
            challenge.amount_display, challenge.token_symbol,
            &challenge.recipient[..16.min(challenge.recipient.len())], tx_signature);

        // Build v2 payment proof
        let payment_payload = serde_json::json!({
            "x402Version": 2,
            "scheme": "exact",
            "network": challenge.network,
            "payload": {
                "signature": tx_signature,
                "from": pocket_pubkey.to_string(),
                "to": challenge.recipient,
                "amount": challenge.amount_raw.to_string(),
                "asset": challenge.token_mint,
            }
        });
        let payment_b64 = base64::engine::general_purpose::STANDARD.encode(
            payment_payload.to_string().as_bytes()
        );

        // Retry with PAYMENT-SIGNATURE header (use same method as original request)
        let mut retry_req2 = match method {
            "POST" => http_client.post(original_url),
            "PUT" => http_client.put(original_url),
            "PATCH" => http_client.patch(original_url),
            "DELETE" => http_client.delete(original_url),
            _ => http_client.get(original_url),
        };
        retry_req2 = retry_req2
            .header("PAYMENT-SIGNATURE", &payment_b64)
            .timeout(std::time::Duration::from_secs(30));
        if let Some(body) = request_body {
            retry_req2 = retry_req2.header("Content-Type", "application/json").body(body.to_string());
        }
        let final_response = retry_req2
            .send()
            .await
            .map_err(|e| MazeError::RpcError(format!("Failed to fetch paid content: {}", e)))?;

        let final_status = final_response.status().as_u16();
        let response_body = final_response.text().await
            .map_err(|e| MazeError::RpcError(format!("Failed to read paid content: {}", e)))?;

        if final_status >= 200 && final_status < 300 {
            Ok(X402PaymentResult {
                success: true,
                response_body: Some(response_body),
                response_status: final_status,
                tx_signature: Some(tx_signature),
                amount_paid: challenge.amount_display,
                token_symbol: challenge.token_symbol.clone(),
                error: None,
            })
        } else if final_status == 402 {
            Ok(X402PaymentResult {
                success: false,
                response_body: Some(response_body),
                response_status: final_status,
                tx_signature: Some(tx_signature),
                amount_paid: challenge.amount_display,
                token_symbol: challenge.token_symbol.clone(),
                error: Some("Payment submitted but server has not verified yet.".into()),
            })
        } else {
            Ok(X402PaymentResult {
                success: false,
                response_body: Some(response_body),
                response_status: final_status,
                tx_signature: Some(tx_signature),
                amount_paid: challenge.amount_display,
                token_symbol: challenge.token_symbol.clone(),
                error: Some(format!("Server returned HTTP {} after payment", final_status)),
            })
        }
    }
}

/// Send a direct payment transaction (no facilitator) with retries
async fn send_direct_payment(
    rpc_client: &solana_client::rpc_client::RpcClient,
    tx: &Transaction,
) -> Result<String> {
    let mut last_err = String::new();

    for attempt in 1..=5u8 {
        let config = solana_client::rpc_config::RpcSendTransactionConfig {
            skip_preflight: true, preflight_commitment: None,
            encoding: None, max_retries: Some(3), min_context_slot: None,
        };

        match rpc_client.send_transaction_with_config(tx, config) {
            Ok(sig) => {
                if attempt > 1 {
                    info!("x402 direct payment TX succeeded on attempt {}/5", attempt);
                }
                // Wait for confirmation
                let mut confirmed = false;
                for _ in 0..30 {
                    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
                    if let Ok(Some(result)) = rpc_client.get_signature_status(&sig) {
                        if result.is_ok() {
                            confirmed = true;
                            break;
                        } else if let Err(e) = result {
                            return Err(MazeError::TransactionError(
                                format!("x402 payment TX failed on-chain: {:?}", e)
                            ));
                        }
                    }
                }
                if !confirmed {
                    return Err(MazeError::TransactionError(
                        "x402 payment TX confirmation timeout (15s)".into()
                    ));
                }
                return Ok(sig.to_string());
            }
            Err(e) => {
                let err_str = e.to_string();
                if err_str.contains("connection") || err_str.contains("timeout") || err_str.contains("closed") {
                    warn!("x402 direct payment attempt {}/5: {}", attempt, err_str);
                    last_err = err_str;
                    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
                    continue;
                }
                return Err(MazeError::TransactionError(format!("x402 payment TX failed: {}", e)));
            }
        }
    }

    Err(MazeError::TransactionError(
        format!("x402 payment TX failed after 5 attempts: {}", last_err)
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_v2_base64_challenge() {
        // Real PayAI format
        let json = r#"{"x402Version":2,"accepts":[{"scheme":"exact","network":"solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp","amount":"10000","payTo":"H32YnqbzL62YkHMSCzfKcLry9yuipwwx1EMztiCSPhjb","maxTimeoutSeconds":60,"asset":"EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v","extra":{"feePayer":"2wKupLR9q6wXYppw8Gr2NvWxKBUqm4PPJKkQfoxHDBg4"}}]}"#;
        let b64 = base64::engine::general_purpose::STANDARD.encode(json.as_bytes());

        let challenge = parse_x402_challenge(&b64).unwrap();
        assert_eq!(challenge.recipient, "H32YnqbzL62YkHMSCzfKcLry9yuipwwx1EMztiCSPhjb");
        assert_eq!(challenge.amount_raw, 10000);
        assert_eq!(challenge.amount_display, 0.01);
        assert_eq!(challenge.token_symbol, "USDC");
        assert_eq!(challenge.network, "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp");
        assert_eq!(challenge.fee_payer.as_deref(), Some("2wKupLR9q6wXYppw8Gr2NvWxKBUqm4PPJKkQfoxHDBg4"));
    }

    #[test]
    fn test_parse_v2_multi_network_picks_solana() {
        let json = r#"{"x402Version":2,"accepts":[{"scheme":"exact","network":"eip155:8453","amount":"10000","payTo":"0xABC","asset":"0x036CbD"},{"scheme":"exact","network":"solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp","amount":"10000","payTo":"11111111111111111111111111111112","asset":"EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"}]}"#;
        let b64 = base64::engine::general_purpose::STANDARD.encode(json.as_bytes());

        let challenge = parse_x402_challenge(&b64).unwrap();
        assert_eq!(challenge.recipient, "11111111111111111111111111111112");
        assert_eq!(challenge.network, "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp");
    }

    #[test]
    fn test_parse_v2_no_solana_option() {
        let json = r#"{"x402Version":2,"accepts":[{"scheme":"exact","network":"eip155:8453","amount":"10000","payTo":"0xABC","asset":"0x036CbD"}]}"#;
        let b64 = base64::engine::general_purpose::STANDARD.encode(json.as_bytes());

        let result = parse_x402_challenge(&b64);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_v1_fallback() {
        let header = r#"{"recipient":"11111111111111111111111111111112","amount":"1000000","asset":"EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v","network":"solana:mainnet"}"#;

        let challenge = parse_x402_challenge(header).unwrap();
        assert_eq!(challenge.recipient, "11111111111111111111111111111112");
        assert_eq!(challenge.amount_raw, 1000000);
        assert_eq!(challenge.token_symbol, "USDC");
    }

    #[test]
    fn test_identify_stablecoin() {
        assert_eq!(identify_stablecoin("USDC").unwrap().1, "USDC");
        assert_eq!(identify_stablecoin("usdt").unwrap().1, "USDT");
        assert_eq!(identify_stablecoin(USDC_MINT).unwrap().1, "USDC");
        assert!(identify_stablecoin("DAI").is_err());
    }

    #[test]
    fn test_is_solana_network() {
        assert!(is_solana_network("solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp"));
        assert!(is_solana_network("solana:mainnet"));
        assert!(!is_solana_network("eip155:8453"));
        assert!(!is_solana_network("ethereum:mainnet"));
    }
}
