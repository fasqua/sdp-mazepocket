//! MPP (Machine Payments Protocol) Client for KausaPay
//!
//! Implements the client-side of the MPP protocol (Tempo/Stripe spec).
//! MPP uses WWW-Authenticate: Payment header for challenges
//! and Authorization: Payment header for credentials.
//! Backward-compatible with x402 "charge" intent.

use serde::{Deserialize, Serialize};
use solana_sdk::{
    pubkey::Pubkey,
    signature::{Keypair, Signer},
    transaction::Transaction,
};
use std::str::FromStr;
use tracing::info;
use base64::Engine;

use crate::error::{MazeError, Result};
use crate::x402::{self, X402Challenge, X402PaymentResult, USDC_MINT, STABLECOIN_DECIMALS, SOLANA_MAINNET_CAIP2};

/// Parsed MPP payment challenge from WWW-Authenticate: Payment header
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MppChallenge {
    /// Payment ID from challenge
    pub id: String,
    /// Server realm
    pub realm: String,
    /// Payment method (e.g. "solana")
    pub method: String,
    /// Payment intent (e.g. "charge")
    pub intent: String,
    /// Description of what is being paid for
    pub description: String,
    /// Expiration time
    pub expires: String,
    /// Decoded request data
    pub request: MppRequest,
    /// Raw header value
    pub raw_header: String,
}

/// Decoded MPP request data (from Base64 "request" field)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MppRequest {
    pub amount: String,
    pub currency: String,
    pub recipient: String,
    pub decimals: u8,
    pub fee_payer: bool,
    pub fee_payer_key: Option<String>,
    pub network: String,
    pub recent_blockhash: Option<String>,
    pub token_program: Option<String>,
}

/// Parse MPP challenge from WWW-Authenticate: Payment header value.
///
/// Format: Payment id="...", realm="...", method="...", intent="...",
///         request="<base64>", description="...", expires="..."
pub fn parse_mpp_challenge(header_value: &str) -> Result<MppChallenge> {
    let trimmed = header_value.trim();

    // Strip "Payment " prefix if present
    let params_str = if trimmed.starts_with("Payment ") {
        &trimmed[8..]
    } else {
        trimmed
    };

    // Parse key="value" pairs
    let id = extract_param(params_str, "id")
        .ok_or_else(|| MazeError::InvalidParameters("MPP challenge missing 'id' field".into()))?;
    let realm = extract_param(params_str, "realm").unwrap_or_default();
    let method = extract_param(params_str, "method")
        .ok_or_else(|| MazeError::InvalidParameters("MPP challenge missing 'method' field".into()))?;
    let intent = extract_param(params_str, "intent").unwrap_or_else(|| "charge".to_string());
    let description = extract_param(params_str, "description").unwrap_or_default();
    let expires = extract_param(params_str, "expires").unwrap_or_default();
    let request_b64 = extract_param(params_str, "request")
        .ok_or_else(|| MazeError::InvalidParameters("MPP challenge missing 'request' field".into()))?;

    // Only support "solana" method for now
    if method != "solana" {
        return Err(MazeError::InvalidParameters(
            format!("MPP method '{}' not supported. KausaPay only supports Solana.", method)
        ));
    }

    // Only support "charge" intent for now
    if intent != "charge" {
        return Err(MazeError::InvalidParameters(
            format!("MPP intent '{}' not supported. KausaPay only supports 'charge' (one-time payment).", intent)
        ));
    }

    // Decode request from Base64
    let request_bytes = base64::engine::general_purpose::STANDARD.decode(&request_b64)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&request_b64))
        .map_err(|e| MazeError::InvalidParameters(format!("MPP request Base64 decode failed: {}", e)))?;

    let request_json: serde_json::Value = serde_json::from_slice(&request_bytes)
        .map_err(|e| MazeError::InvalidParameters(format!("MPP request JSON parse failed: {}", e)))?;

    // Parse request fields
    let amount = request_json.get("amount")
        .and_then(|v| v.as_str())
        .unwrap_or("0")
        .to_string();

    let currency = request_json.get("currency")
        .and_then(|v| v.as_str())
        .unwrap_or(USDC_MINT)
        .to_string();

    let recipient = request_json.get("recipient")
        .and_then(|v| v.as_str())
        .ok_or_else(|| MazeError::InvalidParameters("MPP request missing 'recipient' field".into()))?
        .to_string();

    // Validate recipient is valid Solana pubkey
    Pubkey::from_str(&recipient)
        .map_err(|_| MazeError::InvalidParameters(format!("MPP recipient is not a valid Solana address: {}", recipient)))?;

    let method_details = request_json.get("methodDetails");
    let decimals = method_details
        .and_then(|md| md.get("decimals"))
        .and_then(|v| v.as_u64())
        .unwrap_or(STABLECOIN_DECIMALS as u64) as u8;

    let fee_payer = method_details
        .and_then(|md| md.get("feePayer"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let fee_payer_key = method_details
        .and_then(|md| md.get("feePayerKey"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let network = method_details
        .and_then(|md| md.get("network"))
        .and_then(|v| v.as_str())
        .unwrap_or("mainnet")
        .to_string();

    let recent_blockhash = method_details
        .and_then(|md| md.get("recentBlockhash"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let token_program = method_details
        .and_then(|md| md.get("tokenProgram"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let request = MppRequest {
        amount,
        currency,
        recipient,
        decimals,
        fee_payer,
        fee_payer_key,
        network,
        recent_blockhash,
        token_program,
    };

    Ok(MppChallenge {
        id,
        realm,
        method,
        intent,
        description,
        expires,
        request,
        raw_header: trimmed.to_string(),
    })
}

/// Convert MPP challenge to X402Challenge for reuse of payment execution logic
pub fn mpp_to_x402_challenge(mpp: &MppChallenge) -> Result<X402Challenge> {
    let amount_raw = mpp.request.amount.parse::<u64>()
        .map_err(|_| MazeError::InvalidParameters(format!("MPP amount not valid: {}", mpp.request.amount)))?;

    let (token_mint, token_symbol) = x402::identify_stablecoin(&mpp.request.currency)?;

    let amount_display = amount_raw as f64 / 10f64.powi(mpp.request.decimals as i32);

    let network = if mpp.request.network == "mainnet" || mpp.request.network == "localnet" {
        format!("solana:{}", mpp.request.network)
    } else if mpp.request.network.starts_with("solana:") {
        mpp.request.network.clone()
    } else {
        SOLANA_MAINNET_CAIP2.to_string()
    };

    Ok(X402Challenge {
        recipient: mpp.request.recipient.clone(),
        amount_raw,
        amount_display,
        token_mint,
        token_symbol,
        network,
        raw_header: mpp.raw_header.clone(),
        extra_payload: None,
        fee_payer: mpp.request.fee_payer_key.clone(),
    })
}

/// Execute MPP payment flow.
///
/// 1. Convert MPP challenge to X402Challenge (same Solana TX logic)
/// 2. Build and sign the payment transaction
/// 3. Retry original request with Authorization: Payment header (MPP spec)
pub async fn execute_mpp_payment(
    http_client: &reqwest::Client,
    rpc_client: &solana_client::rpc_client::RpcClient,
    pocket_keypair: &Keypair,
    mpp_challenge: &MppChallenge,
    max_amount_usdc: f64,
    original_url: &str,
    method: &str,
    request_body: Option<&str>,
) -> Result<X402PaymentResult> {
    let x402_challenge = mpp_to_x402_challenge(mpp_challenge)?;

    // Safety check: amount vs max
    if x402_challenge.amount_display > max_amount_usdc {
        return Ok(X402PaymentResult {
            success: false, response_body: None, response_status: 402,
            tx_signature: None, amount_paid: 0.0,
            token_symbol: x402_challenge.token_symbol.clone(),
            error: Some(format!(
                "Payment exceeds limit. Required: {} {}, Max: {} USDC",
                x402_challenge.amount_display, x402_challenge.token_symbol, max_amount_usdc
            )),
        });
    }

    let pocket_pubkey = pocket_keypair.pubkey();
    let token_mint_pubkey = Pubkey::from_str(&x402_challenge.token_mint)
        .map_err(|e| MazeError::InvalidParameters(format!("Invalid token mint: {}", e)))?;
    let recipient_pubkey = Pubkey::from_str(&x402_challenge.recipient)
        .map_err(|e| MazeError::InvalidParameters(format!("Invalid recipient: {}", e)))?;

    let pocket_ata = spl_associated_token_account::get_associated_token_address(
        &pocket_pubkey, &token_mint_pubkey,
    );

    // Check token balance
    let token_balance = match rpc_client.get_token_account_balance(&pocket_ata) {
        Ok(balance) => balance.amount.parse::<u64>().unwrap_or(0),
        Err(_) => {
            return Ok(X402PaymentResult {
                success: false, response_body: None, response_status: 402,
                tx_signature: None, amount_paid: 0.0,
                token_symbol: x402_challenge.token_symbol.clone(),
                error: Some(format!("No {} token account found. Swap SOL to {} first.",
                    x402_challenge.token_symbol, x402_challenge.token_symbol)),
            });
        }
    };

    if token_balance < x402_challenge.amount_raw {
        let current = token_balance as f64 / 10f64.powi(STABLECOIN_DECIMALS as i32);
        return Ok(X402PaymentResult {
            success: false, response_body: None, response_status: 402,
            tx_signature: None, amount_paid: 0.0,
            token_symbol: x402_challenge.token_symbol.clone(),
            error: Some(format!("Insufficient {}. Have: {:.6}, Need: {:.6}.",
                x402_challenge.token_symbol, current, x402_challenge.amount_display)),
        });
    }

    // Determine fee payer
    let fee_payer_pubkey = if let Some(ref fp) = x402_challenge.fee_payer {
        Pubkey::from_str(fp).unwrap_or(pocket_pubkey)
    } else {
        pocket_pubkey
    };
    let has_facilitator = x402_challenge.fee_payer.is_some() && fee_payer_pubkey != pocket_pubkey;

    if !has_facilitator {
        let sol_balance = rpc_client.get_balance(&pocket_pubkey)
            .map_err(|e| MazeError::RpcError(format!("Failed to get SOL balance: {}", e)))?;
        if sol_balance < 10_000 {
            return Ok(X402PaymentResult {
                success: false, response_body: None, response_status: 402,
                tx_signature: None, amount_paid: 0.0,
                token_symbol: x402_challenge.token_symbol.clone(),
                error: Some("Insufficient SOL for transaction fees.".into()),
            });
        }
    }

    let recipient_ata = spl_associated_token_account::get_associated_token_address(
        &recipient_pubkey, &token_mint_pubkey,
    );

    let blockhash = rpc_client.get_latest_blockhash()
        .map_err(|e| MazeError::RpcError(format!("Failed to get blockhash: {}", e)))?;

    // Build transaction (same as x402)
    let mut instructions = Vec::new();
    instructions.push(
        solana_sdk::compute_budget::ComputeBudgetInstruction::set_compute_unit_limit(
            if has_facilitator { 40_000 } else { 200_000 }
        )
    );
    instructions.push(
        solana_sdk::compute_budget::ComputeBudgetInstruction::set_compute_unit_price(1)
    );

    if !has_facilitator {
        let recipient_ata_exists = rpc_client.get_account(&recipient_ata).is_ok();
        if !recipient_ata_exists {
            instructions.push(
                spl_associated_token_account::instruction::create_associated_token_account(
                    &pocket_pubkey, &recipient_pubkey, &token_mint_pubkey, &spl_token::id(),
                )
            );
        }
    }

    instructions.push(
        spl_token::instruction::transfer_checked(
            &spl_token::id(),
            &pocket_ata,
            &token_mint_pubkey,
            &recipient_ata,
            &pocket_pubkey,
            &[],
            x402_challenge.amount_raw,
            STABLECOIN_DECIMALS,
        ).map_err(|e| MazeError::TransactionError(format!("Failed to build transfer: {}", e)))?
    );

    let tx_b64: String;
    let tx_signature_direct: Option<String>;

    if has_facilitator {
        // Facilitator mode: partial sign, send serialized TX
        let message = solana_sdk::message::Message::new_with_blockhash(
            &instructions, Some(&fee_payer_pubkey), &blockhash,
        );
        let mut tx = Transaction::new_unsigned(message);
        tx.partial_sign(&[pocket_keypair], blockhash);

        let tx_bytes = bincode::serialize(&tx)
            .map_err(|e| MazeError::TransactionError(format!("Failed to serialize TX: {}", e)))?;
        tx_b64 = base64::engine::general_purpose::STANDARD.encode(&tx_bytes);
        tx_signature_direct = None;
    } else {
        // Direct mode: full sign, submit, get signature
        let tx = Transaction::new_signed_with_payer(
            &instructions, Some(&pocket_pubkey), &[pocket_keypair], blockhash,
        );
        let sig = x402::send_direct_payment(rpc_client, &tx).await?;
        tx_b64 = sig.clone();
        tx_signature_direct = Some(sig);
    }

    info!("MPP payment: {} {} to {} (facilitator={})",
        x402_challenge.amount_display, x402_challenge.token_symbol,
        &x402_challenge.recipient[..16.min(x402_challenge.recipient.len())],
        has_facilitator);

    // Build MPP credential for Authorization: Payment header
    let credential = build_mpp_credential(
        &mpp_challenge.id,
        &mpp_challenge.method,
        &tx_b64,
        tx_signature_direct.as_deref(),
        has_facilitator,
    );

    // Retry with Authorization: Payment header (MPP spec)
    let mut retry_req = match method {
        "POST" => http_client.post(original_url),
        "PUT" => http_client.put(original_url),
        "PATCH" => http_client.patch(original_url),
        "DELETE" => http_client.delete(original_url),
        _ => http_client.get(original_url),
    };
    retry_req = retry_req
        .header("Authorization", format!("Payment {}", credential))
        .timeout(std::time::Duration::from_secs(30));
    if let Some(body) = request_body {
        retry_req = retry_req.header("Content-Type", "application/json").body(body.to_string());
    }

    let final_response = retry_req
        .send()
        .await
        .map_err(|e| MazeError::RpcError(format!("MPP retry failed: {}", e)))?;

    let final_status = final_response.status().as_u16();

    // Extract Payment-Receipt header
    let receipt = final_response.headers()
        .get("payment-receipt")
        .or_else(|| final_response.headers().get("Payment-Receipt"))
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let response_body = final_response.text().await
        .map_err(|e| MazeError::RpcError(format!("Failed to read MPP response: {}", e)))?;

    info!("MPP retry result: status={}, receipt={:?}, body={}",
        final_status, receipt, &response_body[..500.min(response_body.len())]);

    if final_status >= 200 && final_status < 300 {
        Ok(X402PaymentResult {
            success: true,
            response_body: Some(response_body),
            response_status: final_status,
            tx_signature: tx_signature_direct,
            amount_paid: x402_challenge.amount_display,
            token_symbol: x402_challenge.token_symbol.clone(),
            error: None,
        })
    } else if final_status == 402 {
        Ok(X402PaymentResult {
            success: false,
            response_body: Some(response_body),
            response_status: final_status,
            tx_signature: tx_signature_direct,
            amount_paid: x402_challenge.amount_display,
            token_symbol: x402_challenge.token_symbol.clone(),
            error: Some("MPP payment submitted but server has not verified yet.".into()),
        })
    } else {
        Ok(X402PaymentResult {
            success: false,
            response_body: Some(response_body),
            response_status: final_status,
            tx_signature: tx_signature_direct,
            amount_paid: x402_challenge.amount_display,
            token_symbol: x402_challenge.token_symbol.clone(),
            error: Some(format!("Server returned HTTP {} after MPP payment", final_status)),
        })
    }
}

/// Build MPP credential string for Authorization: Payment header.
///
/// Format: id="...", method="solana", credential="<base64>"
fn build_mpp_credential(
    id: &str,
    method: &str,
    tx_data: &str,
    tx_signature: Option<&str>,
    is_facilitator: bool,
) -> String {
    let credential_json = if is_facilitator {
        serde_json::json!({
            "transaction": tx_data,
        })
    } else {
        serde_json::json!({
            "signature": tx_signature.unwrap_or(tx_data),
        })
    };

    let credential_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(
        credential_json.to_string().as_bytes()
    );

    format!("id=\"{}\" method=\"{}\" credential=\"{}\"", id, method, credential_b64)
}

/// Extract a parameter value from key="value" format string
fn extract_param(s: &str, key: &str) -> Option<String> {
    let pattern = format!("{}=\"", key);
    if let Some(start) = s.find(&pattern) {
        let value_start = start + pattern.len();
        if let Some(end) = s[value_start..].find('"') {
            return Some(s[value_start..value_start + end].to_string());
        }
    }
    // Try without escaped quotes (raw string)
    let pattern2 = format!("{}=\"", key);
    if let Some(start) = s.find(&pattern2) {
        let value_start = start + pattern2.len();
        if let Some(end) = s[value_start..].find('"') {
            return Some(s[value_start..value_start + end].to_string());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_mpp_challenge() {
        let header = r#"Payment id="test123", realm="example.com", method="solana", intent="charge", request="eyJhbW91bnQiOiIxMDAwMCIsImN1cnJlbmN5IjoiRVBqRldkZDVBdWZxU1NxZU0ycU4xeHp5YmFwQzhHNHdFR0drWnd5VER0MXYiLCJtZXRob2REZXRhaWxzIjp7ImRlY2ltYWxzIjo2LCJmZWVQYXllciI6dHJ1ZSwiZmVlUGF5ZXJLZXkiOiJCVWoyUGdGQ2p5MTd4WGtramVvYXVmSzIzOWlwSk1yejh0WUhpWWliRjE4MyIsIm5ldHdvcmsiOiJsb2NhbG5ldCIsInRva2VuUHJvZ3JhbSI6IlRva2Vua2VnUWZlWnlpTndBSmJOYkdLUEZYQ1d1QnZmOVNzNjIzVlE1REEifSwicmVjaXBpZW50IjoiQlVqMlBnRkNqeTE3eFhra2plb2F1ZksyMzlpcEpNcno4dFlIaVlpYkYxODMifQ", description="Stock quote", expires="2026-05-07T12:00:00Z""#;

        let challenge = parse_mpp_challenge(header).unwrap();
        assert_eq!(challenge.id, "test123");
        assert_eq!(challenge.method, "solana");
        assert_eq!(challenge.intent, "charge");
        assert_eq!(challenge.request.recipient, "BUj2PgFCjy17xXkkjeoaufK239ipJMrz8tYHiYibF183");
        assert_eq!(challenge.request.amount, "10000");
        assert!(challenge.request.fee_payer);
    }

    #[test]
    fn test_mpp_to_x402_challenge() {
        let mpp = MppChallenge {
            id: "test".to_string(),
            realm: "example.com".to_string(),
            method: "solana".to_string(),
            intent: "charge".to_string(),
            description: "test".to_string(),
            expires: "".to_string(),
            request: MppRequest {
                amount: "10000".to_string(),
                currency: "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v".to_string(),
                recipient: "BUj2PgFCjy17xXkkjeoaufK239ipJMrz8tYHiYibF183".to_string(),
                decimals: 6,
                fee_payer: true,
                fee_payer_key: Some("BUj2PgFCjy17xXkkjeoaufK239ipJMrz8tYHiYibF183".to_string()),
                network: "mainnet".to_string(),
                recent_blockhash: None,
                token_program: None,
            },
            raw_header: "".to_string(),
        };

        let x402 = mpp_to_x402_challenge(&mpp).unwrap();
        assert_eq!(x402.amount_raw, 10000);
        assert_eq!(x402.amount_display, 0.01);
        assert_eq!(x402.token_symbol, "USDC");
        assert_eq!(x402.recipient, "BUj2PgFCjy17xXkkjeoaufK239ipJMrz8tYHiYibF183");
        assert_eq!(x402.fee_payer.as_deref(), Some("BUj2PgFCjy17xXkkjeoaufK239ipJMrz8tYHiYibF183"));
    }

    #[test]
    fn test_extract_param() {
        let s = r#"id="abc123", realm="example.com", method="solana""#;
        assert_eq!(extract_param(s, "id"), Some("abc123".to_string()));
        assert_eq!(extract_param(s, "realm"), Some("example.com".to_string()));
        assert_eq!(extract_param(s, "method"), Some("solana".to_string()));
        assert_eq!(extract_param(s, "missing"), None);
    }
}
