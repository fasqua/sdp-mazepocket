//! EVM Wallet integration for Cross-Chain Swap
//!
//! Handles EVM keypair generation and deBridge DLN cross-chain operations
//! using evm_sidecar.mjs (ethers.js)

use serde::{Deserialize, Serialize};
use tracing::info;

use crate::error::{MazeError, Result};

/// Path to EVM sidecar script
const EVM_SIDECAR: &str = "/root/sdp-mazepocket/evm_sidecar.mjs";

// ============ RESPONSE TYPES ============

/// EVM keypair generation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvmKeypair {
    pub address: String,
    pub private_key: String,
}

/// EVM balance info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvmBalanceInfo {
    pub eth_balance: String,
    pub eth_balance_wei: String,
    pub tokens: Vec<EvmTokenBalance>,
}

/// EVM token balance
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvmTokenBalance {
    pub address: String,
    pub symbol: String,
    pub decimals: Option<u8>,
    pub balance: String,
    pub balance_raw: Option<String>,
    pub error: Option<String>,
}

/// deBridge quote/create-tx result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DebridgeQuoteResult {
    pub estimation: Option<serde_json::Value>,
    pub tx: Option<serde_json::Value>,
    pub order_id: Option<String>,
    pub order: Option<serde_json::Value>,
}

/// deBridge order status result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DebridgeOrderStatus {
    pub status: Option<String>,
    pub data: serde_json::Value,
}

// ============ SIDECAR CALL ============

/// Call EVM sidecar and parse JSON output
async fn call_sidecar(command: &str, payload: &serde_json::Value) -> Result<serde_json::Value> {
    let payload_str = serde_json::to_string(payload)
        .map_err(|e| MazeError::RpcError(format!("JSON serialize failed: {}", e)))?;

    let mut child = tokio::process::Command::new("node")
        .arg(EVM_SIDECAR)
        .arg(command)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| MazeError::RpcError(format!("EVM sidecar failed to start: {}", e)))?;

    if let Some(mut stdin) = child.stdin.take() {
        use tokio::io::AsyncWriteExt;
        stdin.write_all(payload_str.as_bytes()).await
            .map_err(|e| MazeError::RpcError(format!("Failed to write to sidecar stdin: {}", e)))?;
        drop(stdin);
    }

    let output = child.wait_with_output().await
        .map_err(|e| MazeError::RpcError(format!("EVM sidecar failed: {}", e)))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(MazeError::RpcError(format!("EVM sidecar error: {}", stderr)));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value = serde_json::from_str(stdout.trim())
        .map_err(|e| MazeError::RpcError(format!("EVM sidecar output parse failed: {} | output: {}", e, &stdout[..200.min(stdout.len())])))?;

    Ok(parsed)
}

// ============ API FUNCTIONS ============

/// Generate a new EVM keypair
pub async fn generate_keypair() -> Result<EvmKeypair> {
    info!("EVM: generating new keypair");

    let result = call_sidecar("generate", &serde_json::json!({})).await?;

    let success = result.get("success").and_then(|v| v.as_bool()).unwrap_or(false);
    if !success {
        let error = result.get("error").and_then(|v| v.as_str()).unwrap_or("Unknown error");
        return Err(MazeError::RpcError(format!("EVM keypair generation failed: {}", error)));
    }

    let data = result.get("data").ok_or_else(|| MazeError::RpcError("No data in response".into()))?;
    let address = data.get("address").and_then(|v| v.as_str())
        .ok_or_else(|| MazeError::RpcError("No address in response".into()))?;
    let private_key = data.get("privateKey").and_then(|v| v.as_str())
        .ok_or_else(|| MazeError::RpcError("No privateKey in response".into()))?;

    Ok(EvmKeypair {
        address: address.to_string(),
        private_key: private_key.to_string(),
    })
}

/// Get EVM balance for an address
pub async fn get_balance(address: &str, tokens: Option<Vec<String>>) -> Result<EvmBalanceInfo> {
    info!("EVM: getting balance for {}", address);

    let payload = serde_json::json!({
        "address": address,
        "tokens": tokens.unwrap_or_default(),
    });

    let result = call_sidecar("balance", &payload).await?;

    let success = result.get("success").and_then(|v| v.as_bool()).unwrap_or(false);
    if !success {
        let error = result.get("error").and_then(|v| v.as_str()).unwrap_or("Unknown error");
        return Err(MazeError::RpcError(format!("EVM balance check failed: {}", error)));
    }

    let data = result.get("data").ok_or_else(|| MazeError::RpcError("No data in response".into()))?;

    let eth_balance = data.get("eth_balance").and_then(|v| v.as_str()).unwrap_or("0").to_string();
    let eth_balance_wei = data.get("eth_balance_wei").and_then(|v| v.as_str()).unwrap_or("0").to_string();

    let tokens_arr = data.get("tokens").and_then(|v| v.as_array()).cloned().unwrap_or_default();
    let tokens: Vec<EvmTokenBalance> = tokens_arr.into_iter().filter_map(|t| {
        serde_json::from_value(t).ok()
    }).collect();

    Ok(EvmBalanceInfo {
        eth_balance,
        eth_balance_wei,
        tokens,
    })
}

/// Get deBridge quote + create-tx for cross-chain swap (Solana -> Base)
pub async fn debridge_quote(
    dst_token_out: &str,
    src_amount_lamports: u64,
    dst_recipient: &str,
    src_authority: &str,
    affiliate_fee_percent: Option<f64>,
    affiliate_fee_recipient: Option<&str>,
    referral_code: Option<u32>,
) -> Result<DebridgeQuoteResult> {
    info!("EVM: deBridge quote for {} lamports -> {} on Base", src_amount_lamports, dst_token_out);

    let mut payload = serde_json::json!({
        "src_chain_id": 7565164,
        "dst_chain_id": 8453,
        "src_token_in": "So11111111111111111111111111111111111111112",
        "dst_token_out": dst_token_out,
        "src_amount": src_amount_lamports.to_string(),
        "dst_recipient": dst_recipient,
        "src_authority": src_authority,
        "dst_authority": dst_recipient,
    });

    if let Some(fee) = affiliate_fee_percent {
        payload["affiliate_fee_percent"] = serde_json::json!(fee);
    }
    if let Some(recipient) = affiliate_fee_recipient {
        payload["affiliate_fee_recipient"] = serde_json::json!(recipient);
    }
    if let Some(code) = referral_code {
        payload["referral_code"] = serde_json::json!(code);
    }

    let result = call_sidecar("debridge-quote", &payload).await?;

    let success = result.get("success").and_then(|v| v.as_bool()).unwrap_or(false);
    if !success {
        let error = result.get("error").and_then(|v| v.as_str()).unwrap_or("Unknown error");
        let details = result.get("details").cloned().unwrap_or(serde_json::Value::Null);
        return Err(MazeError::RpcError(format!("deBridge quote failed: {} | details: {}", error, details)));
    }

    let data = result.get("data").cloned().unwrap_or(serde_json::Value::Null);

    Ok(DebridgeQuoteResult {
        estimation: data.get("estimation").cloned(),
        tx: data.get("tx").cloned(),
        order_id: data.get("order_id").and_then(|v| v.as_str()).map(|s| s.to_string()),
        order: data.get("order").cloned(),
    })
}

/// Check deBridge order status
pub async fn debridge_order_status(order_id: Option<&str>, tx_hash: Option<&str>) -> Result<DebridgeOrderStatus> {
    let payload = serde_json::json!({
        "order_id": order_id,
        "tx_hash": tx_hash,
    });

    let result = call_sidecar("order-status", &payload).await?;

    let success = result.get("success").and_then(|v| v.as_bool()).unwrap_or(false);
    if !success {
        let error = result.get("error").and_then(|v| v.as_str()).unwrap_or("Unknown error");
        return Err(MazeError::RpcError(format!("deBridge order status failed: {}", error)));
    }

    let data = result.get("data").cloned().unwrap_or(serde_json::Value::Null);
    let status = data.get("status").and_then(|v| v.as_str()).map(|s| s.to_string());

    Ok(DebridgeOrderStatus {
        status,
        data,
    })
}


/// EVM transaction result (approve + send)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvmTxResult {
    pub tx_hash: String,
    pub block_number: Option<u64>,
    pub gas_used: Option<String>,
    pub status: Option<u64>,
}

/// Get deBridge quote + create-tx for reverse cross-chain swap (Base -> Solana)
pub async fn debridge_quote_reverse(
    src_token_in: &str,
    src_amount: &str,
    dst_recipient: &str,
    src_authority: &str,
    affiliate_fee_percent: Option<f64>,
    affiliate_fee_recipient: Option<&str>,
    referral_code: Option<u32>,
) -> Result<DebridgeQuoteResult> {
    info!("EVM: deBridge reverse quote for {} {} -> SOL on Solana", src_amount, src_token_in);

    let mut payload = serde_json::json!({
        "src_token_in": src_token_in,
        "src_amount": src_amount,
        "dst_recipient": dst_recipient,
        "src_authority": src_authority,
        "dst_authority": dst_recipient,
    });

    if let Some(fee) = affiliate_fee_percent {
        payload["affiliate_fee_percent"] = serde_json::json!(fee);
    }
    if let Some(recipient) = affiliate_fee_recipient {
        payload["affiliate_fee_recipient"] = serde_json::json!(recipient);
    }
    if let Some(code) = referral_code {
        payload["referral_code"] = serde_json::json!(code);
    }

    let result = call_sidecar("debridge-quote-reverse", &payload).await?;

    let success = result.get("success").and_then(|v| v.as_bool()).unwrap_or(false);
    if !success {
        let error = result.get("error").and_then(|v| v.as_str()).unwrap_or("Unknown error");
        let details = result.get("details").cloned().unwrap_or(serde_json::Value::Null);
        return Err(MazeError::RpcError(format!("deBridge reverse quote failed: {} | details: {}", error, details)));
    }

    let data = result.get("data").cloned().unwrap_or(serde_json::Value::Null);

    Ok(DebridgeQuoteResult {
        estimation: data.get("estimation").cloned(),
        tx: data.get("tx").cloned(),
        order_id: data.get("order_id").and_then(|v| v.as_str()).map(|s| s.to_string()),
        order: data.get("order").cloned(),
    })
}

/// Approve ERC-20 token + send deBridge transaction on Base (for reverse flow)
pub async fn evm_approve_and_send(
    private_key: &str,
    approve_to: Option<&str>,
    approve_token: Option<&str>,
    approve_amount: Option<&str>,
    tx_to: &str,
    tx_data: &str,
    tx_value: &str,
) -> Result<EvmTxResult> {
    info!("EVM: approve + send tx to {}", tx_to);

    let mut payload = serde_json::json!({
        "private_key": private_key,
        "tx_to": tx_to,
        "tx_data": tx_data,
        "tx_value": tx_value,
    });

    if let Some(to) = approve_to {
        payload["approve_to"] = serde_json::json!(to);
    }
    if let Some(token) = approve_token {
        payload["approve_token"] = serde_json::json!(token);
    }
    if let Some(amount) = approve_amount {
        payload["approve_amount"] = serde_json::json!(amount);
    }

    let result = call_sidecar("evm-approve-and-send", &payload).await?;

    let success = result.get("success").and_then(|v| v.as_bool()).unwrap_or(false);
    if !success {
        let error = result.get("error").and_then(|v| v.as_str()).unwrap_or("Unknown error");
        return Err(MazeError::RpcError(format!("EVM approve+send failed: {}", error)));
    }

    let data = result.get("data").ok_or_else(|| MazeError::RpcError("No data in response".into()))?;

    Ok(EvmTxResult {
        tx_hash: data.get("tx_hash").and_then(|v| v.as_str()).unwrap_or("").to_string(),
        block_number: data.get("block_number").and_then(|v| v.as_u64()),
        gas_used: data.get("gas_used").and_then(|v| v.as_str()).map(|s| s.to_string()),
        status: data.get("status").and_then(|v| v.as_u64()),
    })
}
