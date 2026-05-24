//! Jupiter Perps integration for Maze Pocket
//!
//! Handles perpetual futures trading via Jupiter Perps.
//! Uses sidecar pattern (Node.js) for Anchor IDL interaction.

use serde::{Deserialize, Serialize};
use tracing::info;

use crate::error::{MazeError, Result};

/// Path to Perps sidecar script
const PERPS_SIDECAR: &str = "/root/sdp-mazepocket/perps_sidecar.mjs";

// ============ REQUEST/RESPONSE TYPES ============

/// Open position request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerpsOpenRequest {
    pub asset: String,
    pub side: String,
    pub collateral_usdc: f64,
    pub leverage: f64,
}

/// Open position response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerpsOpenResponse {
    pub success: bool,
    pub signature: Option<String>,
    pub position_pubkey: Option<String>,
    pub side: Option<String>,
    pub asset: Option<String>,
    pub collateral_usdc: Option<f64>,
    pub leverage: Option<f64>,
    pub size_usd: Option<f64>,
    pub error: Option<String>,
}

/// Close position response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerpsCloseResponse {
    pub success: bool,
    pub signature: Option<String>,
    pub position_pubkey: Option<String>,
    pub side: Option<String>,
    pub asset: Option<String>,
    pub error: Option<String>,
}

/// Position info from API
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerpsPosition {
    pub position_pubkey: String,
    pub side: String,
    pub asset_mint: String,
    pub collateral_usd: f64,
    pub size_usd: f64,
    pub entry_price: f64,
    pub mark_price: f64,
    pub liquidation_price: f64,
    pub leverage: f64,
    pub pnl_usd: f64,
    pub pnl_pct: f64,
    pub borrow_fees_usd: f64,
    pub close_fees_usd: f64,
}

/// Get positions response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerpsPositionsResponse {
    pub success: bool,
    pub count: Option<u32>,
    pub positions: Option<Vec<PerpsPosition>>,
    pub error: Option<String>,
}

/// Market data response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerpsMarketResponse {
    pub success: bool,
    pub asset: Option<String>,
    pub price: Option<f64>,
    pub price_change_24h: Option<f64>,
    pub high_24h: Option<f64>,
    pub low_24h: Option<f64>,
    pub volume_24h: Option<f64>,
    pub open_fee_pct: Option<f64>,
    pub long_borrow_rate_pct: Option<f64>,
    pub short_borrow_rate_pct: Option<f64>,
    pub long_utilization_pct: Option<f64>,
    pub short_utilization_pct: Option<f64>,
    pub long_available_liquidity: Option<f64>,
    pub short_available_liquidity: Option<f64>,
    pub error: Option<String>,
}

/// Estimate response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerpsEstimateResponse {
    pub success: bool,
    pub entry_price: Option<f64>,
    pub leverage: Option<f64>,
    pub liquidation_price: Option<f64>,
    pub open_fee_usd: Option<f64>,
    pub price_impact_fee_usd: Option<f64>,
    pub borrow_fee_usd: Option<f64>,
    pub position_size_usd: Option<f64>,
    pub collateral_usd: Option<f64>,
    pub error: Option<String>,
}

// ============ SIDECAR CALL ============

/// Call Perps sidecar and parse JSON output
async fn call_sidecar(command: &str, payload: &serde_json::Value) -> Result<serde_json::Value> {
    let payload_str = serde_json::to_string(payload)
        .map_err(|e| MazeError::RpcError(format!("JSON serialize failed: {}", e)))?;

    let mut child = tokio::process::Command::new("node")
        .arg(PERPS_SIDECAR)
        .arg(command)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| MazeError::RpcError(format!("Perps sidecar failed to start: {}", e)))?;

    if let Some(mut stdin) = child.stdin.take() {
        use tokio::io::AsyncWriteExt;
        stdin.write_all(payload_str.as_bytes()).await
            .map_err(|e| MazeError::RpcError(format!("Failed to write to sidecar stdin: {}", e)))?;
        drop(stdin);
    }

    let output = child.wait_with_output().await
        .map_err(|e| MazeError::RpcError(format!("Perps sidecar failed: {}", e)))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(MazeError::RpcError(format!("Perps sidecar error: {}", stderr)));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value = serde_json::from_str(stdout.trim())
        .map_err(|e| MazeError::RpcError(format!("Perps sidecar output parse failed: {} | output: {}", e, &stdout[..200.min(stdout.len())])))?;

    Ok(parsed)
}

// ============ API FUNCTIONS ============

/// Open a perpetual position
pub async fn open_position(
    private_key: &str,
    rpc_url: &str,
    asset: &str,
    side: &str,
    collateral_usdc: f64,
    leverage: f64,
    priority_fee: Option<u64>,
) -> Result<PerpsOpenResponse> {
    info!("Perps open position: {} {} {}x, collateral {} USDC", side, asset, leverage, collateral_usdc);

    let payload = serde_json::json!({
        "private_key": private_key,
        "rpc_url": rpc_url,
        "asset": asset,
        "side": side,
        "collateral_usdc": collateral_usdc,
        "leverage": leverage,
        "priority_fee": priority_fee.unwrap_or(100000),
    });

    let result = call_sidecar("open-position", &payload).await?;
    let success = result.get("success").and_then(|v| v.as_bool()).unwrap_or(false);

    if !success {
        let error = result.get("error").and_then(|v| v.as_str()).unwrap_or("Unknown error").to_string();
        return Ok(PerpsOpenResponse {
            success: false, signature: None, position_pubkey: None,
            side: None, asset: None, collateral_usdc: None,
            leverage: None, size_usd: None, error: Some(error),
        });
    }

    let data = result.get("data").cloned().unwrap_or(serde_json::Value::Null);
    Ok(PerpsOpenResponse {
        success: true,
        signature: data.get("signature").and_then(|v| v.as_str()).map(|s| s.to_string()),
        position_pubkey: data.get("position_pubkey").and_then(|v| v.as_str()).map(|s| s.to_string()),
        side: data.get("side").and_then(|v| v.as_str()).map(|s| s.to_string()),
        asset: data.get("asset").and_then(|v| v.as_str()).map(|s| s.to_string()),
        collateral_usdc: data.get("collateral_usdc").and_then(|v| v.as_f64()),
        leverage: data.get("leverage").and_then(|v| v.as_f64()),
        size_usd: data.get("size_usd").and_then(|v| v.as_f64()),
        error: None,
    })
}

/// Close a perpetual position
pub async fn close_position(
    private_key: &str,
    rpc_url: &str,
    asset: &str,
    side: &str,
    priority_fee: Option<u64>,
) -> Result<PerpsCloseResponse> {
    info!("Perps close position: {} {}", side, asset);

    let payload = serde_json::json!({
        "private_key": private_key,
        "rpc_url": rpc_url,
        "asset": asset,
        "side": side,
        "priority_fee": priority_fee.unwrap_or(100000),
    });

    let result = call_sidecar("close-position", &payload).await?;
    let success = result.get("success").and_then(|v| v.as_bool()).unwrap_or(false);

    if !success {
        let error = result.get("error").and_then(|v| v.as_str()).unwrap_or("Unknown error").to_string();
        return Ok(PerpsCloseResponse {
            success: false, signature: None, position_pubkey: None,
            side: None, asset: None, error: Some(error),
        });
    }

    let data = result.get("data").cloned().unwrap_or(serde_json::Value::Null);
    Ok(PerpsCloseResponse {
        success: true,
        signature: data.get("signature").and_then(|v| v.as_str()).map(|s| s.to_string()),
        position_pubkey: data.get("position_pubkey").and_then(|v| v.as_str()).map(|s| s.to_string()),
        side: data.get("side").and_then(|v| v.as_str()).map(|s| s.to_string()),
        asset: data.get("asset").and_then(|v| v.as_str()).map(|s| s.to_string()),
        error: None,
    })
}

/// Get all positions for a wallet
pub async fn get_positions(wallet_address: &str) -> Result<PerpsPositionsResponse> {
    let payload = serde_json::json!({ "wallet_address": wallet_address });
    let result = call_sidecar("get-positions", &payload).await?;
    let success = result.get("success").and_then(|v| v.as_bool()).unwrap_or(false);

    if !success {
        let error = result.get("error").and_then(|v| v.as_str()).unwrap_or("Unknown error").to_string();
        return Ok(PerpsPositionsResponse {
            success: false, count: None, positions: None, error: Some(error),
        });
    }

    let data = result.get("data").cloned().unwrap_or(serde_json::Value::Null);
    let count = data.get("count").and_then(|v| v.as_u64()).map(|v| v as u32);

    let positions: Vec<PerpsPosition> = data.get("positions")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter().filter_map(|p| {
                Some(PerpsPosition {
                    position_pubkey: p.get("position_pubkey")?.as_str()?.to_string(),
                    side: p.get("side")?.as_str()?.to_string(),
                    asset_mint: p.get("asset_mint")?.as_str()?.to_string(),
                    collateral_usd: p.get("collateral_usd")?.as_f64()?,
                    size_usd: p.get("size_usd")?.as_f64()?,
                    entry_price: p.get("entry_price")?.as_f64()?,
                    mark_price: p.get("mark_price")?.as_f64()?,
                    liquidation_price: p.get("liquidation_price")?.as_f64()?,
                    leverage: p.get("leverage")?.as_f64()?,
                    pnl_usd: p.get("pnl_usd")?.as_f64()?,
                    pnl_pct: p.get("pnl_pct")?.as_f64()?,
                    borrow_fees_usd: p.get("borrow_fees_usd")?.as_f64()?,
                    close_fees_usd: p.get("close_fees_usd")?.as_f64()?,
                })
            }).collect()
        })
        .unwrap_or_default();

    Ok(PerpsPositionsResponse {
        success: true,
        count,
        positions: Some(positions),
        error: None,
    })
}

/// Get market data for an asset
pub async fn get_market(asset: &str) -> Result<PerpsMarketResponse> {
    let payload = serde_json::json!({ "asset": asset });
    let result = call_sidecar("get-market", &payload).await?;
    let success = result.get("success").and_then(|v| v.as_bool()).unwrap_or(false);

    if !success {
        let error = result.get("error").and_then(|v| v.as_str()).unwrap_or("Unknown error").to_string();
        return Ok(PerpsMarketResponse {
            success: false, asset: None, price: None, price_change_24h: None,
            high_24h: None, low_24h: None, volume_24h: None,
            open_fee_pct: None, long_borrow_rate_pct: None, short_borrow_rate_pct: None,
            long_utilization_pct: None, short_utilization_pct: None,
            long_available_liquidity: None, short_available_liquidity: None,
            error: Some(error),
        });
    }

    let data = result.get("data").cloned().unwrap_or(serde_json::Value::Null);
    Ok(PerpsMarketResponse {
        success: true,
        asset: data.get("asset").and_then(|v| v.as_str()).map(|s| s.to_string()),
        price: data.get("price").and_then(|v| v.as_f64()),
        price_change_24h: data.get("price_change_24h").and_then(|v| v.as_f64()),
        high_24h: data.get("high_24h").and_then(|v| v.as_f64()),
        low_24h: data.get("low_24h").and_then(|v| v.as_f64()),
        volume_24h: data.get("volume_24h").and_then(|v| v.as_f64()),
        open_fee_pct: data.get("open_fee_pct").and_then(|v| v.as_f64()),
        long_borrow_rate_pct: data.get("long_borrow_rate_pct").and_then(|v| v.as_f64()),
        short_borrow_rate_pct: data.get("short_borrow_rate_pct").and_then(|v| v.as_f64()),
        long_utilization_pct: data.get("long_utilization_pct").and_then(|v| v.as_f64()),
        short_utilization_pct: data.get("short_utilization_pct").and_then(|v| v.as_f64()),
        long_available_liquidity: data.get("long_available_liquidity").and_then(|v| v.as_f64()),
        short_available_liquidity: data.get("short_available_liquidity").and_then(|v| v.as_f64()),
        error: None,
    })
}

/// Get position estimate before opening
pub async fn estimate_position(
    wallet_address: &str,
    asset: &str,
    side: &str,
    collateral_usdc: f64,
    leverage: f64,
    max_slippage_bps: Option<u32>,
) -> Result<PerpsEstimateResponse> {
    info!("Perps estimate: {} {} {}x, collateral {} USDC", side, asset, leverage, collateral_usdc);

    let payload = serde_json::json!({
        "wallet_address": wallet_address,
        "asset": asset,
        "side": side,
        "collateral_usdc": collateral_usdc,
        "leverage": leverage,
        "max_slippage_bps": max_slippage_bps.unwrap_or(200),
    });

    let result = call_sidecar("estimate", &payload).await?;
    let success = result.get("success").and_then(|v| v.as_bool()).unwrap_or(false);

    if !success {
        let error = result.get("error").and_then(|v| v.as_str()).unwrap_or("Unknown error").to_string();
        return Ok(PerpsEstimateResponse {
            success: false, entry_price: None, leverage: None, liquidation_price: None,
            open_fee_usd: None, price_impact_fee_usd: None, borrow_fee_usd: None,
            position_size_usd: None, collateral_usd: None, error: Some(error),
        });
    }

    let data = result.get("data").cloned().unwrap_or(serde_json::Value::Null);
    Ok(PerpsEstimateResponse {
        success: true,
        entry_price: data.get("entry_price").and_then(|v| v.as_f64()),
        leverage: data.get("leverage").and_then(|v| v.as_f64()),
        liquidation_price: data.get("liquidation_price").and_then(|v| v.as_f64()),
        open_fee_usd: data.get("open_fee_usd").and_then(|v| v.as_f64()),
        price_impact_fee_usd: data.get("price_impact_fee_usd").and_then(|v| v.as_f64()),
        borrow_fee_usd: data.get("borrow_fee_usd").and_then(|v| v.as_f64()),
        position_size_usd: data.get("position_size_usd").and_then(|v| v.as_f64()),
        collateral_usd: data.get("collateral_usd").and_then(|v| v.as_f64()),
        error: None,
    })
}


/// Set TP/SL for a position
pub async fn set_tpsl(
    private_key: &str,
    rpc_url: &str,
    position_pubkey: &str,
    tp_price: Option<f64>,
    sl_price: Option<f64>,
) -> Result<serde_json::Value> {
    info!("Perps set TP/SL: position {}, tp={:?}, sl={:?}", position_pubkey, tp_price, sl_price);

    let mut payload = serde_json::json!({
        "private_key": private_key,
        "rpc_url": rpc_url,
        "position_pubkey": position_pubkey,
    });
    if let Some(tp) = tp_price { payload["tp_price"] = serde_json::json!(tp); }
    if let Some(sl) = sl_price { payload["sl_price"] = serde_json::json!(sl); }

    let result = call_sidecar("set-tpsl", &payload).await?;
    let success = result.get("success").and_then(|v| v.as_bool()).unwrap_or(false);
    if !success {
        let error = result.get("error").and_then(|v| v.as_str()).unwrap_or("Unknown error").to_string();
        return Ok(serde_json::json!({ "success": false, "error": error }));
    }
    Ok(serde_json::json!({ "success": true, "data": result.get("data") }))
}

/// Cancel TP/SL
pub async fn cancel_tpsl(
    private_key: &str,
    rpc_url: &str,
    position_request_pubkey: &str,
) -> Result<serde_json::Value> {
    info!("Perps cancel TP/SL: {}", position_request_pubkey);

    let payload = serde_json::json!({
        "private_key": private_key,
        "rpc_url": rpc_url,
        "position_request_pubkey": position_request_pubkey,
    });

    let result = call_sidecar("cancel-tpsl", &payload).await?;
    let success = result.get("success").and_then(|v| v.as_bool()).unwrap_or(false);
    if !success {
        let error = result.get("error").and_then(|v| v.as_str()).unwrap_or("Unknown error").to_string();
        return Ok(serde_json::json!({ "success": false, "error": error }));
    }
    Ok(serde_json::json!({ "success": true, "data": result.get("data") }))
}

/// Create a limit order
pub async fn limit_order(
    private_key: &str,
    rpc_url: &str,
    asset: &str,
    side: &str,
    input_amount: f64,
    leverage: f64,
    trigger_price: f64,
) -> Result<serde_json::Value> {
    info!("Perps limit order: {} {} {}x @ ${}", side, asset, leverage, trigger_price);

    let payload = serde_json::json!({
        "private_key": private_key,
        "rpc_url": rpc_url,
        "asset": asset,
        "side": side,
        "input_token": "USDC",
        "input_amount": input_amount,
        "leverage": leverage,
        "trigger_price": trigger_price,
    });

    let result = call_sidecar("limit-order", &payload).await?;
    let success = result.get("success").and_then(|v| v.as_bool()).unwrap_or(false);
    if !success {
        let error = result.get("error").and_then(|v| v.as_str()).unwrap_or("Unknown error").to_string();
        return Ok(serde_json::json!({ "success": false, "error": error }));
    }
    Ok(serde_json::json!({ "success": true, "data": result.get("data") }))
}

/// Partial close a position
pub async fn partial_close(
    private_key: &str,
    rpc_url: &str,
    position_pubkey: &str,
    size_usd_delta: Option<f64>,
    collateral_usd_delta: Option<f64>,
) -> Result<serde_json::Value> {
    info!("Perps partial close: position {}", position_pubkey);

    let mut payload = serde_json::json!({
        "private_key": private_key,
        "rpc_url": rpc_url,
        "position_pubkey": position_pubkey,
    });
    if let Some(s) = size_usd_delta { payload["size_usd_delta"] = serde_json::json!(s); }
    if let Some(c) = collateral_usd_delta { payload["collateral_usd_delta"] = serde_json::json!(c); }

    let result = call_sidecar("partial-close", &payload).await?;
    let success = result.get("success").and_then(|v| v.as_bool()).unwrap_or(false);
    if !success {
        let error = result.get("error").and_then(|v| v.as_str()).unwrap_or("Unknown error").to_string();
        return Ok(serde_json::json!({ "success": false, "error": error }));
    }
    Ok(serde_json::json!({ "success": true, "data": result.get("data") }))
}

/// Close all positions for a wallet
pub async fn close_all(
    private_key: &str,
    rpc_url: &str,
) -> Result<serde_json::Value> {
    info!("Perps close all positions");

    let payload = serde_json::json!({
        "private_key": private_key,
        "rpc_url": rpc_url,
    });

    let result = call_sidecar("close-all", &payload).await?;
    let success = result.get("success").and_then(|v| v.as_bool()).unwrap_or(false);
    if !success {
        let error = result.get("error").and_then(|v| v.as_str()).unwrap_or("Unknown error").to_string();
        return Ok(serde_json::json!({ "success": false, "error": error }));
    }
    Ok(serde_json::json!({ "success": true, "data": result.get("data") }))
}

/// Get trade history
pub async fn trade_history(wallet_address: &str, asset: Option<&str>, side: Option<&str>) -> Result<serde_json::Value> {
    let mut payload = serde_json::json!({ "wallet_address": wallet_address });
    if let Some(a) = asset { payload["asset"] = serde_json::json!(a); }
    if let Some(s) = side { payload["side"] = serde_json::json!(s); }

    let result = call_sidecar("trade-history", &payload).await?;
    let success = result.get("success").and_then(|v| v.as_bool()).unwrap_or(false);
    if !success {
        let error = result.get("error").and_then(|v| v.as_str()).unwrap_or("Unknown error").to_string();
        return Ok(serde_json::json!({ "success": false, "error": error }));
    }
    Ok(serde_json::json!({ "success": true, "data": result.get("data") }))
}
