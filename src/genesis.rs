//! Genesis Launch Pool integration for SDP Maze Pocket
//!
//! Provides private deposit and claim for Metaplex Genesis Launch Pools
//! via genesis_sidecar.mjs (Node.js + Umi + Genesis SDK)

use serde::{Deserialize, Serialize};
use solana_sdk::signature::{Keypair, Signer};
use tracing::{info, error};

use crate::error::{MazeError, Result};

/// Genesis deposit request
#[derive(Debug, Deserialize)]
pub struct GenesisDepositRequest {
    pub genesis_account: String,
    pub mint_address: String,
    pub amount_lamports: u64,
}

/// Genesis deposit result
#[derive(Debug, Serialize)]
pub struct GenesisDepositResult {
    pub success: bool,
    pub tx_signature: Option<String>,
    pub depositor: Option<String>,
    pub amount_deposited: Option<u64>,
    pub launch_pool_bucket: Option<String>,
    pub error: Option<String>,
}

/// Genesis claim request
#[derive(Debug, Deserialize)]
pub struct GenesisClaimRequest {
    pub genesis_account: String,
    pub mint_address: String,
}

/// Genesis claim result
#[derive(Debug, Serialize)]
pub struct GenesisClaimResult {
    pub success: bool,
    pub tx_signature: Option<String>,
    pub claimed_by: Option<String>,
    pub token_mint: Option<String>,
    pub error: Option<String>,
}

/// Execute Genesis deposit via sidecar
pub async fn execute_genesis_deposit(
    pocket_keypair: &Keypair,
    rpc_url: &str,
    req: &GenesisDepositRequest,
) -> Result<GenesisDepositResult> {
    let private_key_bytes: Vec<u8> = pocket_keypair.to_bytes().to_vec();

    let sidecar_payload = serde_json::json!({
        "private_key_bytes": private_key_bytes,
        "rpc_url": rpc_url,
        "genesis_account": req.genesis_account,
        "mint_address": req.mint_address,
        "amount_lamports": req.amount_lamports,
    });

    let result = call_sidecar("wrap-and-deposit", &sidecar_payload).await?;

    let data = result.get("data").cloned().unwrap_or(serde_json::Value::Null);
    let data_success = data.get("success").and_then(|v| v.as_bool()).unwrap_or(false);

    if data_success {
        let sig = data.get("tx_signature").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let depositor = data.get("depositor").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let amount = data.get("amount_deposited").and_then(|v| v.as_u64()).unwrap_or(0);
        let bucket = data.get("launch_pool_bucket").and_then(|v| v.as_str()).unwrap_or("").to_string();

        info!("Genesis deposit completed: {} lamports to {} ({})", amount, req.genesis_account, sig);

        Ok(GenesisDepositResult {
            success: true,
            tx_signature: Some(sig),
            depositor: Some(depositor),
            amount_deposited: Some(amount),
            launch_pool_bucket: Some(bucket),
            error: None,
        })
    } else {
        let err_msg = data.get("error").and_then(|v| v.as_str())
            .or_else(|| result.get("error").and_then(|v| v.as_str()))
            .unwrap_or("Genesis deposit failed")
            .to_string();

        error!("Genesis deposit failed: {}", err_msg);

        Ok(GenesisDepositResult {
            success: false,
            tx_signature: None,
            depositor: None,
            amount_deposited: None,
            launch_pool_bucket: None,
            error: Some(err_msg),
        })
    }
}

/// Execute Genesis claim via sidecar
pub async fn execute_genesis_claim(
    pocket_keypair: &Keypair,
    rpc_url: &str,
    req: &GenesisClaimRequest,
) -> Result<GenesisClaimResult> {
    let private_key_bytes: Vec<u8> = pocket_keypair.to_bytes().to_vec();

    let sidecar_payload = serde_json::json!({
        "private_key_bytes": private_key_bytes,
        "rpc_url": rpc_url,
        "genesis_account": req.genesis_account,
        "mint_address": req.mint_address,
    });

    let result = call_sidecar("claim", &sidecar_payload).await?;

    let data = result.get("data").cloned().unwrap_or(serde_json::Value::Null);
    let data_success = data.get("success").and_then(|v| v.as_bool()).unwrap_or(false);

    if data_success {
        let sig = data.get("tx_signature").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let claimed_by = data.get("claimed_by").and_then(|v| v.as_str()).unwrap_or("").to_string();

        info!("Genesis claim completed: {} claimed from {} ({})", claimed_by, req.genesis_account, sig);

        Ok(GenesisClaimResult {
            success: true,
            tx_signature: Some(sig),
            claimed_by: Some(claimed_by),
            token_mint: Some(req.mint_address.clone()),
            error: None,
        })
    } else {
        let err_msg = data.get("error").and_then(|v| v.as_str())
            .or_else(|| result.get("error").and_then(|v| v.as_str()))
            .unwrap_or("Genesis claim failed")
            .to_string();

        error!("Genesis claim failed: {}", err_msg);

        Ok(GenesisClaimResult {
            success: false,
            tx_signature: None,
            claimed_by: None,
            token_mint: None,
            error: Some(err_msg),
        })
    }
}

/// Call genesis_sidecar.mjs via stdin/stdout
async fn call_sidecar(command: &str, payload: &serde_json::Value) -> Result<serde_json::Value> {
    let payload_str = serde_json::to_string(payload)
        .map_err(|e| MazeError::RpcError(format!("Genesis sidecar JSON failed: {}", e)))?;

    let mut child = tokio::process::Command::new("node")
        .arg("/root/sdp-mazepocket/genesis_sidecar.mjs")
        .arg(command)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| MazeError::RpcError(format!("Genesis sidecar failed to start: {}", e)))?;

    if let Some(mut stdin) = child.stdin.take() {
        use tokio::io::AsyncWriteExt;
        stdin.write_all(payload_str.as_bytes()).await
            .map_err(|e| MazeError::RpcError(format!("Failed to write to genesis sidecar: {}", e)))?;
        drop(stdin);
    }

    let output = child.wait_with_output().await
        .map_err(|e| MazeError::RpcError(format!("Genesis sidecar failed: {}", e)))?;

    let stdout = String::from_utf8_lossy(&output.stdout);

    if stdout.trim().is_empty() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(MazeError::RpcError(format!("Genesis sidecar no output. stderr: {}", stderr)));
    }

    let result: serde_json::Value = serde_json::from_str(stdout.trim())
        .map_err(|e| MazeError::RpcError(format!(
            "Genesis sidecar parse failed: {} | output: {}",
            e, &stdout[..200.min(stdout.len())]
        )))?;

    let sidecar_success = result.get("success").and_then(|v| v.as_bool()).unwrap_or(false);
    if sidecar_success {
        Ok(result)
    } else {
        let err = result.get("error").and_then(|v| v.as_str()).unwrap_or("Unknown sidecar error");
        Err(MazeError::RpcError(format!("Genesis sidecar error: {}", err)))
    }
}


/// Genesis bonding curve buy request
#[derive(Debug, Deserialize)]
pub struct GenesisBuyRequest {
    pub genesis_account: String,
    pub mint_address: String,
    pub amount_lamports: u64,
    pub min_amount_out: Option<u64>,
}

/// Genesis bonding curve buy result
#[derive(Debug, Serialize)]
pub struct GenesisBuyResult {
    pub success: bool,
    pub tx_signature: Option<String>,
    pub buyer: Option<String>,
    pub amount_spent: Option<u64>,
    pub bonding_curve_bucket: Option<String>,
    pub error: Option<String>,
}

/// Execute Genesis bonding curve buy via sidecar
pub async fn execute_genesis_buy(
    pocket_keypair: &Keypair,
    rpc_url: &str,
    req: &GenesisBuyRequest,
) -> Result<GenesisBuyResult> {
    let private_key_bytes: Vec<u8> = pocket_keypair.to_bytes().to_vec();

    let sidecar_payload = serde_json::json!({
        "private_key_bytes": private_key_bytes,
        "rpc_url": rpc_url,
        "genesis_account": req.genesis_account,
        "mint_address": req.mint_address,
        "amount_lamports": req.amount_lamports,
        "min_amount_out": req.min_amount_out.unwrap_or(0),
    });

    let result = call_sidecar("buy-bonding-curve", &sidecar_payload).await?;

    let data = result.get("data").cloned().unwrap_or(serde_json::Value::Null);
    let data_success = data.get("success").and_then(|v| v.as_bool()).unwrap_or(false);

    if data_success {
        let sig = data.get("tx_signature").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let buyer = data.get("buyer").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let amount = data.get("amount_spent").and_then(|v| v.as_u64()).unwrap_or(0);
        let bucket = data.get("bonding_curve_bucket").and_then(|v| v.as_str()).unwrap_or("").to_string();

        info!("Genesis bonding curve buy completed: {} lamports on {} ({})", amount, req.genesis_account, sig);

        Ok(GenesisBuyResult {
            success: true,
            tx_signature: Some(sig),
            buyer: Some(buyer),
            amount_spent: Some(amount),
            bonding_curve_bucket: Some(bucket),
            error: None,
        })
    } else {
        let err_msg = data.get("error").and_then(|v| v.as_str())
            .or_else(|| result.get("error").and_then(|v| v.as_str()))
            .unwrap_or("Genesis bonding curve buy failed")
            .to_string();

        error!("Genesis bonding curve buy failed: {}", err_msg);

        Ok(GenesisBuyResult {
            success: false,
            tx_signature: None,
            buyer: None,
            amount_spent: None,
            bonding_curve_bucket: None,
            error: Some(err_msg),
        })
    }
}


/// Genesis activate request (create ATAs before buy/deposit)
#[derive(Debug, Deserialize)]
pub struct GenesisActivateRequest {
    pub genesis_account: String,
    pub mint_address: String,
}

/// Genesis activate result
#[derive(Debug, Serialize)]
pub struct GenesisActivateResult {
    pub success: bool,
    pub wallet: Option<String>,
    pub wsol_ata: Option<String>,
    pub base_token_ata: Option<String>,
    pub error: Option<String>,
}

/// Execute Genesis activate via sidecar (create wSOL + base token ATAs)
pub async fn execute_genesis_activate(
    pocket_keypair: &Keypair,
    rpc_url: &str,
    req: &GenesisActivateRequest,
) -> Result<GenesisActivateResult> {
    let private_key_bytes: Vec<u8> = pocket_keypair.to_bytes().to_vec();

    let sidecar_payload = serde_json::json!({
        "private_key_bytes": private_key_bytes,
        "rpc_url": rpc_url,
        "genesis_account": req.genesis_account,
        "mint_address": req.mint_address,
    });

    let result = call_sidecar("activate", &sidecar_payload).await?;

    let data = result.get("data").cloned().unwrap_or(serde_json::Value::Null);
    let data_success = data.get("success").and_then(|v| v.as_bool()).unwrap_or(false);

    if data_success {
        let wallet = data.get("wallet").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let wsol_ata = data.get("wsol_ata").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let base_ata = data.get("base_token_ata").and_then(|v| v.as_str()).unwrap_or("").to_string();

        info!("Genesis activate completed: wallet={} wsol={} base={}", wallet, wsol_ata, base_ata);

        Ok(GenesisActivateResult {
            success: true,
            wallet: Some(wallet),
            wsol_ata: Some(wsol_ata),
            base_token_ata: Some(base_ata),
            error: None,
        })
    } else {
        let err_msg = data.get("error").and_then(|v| v.as_str())
            .or_else(|| result.get("error").and_then(|v| v.as_str()))
            .unwrap_or("Genesis activate failed")
            .to_string();

        error!("Genesis activate failed: {}", err_msg);

        Ok(GenesisActivateResult {
            success: false,
            wallet: None,
            wsol_ata: None,
            base_token_ata: None,
            error: Some(err_msg),
        })
    }
}


/// Genesis bonding curve sell request
#[derive(Debug, Deserialize)]
pub struct GenesisSellRequest {
    pub genesis_account: String,
    pub mint_address: String,
    pub amount_tokens: u64,
    pub min_amount_out: Option<u64>,
}

/// Genesis bonding curve sell result
#[derive(Debug, Serialize)]
pub struct GenesisSellResult {
    pub success: bool,
    pub tx_signature: Option<String>,
    pub seller: Option<String>,
    pub amount_sold: Option<u64>,
    pub sol_received: Option<u64>,
    pub bonding_curve_bucket: Option<String>,
    pub error: Option<String>,
}

/// Execute Genesis bonding curve sell via sidecar
pub async fn execute_genesis_sell(
    pocket_keypair: &Keypair,
    rpc_url: &str,
    req: &GenesisSellRequest,
) -> Result<GenesisSellResult> {
    let private_key_bytes: Vec<u8> = pocket_keypair.to_bytes().to_vec();

    let sidecar_payload = serde_json::json!({
        "private_key_bytes": private_key_bytes,
        "rpc_url": rpc_url,
        "genesis_account": req.genesis_account,
        "mint_address": req.mint_address,
        "amount_tokens": req.amount_tokens,
        "min_amount_out": req.min_amount_out.unwrap_or(0),
    });

    let result = call_sidecar("sell-bonding-curve", &sidecar_payload).await?;

    let data = result.get("data").cloned().unwrap_or(serde_json::Value::Null);
    let data_success = data.get("success").and_then(|v| v.as_bool()).unwrap_or(false);

    if data_success {
        let sig = data.get("tx_signature").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let seller = data.get("seller").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let amount_sold = data.get("amount_sold").and_then(|v| v.as_u64()).unwrap_or(0);
        let sol_received = data.get("sol_received").and_then(|v| v.as_u64()).unwrap_or(0);
        let bucket = data.get("bonding_curve_bucket").and_then(|v| v.as_str()).unwrap_or("").to_string();

        info!("Genesis bonding curve sell completed: {} tokens sold for {} lamports ({})", amount_sold, sol_received, sig);

        Ok(GenesisSellResult {
            success: true,
            tx_signature: Some(sig),
            seller: Some(seller),
            amount_sold: Some(amount_sold),
            sol_received: Some(sol_received),
            bonding_curve_bucket: Some(bucket),
            error: None,
        })
    } else {
        let err_msg = data.get("error").and_then(|v| v.as_str())
            .or_else(|| result.get("error").and_then(|v| v.as_str()))
            .unwrap_or("Genesis bonding curve sell failed")
            .to_string();

        error!("Genesis bonding curve sell failed: {}", err_msg);

        Ok(GenesisSellResult {
            success: false,
            tx_signature: None,
            seller: None,
            amount_sold: None,
            sol_received: None,
            bonding_curve_bucket: None,
            error: Some(err_msg),
        })
    }
}
