//! Printr API integration for Maze Pocket Token Creation
//!
//! Handles token creation, quote fetching, and deployment status
//! using the Printr API. Enables anonymous token launches from pocket wallets.

use serde::{Deserialize, Serialize};
use tracing::info;

use crate::error::{MazeError, Result};

/// Path to Printr sidecar script
const PRINTR_SIDECAR: &str = "/root/sdp-mazepocket/printr_sidecar.mjs";

// ============ REQUEST/RESPONSE TYPES ============


/// Token creation request (to Printr API)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrintrCreateRequest {
    pub name: String,
    pub symbol: String,
    pub description: Option<String>,
    pub image_url: Option<String>,
    pub image_path: Option<String>,
    pub chains: Vec<String>,
    pub creator_accounts: Vec<String>,
    pub initial_supply: Option<u64>,
    pub decimals: Option<u8>,
}

/// Token creation response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrintrCreateResponse {
    pub success: bool,
    pub token_id: Option<String>,
    pub mint_address: Option<String>,
    pub transaction_data: Option<String>,
    pub chains: Vec<ChainDeployment>,
    pub error: Option<String>,
}

/// Per-chain deployment info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainDeployment {
    pub chain: String,
    pub status: String,
    pub contract_address: Option<String>,
    pub tx_signature: Option<String>,
}

/// Deployment status response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrintrDeploymentStatus {
    pub success: bool,
    pub token_id: String,
    pub deployments: Vec<ChainDeployment>,
    pub error: Option<String>,
}



// ============ API FUNCTIONS ============

/// Call Printr sidecar and parse JSON output
async fn call_sidecar(command: &str, payload: &serde_json::Value) -> Result<serde_json::Value> {
    let payload_str = serde_json::to_string(payload)
        .map_err(|e| MazeError::RpcError(format!("JSON serialize failed: {}", e)))?;

    let mut child = tokio::process::Command::new("node")
        .arg(PRINTR_SIDECAR)
        .arg(command)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| MazeError::RpcError(format!("Printr sidecar failed to start: {}", e)))?;

    if let Some(mut stdin) = child.stdin.take() {
        use tokio::io::AsyncWriteExt;
        stdin.write_all(payload_str.as_bytes()).await
            .map_err(|e| MazeError::RpcError(format!("Failed to write to sidecar stdin: {}", e)))?;
        drop(stdin);
    }

    let output = child.wait_with_output().await
        .map_err(|e| MazeError::RpcError(format!("Printr sidecar failed: {}", e)))?;
    if !output.status.success() {

        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(MazeError::RpcError(format!("Printr sidecar error: {}", stderr)));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value = serde_json::from_str(stdout.trim())
        .map_err(|e| MazeError::RpcError(format!("Printr sidecar output parse failed: {} | output: {}", e, &stdout[..200.min(stdout.len())])))?;

    Ok(parsed)
}


/// Create a token via Printr API
pub async fn create_token(
    _http_client: &reqwest::Client,
    req: &PrintrCreateRequest,
) -> Result<PrintrCreateResponse> {
    info!("Printr create token: {} ({}) on chains {:?}", req.name, req.symbol, req.chains);

    let payload = serde_json::json!({

        "name": req.name,
        "symbol": req.symbol,
        "description": req.description,
        "image_url": req.image_url,
        "image_path": req.image_path,
        "chains": req.chains,
        "creator_accounts": req.creator_accounts,
        "initial_supply": req.initial_supply,
        "decimals": req.decimals.unwrap_or(6),
    });

    let result = call_sidecar("create", &payload).await?;

    let success = result.get("success").and_then(|v| v.as_bool()).unwrap_or(false);

    if !success {

        let error = result.get("error").and_then(|v| v.as_str()).unwrap_or("Unknown error").to_string();
        return Ok(PrintrCreateResponse {
            success: false,
            token_id: None,
            mint_address: None,
            chains: vec![],
            transaction_data: None,
            error: Some(error),
        });
    }

    let data = result.get("data").cloned().unwrap_or(serde_json::Value::Null);
    let token_id = data.get("token_id").or_else(|| data.get("tokenId")).and_then(|v| v.as_str()).map(|s| s.to_string());
    let mint_address = data.get("payload")
        .and_then(|p| p.get("mint_address"))
        .and_then(|v| v.as_str())
        .map(|s| {
            // Strip CAIP-10 prefix if present (solana:chainid:ADDRESS -> ADDRESS)
            let parts: Vec<&str> = s.split(':').collect();
            if parts.len() == 3 { parts[2].to_string() } else { s.to_string() }
        });
    let transaction_data = data.get("payload").map(|p| p.to_string());

    let mut deployments = Vec::new();
    if let Some(chains) = data.get("deployments").and_then(|c| c.as_array()) {
        for chain in chains {
            deployments.push(ChainDeployment {
                chain: chain.get("chain").and_then(|v| v.as_str()).unwrap_or("unknown").to_string(),
                status: chain.get("status").and_then(|v| v.as_str()).unwrap_or("pending").to_string(),
                contract_address: chain.get("contractAddress").and_then(|v| v.as_str()).map(|s| s.to_string()),
                tx_signature: chain.get("txSignature").and_then(|v| v.as_str()).map(|s| s.to_string()),
            });
        }
    }

    info!("Printr token created: {:?}", token_id);

    Ok(PrintrCreateResponse {
        success: true,
        token_id,
        mint_address,
        transaction_data,
        chains: deployments,
        error: None,
    })
}

/// Sign and submit a Printr transaction using pocket keypair
pub async fn sign_and_submit_token(
    _http_client: &reqwest::Client,
    _rpc_client: &solana_client::rpc_client::RpcClient,
    pocket_keypair: &solana_sdk::signature::Keypair,
    payload_json: &str,
) -> Result<String> {
    // Extract private key as base58
    let private_key = bs58::encode(&pocket_keypair.to_bytes()).into_string();

    // Parse payload
    let payload: serde_json::Value = serde_json::from_str(payload_json)
        .map_err(|e| MazeError::CryptoError(format!("Payload parse failed: {}", e)))?;

    // Get RPC URL from env
    let rpc_url = std::env::var("SOLANA_RPC_URL")
        .unwrap_or_else(|_| "https://api.mainnet-beta.solana.com".to_string());

    // Call sidecar to sign and submit
    let sidecar_payload = serde_json::json!({
        "payload": payload,
        "private_key": private_key,
        "rpc_url": rpc_url,
    });

    let result = call_sidecar("sign-submit", &sidecar_payload).await?;

    let success = result.get("success").and_then(|v| v.as_bool()).unwrap_or(false);

    if !success {
        let error = result.get("error").and_then(|v| v.as_str()).unwrap_or("Sign/submit failed").to_string();
        return Err(MazeError::TransactionError(error));
    }

    let signature = result.get("data")
        .and_then(|d| d.get("signature"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    info!("Printr TX confirmed via sidecar: {}", signature);
    Ok(signature)
}

/// Get deployment status for a token
pub async fn get_deployment_status(
    _http_client: &reqwest::Client,
    token_id: &str,
) -> Result<PrintrDeploymentStatus> {
    info!("Printr deployment status for token: {}", token_id);

    let payload = serde_json::json!({ "token_id": token_id });
    let result = call_sidecar("get-deployments", &payload).await?;

    let success = result.get("success").and_then(|v| v.as_bool()).unwrap_or(false);

    if !success {

        let error = result.get("error").and_then(|v| v.as_str()).unwrap_or("Unknown error").to_string();
        return Ok(PrintrDeploymentStatus {
            success: false,
            token_id: token_id.to_string(),
            deployments: vec![],
            error: Some(error),
        });
    }

    let data = result.get("data").cloned().unwrap_or(serde_json::Value::Null);
    let mut deployments = Vec::new();
    if let Some(chains) = data.get("deployments").and_then(|c| c.as_array()) {
        for chain in chains {
            deployments.push(ChainDeployment {
                chain: chain.get("chain").and_then(|v| v.as_str()).unwrap_or("unknown").to_string(),
                status: chain.get("status").and_then(|v| v.as_str()).unwrap_or("unknown").to_string(),
                contract_address: chain.get("contractAddress").and_then(|v| v.as_str()).map(|s| s.to_string()),
                tx_signature: chain.get("txSignature").and_then(|v| v.as_str()).map(|s| s.to_string()),
            });
        }
    }

    Ok(PrintrDeploymentStatus {
        success: true,
        token_id: token_id.to_string(),
        deployments,
        error: None,
    })
}

/// Get token details by ID or contract address
pub async fn get_token_info(
    _http_client: &reqwest::Client,
    token_id: &str,
) -> Result<serde_json::Value> {
    let payload = serde_json::json!({ "token_id": token_id });
    let result = call_sidecar("get-token", &payload).await?;

    let success = result.get("success").and_then(|v| v.as_bool()).unwrap_or(false);

    if !success {

        let error = result.get("error").and_then(|v| v.as_str()).unwrap_or("Unknown error").to_string();
        return Err(MazeError::RpcError(format!("Printr token info error: {}", error)));
    }

    Ok(result.get("data").cloned().unwrap_or(serde_json::Value::Null))
}
