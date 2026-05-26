//! Conduit Protocol integration for Maze Pocket
//!
//! Enables KausaOS agents to discover and call external capabilities
//! (inference, compute, scraping, etc.) through Conduit's routing and
//! settlement layer, paying from pocket stealth addresses via USDC.

use serde::{Deserialize, Serialize};
use tracing::info;

use crate::error::{MazeError, Result};

/// Path to Conduit sidecar script
const CONDUIT_SIDECAR: &str = "/root/sdp-mazepocket/conduit_sidecar.mjs";

// ============ REQUEST/RESPONSE TYPES ============

/// Discover request (optional category filter)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConduitDiscoverRequest {
    pub category: Option<String>,
}

/// Provider info returned from discovery
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConduitProvider {
    pub id: u64,
    pub name: String,
    #[serde(rename = "pricePerUnit")]
    pub price_per_unit: Option<String>,
    #[serde(rename = "pricePerCall")]
    pub price_per_call: Option<String>,
}

/// Endpoint info returned from discovery
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConduitEndpoint {
    pub path: String,
    pub capability: String,
    #[serde(rename = "capabilityName")]
    pub capability_name: String,
    pub unit: String,
    pub providers: Vec<ConduitProvider>,
}

/// API listing info returned from discovery
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConduitApiListing {
    pub id: u64,
    pub name: String,
    pub category: String,
    #[serde(rename = "pricePerCall")]
    pub price_per_call: String,
}

/// Discover response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConduitDiscoverResponse {
    pub success: bool,
    pub network: Option<String>,
    pub asset: Option<String>,
    pub endpoints: Vec<ConduitEndpoint>,
    pub api_listings: Vec<ConduitApiListing>,
    pub endpoint_count: u64,
    pub api_listing_count: u64,
    pub error: Option<String>,
}

/// Call request (execute a capability)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConduitCallRequest {
    pub resource_id: serde_json::Value,
    pub payload: serde_json::Value,
}

/// Call response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConduitCallResponse {
    pub success: bool,
    pub status: Option<String>,
    pub body: Option<serde_json::Value>,
    pub signature: Option<String>,
    pub error: Option<String>,
}

// ============ API FUNCTIONS ============

/// Call Conduit sidecar and parse JSON output
async fn call_sidecar(command: &str, payload: &serde_json::Value) -> Result<serde_json::Value> {
    let payload_str = serde_json::to_string(payload)
        .map_err(|e| MazeError::RpcError(format!("JSON serialize failed: {}", e)))?;

    let mut child = tokio::process::Command::new("node")
        .arg(CONDUIT_SIDECAR)
        .arg(command)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| MazeError::RpcError(format!("Conduit sidecar failed to start: {}", e)))?;

    if let Some(mut stdin) = child.stdin.take() {
        use tokio::io::AsyncWriteExt;
        stdin.write_all(payload_str.as_bytes()).await
            .map_err(|e| MazeError::RpcError(format!("Failed to write to sidecar stdin: {}", e)))?;
        drop(stdin);
    }

    let output = child.wait_with_output().await
        .map_err(|e| MazeError::RpcError(format!("Conduit sidecar failed: {}", e)))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(MazeError::RpcError(format!("Conduit sidecar error: {}", stderr)));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value = serde_json::from_str(stdout.trim())
        .map_err(|e| MazeError::RpcError(format!("Conduit sidecar output parse failed: {} | output: {}", e, &stdout[..200.min(stdout.len())])))?;

    Ok(parsed)
}

/// Discover available capabilities on Conduit network
pub async fn discover(
    req: &ConduitDiscoverRequest,
) -> Result<ConduitDiscoverResponse> {
    info!("Conduit discover capabilities, category filter: {:?}", req.category);

    let payload = serde_json::json!({
        "category": req.category,
    });

    let result = call_sidecar("discover", &payload).await?;

    let success = result.get("success").and_then(|v| v.as_bool()).unwrap_or(false);

    if !success {
        let error = result.get("error").and_then(|v| v.as_str()).unwrap_or("Unknown error").to_string();
        return Ok(ConduitDiscoverResponse {
            success: false,
            network: None,
            asset: None,
            endpoints: vec![],
            api_listings: vec![],
            endpoint_count: 0,
            api_listing_count: 0,
            error: Some(error),
        });
    }

    let data = result.get("data").cloned().unwrap_or(serde_json::Value::Null);

    let endpoints: Vec<ConduitEndpoint> = data.get("endpoints")
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .unwrap_or_default();

    let api_listings: Vec<ConduitApiListing> = data.get("apiListings")
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .unwrap_or_default();

    Ok(ConduitDiscoverResponse {
        success: true,
        network: data.get("network").and_then(|v| v.as_str()).map(|s| s.to_string()),
        asset: data.get("asset").and_then(|v| v.as_str()).map(|s| s.to_string()),
        endpoint_count: data.get("endpointCount").and_then(|v| v.as_u64()).unwrap_or(endpoints.len() as u64),
        api_listing_count: data.get("apiListingCount").and_then(|v| v.as_u64()).unwrap_or(api_listings.len() as u64),
        endpoints,
        api_listings,
        error: None,
    })
}

/// Call a Conduit capability using pocket keypair for payment
pub async fn call_capability(
    pocket_keypair: &solana_sdk::signature::Keypair,
    req: &ConduitCallRequest,
) -> Result<ConduitCallResponse> {
    info!("Conduit call capability, resource_id: {}", req.resource_id);

    let private_key = bs58::encode(&pocket_keypair.to_bytes()).into_string();

    let payload = serde_json::json!({
        "private_key": private_key,
        "resource_id": req.resource_id,
        "payload": req.payload,
    });

    let result = call_sidecar("call", &payload).await?;

    let success = result.get("success").and_then(|v| v.as_bool()).unwrap_or(false);

    if !success {
        let error = result.get("error").and_then(|v| v.as_str()).unwrap_or("Call failed").to_string();
        return Ok(ConduitCallResponse {
            success: false,
            status: None,
            body: None,
            signature: None,
            error: Some(error),
        });
    }

    let data = result.get("data").cloned().unwrap_or(serde_json::Value::Null);

    Ok(ConduitCallResponse {
        success: true,
        status: data.get("status").and_then(|v| v.as_str()).map(|s| s.to_string()),
        body: data.get("body").cloned(),
        signature: data.get("signature").and_then(|v| v.as_str()).map(|s| s.to_string()),
        error: None,
    })
}
