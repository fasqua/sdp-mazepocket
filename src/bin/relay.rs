//! SDP Maze Pocket Relay Server
//!
//! Provides API for creating and managing private wallet pockets
//! funded via maze routing.

use axum::{
    extract::{Path, State, Query},
    http::StatusCode,
    response::{Json, IntoResponse},
    routing::{get, post},
    Router,
};
use serde::{Deserialize, Serialize};
use solana_client::rpc_client::RpcClient;
use solana_client::rpc_config::RpcSendTransactionConfig;
use solana_sdk::{
    commitment_config::CommitmentConfig,
    pubkey::Pubkey,
    signature::{Keypair, Signer},
    system_instruction,
    transaction::Transaction,
};
use std::str::FromStr;
use std::sync::Arc;
use tower_http::cors::{Any, CorsLayer};
use tracing::{info, error, warn};

use sdp_mazepocket::{
    config::{
        Config, MazeParameters, MergeStrategy, DelayPattern, DelayScope,
        TX_FEE_LAMPORTS, FEE_PERCENT, FEE_WALLET, MIN_AMOUNT_SOL, EXPIRY_SECONDS,
    },
    core::{lamports_to_sol, sol_to_lamports, generate_pocket_id},
    relay::{
        PocketDatabase, MazeGenerator, MazeGraph, MazeNode,
        database::{MazePocket, PocketStatus, FundingRequest, RouteHistoryEntry, UsageStats},
    },
    error::{MazeError, Result},
};


// ============ APP ERROR ============

fn sanitize_error(msg: &str) -> String {
    if msg.contains("api-key=") || msg.contains("api_key=") || msg.contains("helius") {
        "RPC connection error. Please try again.".to_string()
    } else {
        msg.to_string()
    }
}


struct AppError(MazeError);

impl From<MazeError> for AppError {
    fn from(e: MazeError) -> Self {
        AppError(e)
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> axum::response::Response {
        let (status, code) = match &self.0 {
            MazeError::InvalidMetaAddress(_) => (StatusCode::BAD_REQUEST, "INVALID_ADDRESS"),
            MazeError::InvalidParameters(_) => (StatusCode::BAD_REQUEST, "INVALID_PARAMS"),
            MazeError::InsufficientFunds { .. } => (StatusCode::BAD_REQUEST, "INSUFFICIENT_FUNDS"),
            MazeError::RequestNotFound(_) => (StatusCode::NOT_FOUND, "NOT_FOUND"),
            MazeError::RequestExpired => (StatusCode::GONE, "EXPIRED"),
            MazeError::PocketNotFound(_) => (StatusCode::NOT_FOUND, "POCKET_NOT_FOUND"),
            _ => (StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL_ERROR"),
        };
        
        let body = Json(ErrorResponse {
            success: false,
            error: sanitize_error(&self.0.to_string()),
        });
        
        (status, body).into_response()
    }
}

// ============ APP STATE ============

struct AppState {
    db: PocketDatabase,
    rpc: RpcClient,
    config: Config,
}

// ============ API TYPES ============

#[derive(Debug, Deserialize)]
struct CreatePocketRequest {
    meta_address: String,
    amount_sol: f64,
    maze_config: Option<CustomMazeConfig>,
}

#[derive(Debug, Deserialize)]
struct CustomMazeConfig {
    hop_count: Option<u8>,
    split_ratio: Option<f64>,
    merge_strategy: Option<String>,
    delay_pattern: Option<String>,
    delay_ms: Option<u64>,
    delay_scope: Option<String>,
}

#[derive(Debug, Serialize)]
struct CreatePocketResponse {
    success: bool,
    pocket_id: String,
    deposit_address: String,
    amount_lamports: u64,
    fee_lamports: u64,
    total_deposit: u64,
    expires_at: i64,
    maze_info: MazeInfo,
}

#[derive(Debug, Serialize)]
struct MazeInfo {
    nodes: usize,
    levels: u8,
    estimated_time_seconds: u32,
}


// ============ DIRECT ROUTE ============

#[derive(Debug, Deserialize)]
struct RouteRequest {
    meta_address: String,
    amount_sol: f64,
    destination_slot: Option<u8>,
    destination: Option<String>,
    maze_config: Option<CustomMazeConfig>,
}

#[derive(Debug, Serialize)]
struct RouteResponse {
    success: bool,
    route_id: String,
    deposit_address: String,
    destination: String,
    amount_lamports: u64,
    fee_lamports: u64,
    total_deposit: u64,
    expires_at: i64,
    maze_info: MazeInfo,
}
#[derive(Debug, Deserialize)]
struct ListPocketsQuery {
    meta_address: String,
}

#[derive(Debug, Serialize)]
struct PocketInfo {
    id: String,
    address: String,
    balance_lamports: u64,
    balance_sol: f64,
    status: String,
    created_at: i64,
    funding_amount_lamports: u64,
}

#[derive(Debug, Serialize)]
struct ListPocketsResponse {
    success: bool,
    pockets: Vec<PocketInfo>,
    count: usize,
}

#[derive(Debug, Deserialize)]
struct GetPocketQuery {
    meta_address: String,
}

#[derive(Debug, Serialize)]
struct GetPocketResponse {
    success: bool,
    pocket: Option<PocketDetailInfo>,
    message: Option<String>,
}

#[derive(Debug, Serialize)]
struct PocketDetailInfo {
    id: String,
    address: String,
    private_key: String,
    balance_lamports: u64,
    balance_sol: f64,
    status: String,
    created_at: i64,
    funding_amount_lamports: u64,
    last_sweep_at: Option<i64>,
}

#[derive(Debug, Deserialize)]
struct SweepRequest {
    meta_address: String,
    destination_slot: Option<u8>,
    destination: Option<String>,  // Direct address (fallback)
    maze_config: Option<CustomMazeConfig>,
}

#[derive(Debug, Serialize)]
struct SweepResponse {
    sweep_id: Option<String>,
    success: bool,
    message: String,
    amount_swept: Option<u64>,
    destination: Option<String>,
    tx_signature: Option<String>,
}

#[derive(Debug, Deserialize)]
struct DeletePocketRequest {
    meta_address: String,
}

#[derive(Debug, Serialize)]
struct DeletePocketResponse {
    success: bool,
    message: String,
}

#[derive(Debug, Serialize)]
struct StatusResponse {
    tx_signature: Option<String>,
    success: bool,
    request_id: String,
    status: String,
    progress: Option<MazeProgress>,
    error: Option<String>,
}

#[derive(Debug, Serialize)]
struct MazeProgress {
    completed_nodes: usize,
    total_nodes: usize,
    current_level: u8,
    total_levels: u8,
    percentage: u8,
}

#[derive(Debug, Serialize)]
struct ErrorResponse {
    success: bool,
    error: String,
}

#[derive(Debug, Serialize)]
struct StatsResponse {
    total_nodes_alltime: i64,
    total_hops_alltime: i64,
    nodes_24h: i64,
}

// ============ SWEEP ALL POCKETS (Phase 3) ============

#[derive(Debug, Deserialize)]
struct SweepAllPocketsRequest {
    meta_address: String,
    destination_slot: Option<u8>,
    destination: Option<String>,
    maze_config: Option<CustomMazeConfig>,
}

#[derive(Debug, Serialize)]
struct SweepAllPocketResult {
    pocket_id: String,
    success: bool,
    sweep_id: Option<String>,
    amount_swept: Option<u64>,
    error: Option<String>,
}

#[derive(Debug, Serialize)]
struct SweepAllPocketsResponse {
    success: bool,
    total_pockets: usize,
    successful_sweeps: usize,
    failed_sweeps: usize,
    total_amount_swept: u64,
    destination: String,
    results: Vec<SweepAllPocketResult>,
}

// ============ UTILITY FUNCTIONS ============

fn hash_meta_address(meta: &str) -> String {
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(meta.as_bytes());
    hex::encode(hasher.finalize())
}

fn parse_maze_config(config: Option<CustomMazeConfig>) -> MazeParameters {
    let mut params = MazeParameters::random();
    
    if let Some(cfg) = config {
        if let Some(hops) = cfg.hop_count {
            params.hop_count = hops.max(5).min(10);
        }
        if let Some(ratio) = cfg.split_ratio {
            params.split_ratio = ratio.max(1.1).min(3.0);
        }
        if let Some(ref strategy) = cfg.merge_strategy {
            params.merge_strategy = match strategy.as_str() {
                "early" => MergeStrategy::Early,
                "late" => MergeStrategy::Late,
                "middle" => MergeStrategy::Middle,
                "fibonacci" => MergeStrategy::Fibonacci,
                _ => MergeStrategy::Random,
            };
        }
        if let Some(ref pattern) = cfg.delay_pattern {
            params.delay_pattern = match pattern.as_str() {
                "none" => DelayPattern::None,
                "linear" => DelayPattern::Linear,
                "exponential" => DelayPattern::Exponential,
                "fibonacci" => DelayPattern::Fibonacci,
                _ => DelayPattern::Random,
            };
        }
        if let Some(ms) = cfg.delay_ms {
            params.delay_ms = ms.min(5000);
        }
        if let Some(ref scope) = cfg.delay_scope {
            params.delay_scope = match scope.as_str() {
                "level" => DelayScope::Level,
                _ => DelayScope::Node,
            };
        }
    }
    
    params
}


// ============ API HANDLERS ============

/// Health check endpoint
async fn health_check() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "status": "ok",
        "service": "sdp-mazepocket",
        "version": "1.0.0"
    }))
}


/// Tier config endpoint for MCP
async fn tier_config(
    State(state): State<Arc<AppState>>,
) -> Json<serde_json::Value> {
    // Get active partners from database
    let partner_tokens: Vec<serde_json::Value> = match state.db.list_partners() {
        Ok(partners) => partners.iter().map(|p| {
            serde_json::json!({
                "symbol": p.token_symbol,
                "mint": p.token_mint,
                "thresholds": {
                    "BASIC": p.tier_basic,
                    "PRO": p.tier_pro
                },
                "max_tier": "PRO",
                "is_official": p.is_official_partner
            })
        }).collect(),
        Err(_) => vec![],
    };

    Json(serde_json::json!({
        "master_token": {
            "symbol": "KAUSA",
            "mint": "BWXSNRBKMviG68MqavyssnzDq4qSArcN7eNYjqEfpump",
            "thresholds": {
                "BASIC": 1000,
                "PRO": 10000,
                "ENTERPRISE": 100000
            },
            "minimum_for_partner_unlock": 100
        },
        "partner_tokens": partner_tokens,
        "limits": {
            "FREE": {
                "fee_percent": 2.0,
                "max_complexity": "medium",
                "max_amount_sol": 0.1,
                "daily_routes": 1
            },
            "BASIC": {
                "fee_percent": 1.0,
                "max_complexity": "high",
                "max_amount_sol": 1,
                "daily_routes": 5
            },
            "PRO": {
                "fee_percent": 0.5,
                "max_complexity": "high",
                "max_amount_sol": 10,
                "daily_routes": 20
            },
            "ENTERPRISE": {
                "fee_percent": 0.25,
                "max_complexity": "high",
                "max_amount_sol": 100,
                "daily_routes": 100
            }
        }
    }))
}


/// Protocol stats endpoint
async fn stats_handler(
    State(state): State<Arc<AppState>>,
) -> std::result::Result<Json<StatsResponse>, AppError> {
    let stats = state.db.get_protocol_stats()?;
    Ok(Json(StatsResponse {
        total_nodes_alltime: stats.total_nodes_alltime,
        total_hops_alltime: stats.total_hops_alltime,
        nodes_24h: stats.nodes_24h,
    }))
}
/// Create a new Maze Pocket
async fn create_pocket(
    State(state): State<Arc<AppState>>,
    Json(req): Json<CreatePocketRequest>,
) -> std::result::Result<Json<CreatePocketResponse>, AppError> {
    info!("Create pocket request: {} SOL from {}", req.amount_sol, &req.meta_address[..20.min(req.meta_address.len())]);

    // Validate amount
    if req.amount_sol < MIN_AMOUNT_SOL {
        return Err(MazeError::InvalidParameters(format!("Minimum amount is {} SOL", MIN_AMOUNT_SOL)).into());
    }

    let owner_meta_hash = hash_meta_address(&req.meta_address);
    let amount_lamports = sol_to_lamports(req.amount_sol);
    let fee_lamports = (amount_lamports as f64 * FEE_PERCENT / 100.0) as u64;

    // Parse maze config (available to ALL users, no KAUSA check)
    let maze_params = parse_maze_config(req.maze_config);

    // Generate pocket keypair
    let pocket_keypair = Keypair::new();
    let pocket_pubkey = pocket_keypair.pubkey().to_string();
    let pocket_id = generate_pocket_id();

    // Encrypt pocket keypair
    let keypair_encrypted = state.db.encrypt(&pocket_keypair.to_bytes())
        ?;

    // Generate maze for funding
    let generator = MazeGenerator::new(maze_params);
    let total_with_fees = amount_lamports + fee_lamports + (TX_FEE_LAMPORTS * 50);
    
    let encrypt_fn = |data: &[u8]| state.db.encrypt(data);
    let maze = generator.generate(total_with_fees, encrypt_fn)
        ?;

    let deposit_node = maze.get_deposit_node()
        .ok_or(MazeError::InvalidParameters("Not found".into()))?;

    let deposit_address = deposit_node.address.clone();
    let now = chrono::Utc::now().timestamp();

    // Create pocket record (status: pending until funded)
    let pocket = MazePocket {
        id: pocket_id.clone(),
        owner_meta_hash: owner_meta_hash.clone(),
        stealth_pubkey: pocket_pubkey.clone(),
        keypair_encrypted,
        funding_maze_id: None, // Will be set after funding
        funding_amount_lamports: amount_lamports,
        created_at: now,
        last_sweep_at: None,
        status: PocketStatus::Active,
        label: None,
        archived: false,
    };

    state.db.create_pocket(&pocket)
        ?;

    // Create funding request
    let request_id = format!("fund_{}", &pocket_id[7..]); // fund_xxxxxxxx
    let maze_json = serde_json::to_string(&maze).unwrap_or_default();
    
    let deposit_keypair_encrypted = deposit_node.keypair_encrypted.clone();

    let funding_request = FundingRequest {
        id: request_id.clone(),
        pocket_id: pocket_id.clone(),
        owner_meta_hash,
        deposit_address: deposit_address.clone(),
        deposit_keypair_encrypted,
        amount_lamports,
        fee_lamports,
        maze_config_json: None,
        status: "pending".to_string(),
        created_at: now,
        expires_at: now + EXPIRY_SECONDS,
        completed_at: None,
        error_message: None,
        tx_signature: None,
        destination_address: None,
    };

    state.db.create_funding_request(&funding_request, &maze_json)
        ?;

    // Store maze nodes
    for node in &maze.nodes {
        state.db.store_maze_node(&request_id, node)
            ?;
    }

    let total_deposit = amount_lamports + fee_lamports + (TX_FEE_LAMPORTS * maze.total_transactions as u64);

    info!("Pocket {} created with deposit address {}", pocket_id, deposit_address);

    Ok(Json(CreatePocketResponse {
        success: true,
        pocket_id,
        deposit_address,
        amount_lamports,
        fee_lamports,
        total_deposit,
        expires_at: now + EXPIRY_SECONDS,
        maze_info: MazeInfo {
            nodes: maze.nodes.len(),
            levels: maze.total_levels,
            estimated_time_seconds: (maze.nodes.len() as u32) * 2,
        },
    }))
}


/// Create a direct route (A -> maze -> B without pocket)
async fn create_route(
    State(state): State<Arc<AppState>>,
    Json(req): Json<RouteRequest>,
) -> std::result::Result<Json<RouteResponse>, AppError> {

    // Validate amount
    if req.amount_sol < MIN_AMOUNT_SOL {
        return Err(MazeError::InvalidParameters(format!("Minimum amount is {} SOL", MIN_AMOUNT_SOL)).into());
    }
    let owner_meta_hash = hash_meta_address(&req.meta_address);

    // Determine destination - prefer slot, then direct address
    let destination = if let Some(slot) = req.destination_slot {
        if slot < 1 || slot > 5 {
            return Err(MazeError::InvalidParameters("Invalid slot. Must be 1-5".into()).into());
        }
        match state.db.get_destination_wallet(&owner_meta_hash, slot)? {
            Some(addr) => addr,
            None => return Err(MazeError::InvalidParameters(format!("No wallet saved in slot {}", slot)).into()),
        }
    } else if let Some(ref addr) = req.destination {
        addr.clone()
    } else {
        return Err(MazeError::InvalidParameters("Must specify destination_slot (1-5) or destination address".into()).into());
    };

    info!("Create route request: {} SOL to {}", req.amount_sol, &destination[..20.min(destination.len())]);

    // Validate destination is valid Solana address
    let _destination_pubkey = Pubkey::from_str(&destination)
        .map_err(|_| MazeError::InvalidParameters("Invalid destination address".into()))?;
    let amount_lamports = sol_to_lamports(req.amount_sol);
    let fee_lamports = (amount_lamports as f64 * FEE_PERCENT / 100.0) as u64;

    // Parse maze config
    let maze_params = parse_maze_config(req.maze_config);

    // Generate route ID (no pocket needed)
    let route_id = format!("route_{}", &generate_pocket_id()[7..]);

    // Generate maze for routing
    let generator = MazeGenerator::new(maze_params);
    let total_with_fees = amount_lamports + fee_lamports + (TX_FEE_LAMPORTS * 50);

    let encrypt_fn = |data: &[u8]| state.db.encrypt(data);
    let maze = generator.generate(total_with_fees, encrypt_fn)?;

    let deposit_node = maze.get_deposit_node()
        .ok_or(MazeError::InvalidParameters("Deposit node not found".into()))?;

    let deposit_address = deposit_node.address.clone();
    let now = chrono::Utc::now().timestamp();


    // Create virtual pocket entry for FOREIGN KEY constraint
    let virtual_keypair = Keypair::new();
    let keypair_encrypted = state.db.encrypt(&virtual_keypair.to_bytes())?;
    let pocket = MazePocket {
        id: route_id.clone(),
        owner_meta_hash: owner_meta_hash.clone(),
        stealth_pubkey: destination.clone(), // Use destination as stealth_pubkey
        keypair_encrypted,
        funding_maze_id: None,
        funding_amount_lamports: amount_lamports,
        created_at: now,
        last_sweep_at: None,
        status: PocketStatus::Active,
        label: None,
        archived: false,
    };
    state.db.create_pocket(&pocket)?;
    // Create funding request with destination (direct route)
    let request_id = format!("fund_{}", &route_id[6..]); // fund_xxxxxxxx
    let maze_json = serde_json::to_string(&maze).unwrap_or_default();
    let deposit_keypair_encrypted = deposit_node.keypair_encrypted.clone();

    let funding_request = FundingRequest {
        id: request_id.clone(),
        pocket_id: route_id.clone(), // Use route_id as pocket_id for tracking
        owner_meta_hash,
        deposit_address: deposit_address.clone(),
        deposit_keypair_encrypted,
        amount_lamports,
        fee_lamports,
        maze_config_json: None,
        status: "pending".to_string(),
        created_at: now,
        expires_at: now + EXPIRY_SECONDS,
        completed_at: None,
        error_message: None,
        destination_address: Some(destination.clone()),
        tx_signature: None,
    };

    state.db.create_funding_request(&funding_request, &maze_json)?;

    // Store maze nodes
    for node in &maze.nodes {
        state.db.store_maze_node(&request_id, node)?;
    }

    let total_deposit = amount_lamports + fee_lamports + (TX_FEE_LAMPORTS * maze.total_transactions as u64);

    info!("Route {} created with deposit address {}, destination {}", route_id, deposit_address, destination);

    Ok(Json(RouteResponse {
        success: true,
        route_id,
        deposit_address,
        destination: destination,
        amount_lamports,
        fee_lamports,
        total_deposit,
        expires_at: now + EXPIRY_SECONDS,
        maze_info: MazeInfo {
            nodes: maze.nodes.len(),
            levels: maze.total_levels,
            estimated_time_seconds: (maze.nodes.len() as u32) * 2,
        },
    }))
}
/// List all pockets for a user
async fn list_pockets(
    State(state): State<Arc<AppState>>,
    Query(query): Query<ListPocketsQuery>,
) -> std::result::Result<Json<ListPocketsResponse>, AppError> {
    let owner_meta_hash = hash_meta_address(&query.meta_address);

    let pockets = state.db.list_pockets(&owner_meta_hash)
        ?;

    let mut pocket_infos = Vec::new();
    for pocket in &pockets {
        // Get current balance from RPC
        let balance = if let Ok(pubkey) = Pubkey::from_str(&pocket.stealth_pubkey) {
            state.rpc.get_balance(&pubkey).unwrap_or(0)
        } else {
            0
        };

        pocket_infos.push(PocketInfo {
            id: pocket.id.clone(),
            address: pocket.stealth_pubkey.clone(),
            balance_lamports: balance,
            balance_sol: lamports_to_sol(balance),
            status: pocket.status.as_str().to_string(),
            created_at: pocket.created_at,
            funding_amount_lamports: pocket.funding_amount_lamports,
        });
    }

    Ok(Json(ListPocketsResponse {
        success: true,
        count: pocket_infos.len(),
        pockets: pocket_infos,
    }))
}

/// Get pocket details (including private key for export)
async fn get_pocket(
    State(state): State<Arc<AppState>>,
    Path(pocket_id): Path<String>,
    Query(query): Query<GetPocketQuery>,
) -> std::result::Result<Json<GetPocketResponse>, AppError> {
    let owner_meta_hash = hash_meta_address(&query.meta_address);

    let pocket = state.db.get_pocket_for_owner(&pocket_id, &owner_meta_hash)
        ?;

    match pocket {
        Some(p) => {
            // Decrypt keypair to get private key
            let keypair_bytes = state.db.decrypt(&p.keypair_encrypted)
                ?;

            let keypair = Keypair::from_bytes(&keypair_bytes)
                .map_err(|e| MazeError::KeypairError(e.to_string()))?;

            // Get current balance
            let balance = if let Ok(pubkey) = Pubkey::from_str(&p.stealth_pubkey) {
                state.rpc.get_balance(&pubkey).unwrap_or(0)
            } else {
                0
            };

            // Export private key as base58
            let private_key = bs58::encode(&keypair.to_bytes()).into_string();

            Ok(Json(GetPocketResponse {
                success: true,
                pocket: Some(PocketDetailInfo {
                    id: p.id,
                    address: p.stealth_pubkey,
                    private_key,
                    balance_lamports: balance,
                    balance_sol: lamports_to_sol(balance),
                    status: p.status.as_str().to_string(),
                    created_at: p.created_at,
                    funding_amount_lamports: p.funding_amount_lamports,
                    last_sweep_at: p.last_sweep_at,
                }),
                message: None,
            }))
        }
        None => Ok(Json(GetPocketResponse {
            success: false,
            pocket: None,
            message: Some("Pocket not found or access denied".to_string()),
        })),
    }
}
/// Sweep pocket funds back to user via maze routing
async fn sweep_pocket(
    State(state): State<Arc<AppState>>,
    Path(pocket_id): Path<String>,
    Json(req): Json<SweepRequest>,
) -> std::result::Result<Json<SweepResponse>, AppError> {
    let owner_meta_hash = hash_meta_address(&req.meta_address);

    // Get pocket
    let pocket = state.db.get_pocket_for_owner(&pocket_id, &owner_meta_hash)?;

    let pocket = match pocket {
        Some(p) => p,
        None => return Ok(Json(SweepResponse {
            sweep_id: None,
            success: false,
            message: "Pocket not found or access denied".to_string(),
            amount_swept: None,
            destination: None,
            tx_signature: None,
        })),
    };

    if pocket.status == PocketStatus::Sweeping {
        return Ok(Json(SweepResponse {
            sweep_id: None,
            success: false,
            message: "Sweep already in progress".to_string(),
            amount_swept: None,
            destination: None,
            tx_signature: None,
        }));
    }

    // Get pocket keypair
    let keypair_bytes = state.db.decrypt(&pocket.keypair_encrypted)?;
    let pocket_keypair = Keypair::from_bytes(&keypair_bytes)
        .map_err(|e| MazeError::KeypairError(e.to_string()))?;

    // Check balance
    let balance = state.rpc.get_balance(&pocket_keypair.pubkey())
        .map_err(|e| MazeError::RpcError(e.to_string()))?;

    if balance <= TX_FEE_LAMPORTS * 20 {
        return Ok(Json(SweepResponse {
            sweep_id: None,
            success: false,
            message: "Pocket has insufficient funds for maze routing fees".to_string(),
            amount_swept: None,
            destination: None,
            tx_signature: None,
        }));
    }

    // Determine destination - prefer slot, then direct address
    let destination = if let Some(slot) = req.destination_slot {
        if slot < 1 || slot > 5 {
            return Ok(Json(SweepResponse {
                sweep_id: None,
                success: false,
                message: "Invalid slot. Must be 1-5".to_string(),
                amount_swept: None,
                destination: None,
                tx_signature: None,
            }));
        }
        match state.db.get_destination_wallet(&owner_meta_hash, slot)? {
            Some(addr) => addr,
            None => return Ok(Json(SweepResponse {
                sweep_id: None,
                success: false,
                message: format!("No wallet saved in slot {}", slot),
                amount_swept: None,
                destination: None,
                tx_signature: None,
            })),
        }
    } else if let Some(ref addr) = req.destination {
        addr.clone()
    } else {
        return Ok(Json(SweepResponse {
            sweep_id: None,
            success: false,
            message: "Must specify destination_slot (1-5) or destination address".to_string(),
            amount_swept: None,
            destination: None,
            tx_signature: None,
        }));
    };

    // Validate destination is valid Solana address
    Pubkey::from_str(&destination)
        .map_err(|_| MazeError::InvalidParameters("Invalid destination address".into()))?;

    // Mark as sweeping
    state.db.update_pocket_status(&pocket_id, PocketStatus::Sweeping)?;

    // Generate sweep maze
    let maze_params = parse_maze_config(req.maze_config);
    let generator = MazeGenerator::new(maze_params);
    // Sweep entire balance minus just the TX fee for initial transfer
    // Pocket will be drained to 0 (closed by Solana)
    let sweep_amount = balance.saturating_sub(TX_FEE_LAMPORTS);
    let encrypt_fn = |data: &[u8]| state.db.encrypt(data);
    
    let maze = match generator.generate(sweep_amount, encrypt_fn) {
        Ok(m) => m,
        Err(e) => {
            state.db.update_pocket_status(&pocket_id, PocketStatus::Active)?;
            return Ok(Json(SweepResponse {
                sweep_id: None,
                success: false,
                message: format!("Failed to generate sweep maze: {}", e),
                amount_swept: None,
                destination: None,
                tx_signature: None,
            }));
        }
    };

    let sweep_id = format!("sweep_{}", &pocket_id[7..]); // Remove "pocket_" prefix
    let maze_json = serde_json::to_string(&maze).unwrap();

    // Save sweep request
    state.db.create_sweep_request(&sweep_id, &pocket_id, &destination, sweep_amount, &maze_json)?;

    // Store maze nodes for progress tracking
    for node in &maze.nodes {
        state.db.store_sweep_node(&sweep_id, node)?;
    }

    // Transfer from pocket to first maze node
    let first_node = &maze.nodes[0];
    let first_node_pubkey = Pubkey::from_str(&first_node.address)
        .map_err(|e| MazeError::InvalidParameters(e.to_string()))?;

    let sig = {
        let mut last_err = String::new();
        let mut result_sig = None;
        for attempt in 1..=5u8 {
            let blockhash = match state.rpc.get_latest_blockhash() {
                Ok(bh) => bh,
                Err(e) => {
                    warn!("Sweep initial attempt {}/5: Failed to get blockhash: {}", attempt, e);
                    last_err = e.to_string();
                    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
                    continue;
                }
            };
            let ix = system_instruction::transfer(
                &pocket_keypair.pubkey(),
                &first_node_pubkey,
                sweep_amount,
            );
            let tx = Transaction::new_signed_with_payer(
                &[ix],
                Some(&pocket_keypair.pubkey()),
                &[&pocket_keypair],
                blockhash,
            );
            let config = RpcSendTransactionConfig {
                skip_preflight: true,
                preflight_commitment: None,
                encoding: None,
                max_retries: Some(3),
                min_context_slot: None,
            };
            match state.rpc.send_transaction_with_config(&tx, config) {
                Ok(s) => {
                    if attempt > 1 {
                        info!("Sweep initial TX succeeded on attempt {}/5", attempt);
                    }
                    result_sig = Some(s);
                    break;
                }
                Err(e) => {
                    let err_str = e.to_string();
                    if err_str.contains("connection") || err_str.contains("timeout") || err_str.contains("closed") {
                        warn!("Sweep initial attempt {}/5: {}", attempt, err_str);
                        last_err = err_str;
                        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
                        continue;
                    }
                    let _ = state.db.update_pocket_status(&pocket_id, PocketStatus::Active);
                    return Err(AppError(MazeError::TransactionError(format!("TX failed: {}", e))));
                }
            }
        }
        match result_sig {
            Some(s) => s,
            None => {
                let _ = state.db.update_pocket_status(&pocket_id, PocketStatus::Active);
                return Err(AppError(MazeError::TransactionError(format!("TX failed after 5 attempts: {}", last_err))));
            }
        }
    };

    // Wait for confirmation before spawning background task
    let mut confirmed = false;
    for _ in 0..30 {
        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
        if let Ok(Some(result)) = state.rpc.get_signature_status(&sig) {
            if result.is_ok() {
                confirmed = true;
                break;
            } else if let Err(e) = result {
                let _ = state.db.update_pocket_status(&pocket_id, PocketStatus::Active);
                return Err(AppError(MazeError::TransactionError(format!("Initial transfer failed: {:?}", e))));
            }
        }
    }
    
    if !confirmed {
        let _ = state.db.update_pocket_status(&pocket_id, PocketStatus::Active);
        return Err(AppError(MazeError::TransactionError("Initial transfer confirmation timeout".into())));
    }

    info!("Sweep initiated for {}: {} lamports via maze to {}", pocket_id, sweep_amount, destination);

    // Execute sweep maze in background
    let state_clone = state.clone();
    let sweep_id_clone = sweep_id.clone();
    let pocket_id_clone = pocket_id.clone();
    tokio::spawn(async move {
        match execute_sweep_maze(state_clone.clone(), &sweep_id_clone).await {
            Ok(_) => {
                let _ = state_clone.db.mark_pocket_swept(&pocket_id_clone);
                info!("Sweep maze completed for {}", pocket_id_clone);
            }
            Err(e) => {
                error!("Sweep maze failed for {}: {}", pocket_id_clone, sanitize_error(&e.to_string()));
                let _ = state_clone.db.update_pocket_status(&pocket_id_clone, PocketStatus::Active);
                let _ = state_clone.db.update_sweep_status(&sweep_id_clone, "failed", None, Some(&sanitize_error(&e.to_string())));
            }
        }
    });

    Ok(Json(SweepResponse {
        sweep_id: Some(sweep_id.clone()),
        success: true,
        message: "Sweep initiated via maze routing".to_string(),
        amount_swept: Some(sweep_amount),
        destination: Some(destination),
        tx_signature: Some(sig.to_string()),
    }))
}

/// Delete a pocket (soft delete)
async fn delete_pocket(
    State(state): State<Arc<AppState>>,
    Path(pocket_id): Path<String>,
    Json(req): Json<DeletePocketRequest>,
) -> std::result::Result<Json<DeletePocketResponse>, AppError> {
    let owner_meta_hash = hash_meta_address(&req.meta_address);

    // Check if pocket exists and is swept
    let pocket = state.db.get_pocket_for_owner(&pocket_id, &owner_meta_hash)
        ?;

    match pocket {
        Some(p) => {
            // Check balance before delete
            let balance = if let Ok(pubkey) = Pubkey::from_str(&p.stealth_pubkey) {
                state.rpc.get_balance(&pubkey).unwrap_or(0)
            } else {
                0
            };

            if balance > TX_FEE_LAMPORTS {
                return Ok(Json(DeletePocketResponse {
                    success: false,
                    message: format!("Cannot delete pocket with balance. Sweep first. Current balance: {} SOL", lamports_to_sol(balance)),
                }));
            }

            state.db.delete_pocket(&pocket_id, &owner_meta_hash)
                ?;

            info!("Pocket {} deleted", pocket_id);

            Ok(Json(DeletePocketResponse {
                success: true,
                message: "Pocket deleted".to_string(),
            }))
        }
        None => Ok(Json(DeletePocketResponse {
            success: false,
            message: "Pocket not found or access denied".to_string(),
        })),
    }
}

/// Get funding request status
async fn get_funding_status(
    State(state): State<Arc<AppState>>,
    Path(request_id): Path<String>,
) -> std::result::Result<Json<StatusResponse>, AppError> {
    // Convert pocket_id to fund_id if needed
    let fund_id = if request_id.starts_with("route_") {
        format!("fund_{}", &request_id[6..])
    } else if request_id.starts_with("pocket_") {
        format!("fund_{}", &request_id[7..])
    } else if request_id.starts_with("fund_") {
        request_id.clone()
    } else {
        format!("fund_{}", request_id)
    };
    
    // Get funding request status
    let funding_req = state.db.get_funding_request(&fund_id)?;
    
    match funding_req {
        Some(req) => {
            let progress = if req.status == "processing" || req.status == "deposit_received" {
                // Get maze progress
                if let Ok((completed, total, current_level, total_levels)) = state.db.get_maze_progress(&fund_id) {
                    let percentage = if total > 0 { (completed * 100 / total) as u8 } else { 0 };
                    Some(MazeProgress {
                        completed_nodes: completed,
                        total_nodes: total,
                        current_level,
                        total_levels,
                        percentage,
                    })
                } else {
                    None
                }
            } else {
                None
            };
            
            Ok(Json(StatusResponse {
                success: true,
                request_id,
                status: req.status,
                progress,
                tx_signature: req.tx_signature,
                error: req.error_message,
            }))
        }
        None => Ok(Json(StatusResponse {
            success: false,
            request_id: fund_id,
            status: "not_found".to_string(),
            progress: None,
            tx_signature: None,
            error: Some("Funding request not found".to_string()),
        })),
    }
}


// ============ SWEEP STATUS ============

#[derive(Serialize)]
struct SweepStatusResponse {
    success: bool,
    sweep_id: String,
    status: String,
    progress: Option<MazeProgress>,
    destination: Option<String>,
    amount_lamports: Option<u64>,
    tx_signature: Option<String>,
    error: Option<String>,
}

async fn get_sweep_status(
    State(state): State<Arc<AppState>>,
    Path(sweep_id): Path<String>,
) -> std::result::Result<Json<SweepStatusResponse>, AppError> {
    let sweep_req = state.db.get_sweep_request(&sweep_id)?;
    
    match sweep_req {
        Some(req) => {
            let status = req.5.clone(); // status is 6th element (index 5)
            
            let progress = if status == "processing" {
                // Get maze progress from sweep nodes
                if let Ok((completed, total, current_level, total_levels)) = state.db.get_sweep_maze_progress(&sweep_id) {
                    let percentage = if total > 0 { (completed * 100 / total) as u8 } else { 0 };
                    Some(MazeProgress {
                        completed_nodes: completed,
                        total_nodes: total,
                        current_level,
                        total_levels,
                        percentage,
                    })
                } else {
                    None
                }
            } else {
                None
            };
            
            Ok(Json(SweepStatusResponse {
                success: true,
                sweep_id,
                status,
                progress,
                destination: Some(req.2.clone()), // destination_address is 3rd element
                amount_lamports: Some(req.3),      // amount_lamports is 4th element
                tx_signature: None,
                error: None,
            }))
        }
        None => Ok(Json(SweepStatusResponse {
            success: false,
            sweep_id,
            status: "not_found".to_string(),
            progress: None,
            destination: None,
            amount_lamports: None,
            tx_signature: None,
            error: Some("Sweep request not found".to_string()),
        })),
    }
}





/// Get balance with retry for connection errors
async fn get_balance_with_retry(
    rpc: &RpcClient,
    pubkey: &Pubkey,
    max_retries: u8,
) -> Result<u64> {
    let mut last_err = String::new();
    for attempt in 1..=max_retries {
        match rpc.get_balance(pubkey) {
            Ok(balance) => return Ok(balance),
            Err(e) => {
                let err_str = e.to_string();
                if err_str.contains("connection") || err_str.contains("timeout") || err_str.contains("closed") {
                    warn!("get_balance attempt {}/{}: {}", attempt, max_retries, err_str);
                    last_err = err_str;
                    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
                    continue;
                }
                return Err(MazeError::RpcError(err_str));
            }
        }
    }
    Err(MazeError::RpcError(format!("get_balance failed after {} attempts: {}", max_retries, last_err)))
}


// ============ MAZE EXECUTION (Copied from sdp-maze with fixes) ============

async fn execute_maze(state: Arc<AppState>, request_id: &str) -> Result<()> {
    info!("Executing maze for funding request {}", request_id);

    // Update status to processing so frontend can show progress
    state.db.update_funding_status(request_id, "processing", None)?;

    // Get maze graph from database
    let maze_json = state.db.get_maze_graph(request_id)?;
    let maze: MazeGraph = serde_json::from_str(&maze_json)
        .map_err(|e| MazeError::DatabaseError(e.to_string()))?;

    // Execute level by level (start from 0 - the deposit node)
    for level in 0..=maze.total_levels {
        let nodes_at_level: Vec<&MazeNode> = maze.nodes.iter()
            .filter(|n| n.level == level)
            .collect();

        info!("Processing level {} with {} nodes", level, nodes_at_level.len());

        for node in nodes_at_level {
            // Check if already completed
            if let Some(status) = state.db.get_node_status(request_id, node.index)? {
                if status == "completed" {
                    continue;
                }
            }

            // Execute node
            execute_node(state.clone(), request_id, node, &maze).await?;

            // Apply delay based on pattern
            let delay_ms = calculate_delay(&maze.parameters, node.level);
            if delay_ms > 0 {
                info!("Delay {}ms after node {}", delay_ms, node.index);
                tokio::time::sleep(tokio::time::Duration::from_millis(delay_ms)).await;
            }
        }
    }

    // Get final tx_signature and update funding request
    let final_tx_sig = state.db.get_final_tx_signature(request_id)?;
    if let Some(sig) = final_tx_sig {
        state.db.update_funding_completed(request_id, &sig)?;
    } else {
        state.db.update_funding_status(request_id, "completed", None)?;
    }

    // Get pocket_id and update pocket with funding_maze_id
    if let Some(funding_req) = state.db.get_funding_request(request_id)? {
        state.db.update_pocket_funding_maze(&funding_req.pocket_id, request_id)?;
    }

    info!("Maze execution completed for {}", request_id);
    Ok(())
}

async fn execute_node(
    state: Arc<AppState>,
    request_id: &str,
    node: &MazeNode,
    maze: &MazeGraph,
) -> Result<()> {
    // Decrypt node keypair
    let keypair_bytes = state.db.decrypt(&node.keypair_encrypted)?;
    let keypair = Keypair::from_bytes(&keypair_bytes)
        .map_err(|e| MazeError::CryptoError(e.to_string()))?;

    // Get outputs
    let outputs = &node.outputs;

    // If no outputs, this is the final node - transfer to pocket
    if outputs.is_empty() {
        let mut final_sig: Option<String> = None;
        // Get the pocket pubkey from funding request
        if let Some(funding_req) = state.db.get_funding_request(request_id)? {
            if let Some(pocket) = state.db.get_pocket(&funding_req.pocket_id)? {
                let dest_pubkey = Pubkey::from_str(&pocket.stealth_pubkey)
                    .map_err(|e| MazeError::InvalidParameters(e.to_string()))?;

                let balance = get_balance_with_retry(&state.rpc, &keypair.pubkey(), 5).await?;
                let transfer_amount = balance.saturating_sub(TX_FEE_LAMPORTS);

                if transfer_amount > 0 {
                    let sig = {
                        let mut last_err = String::new();
                        let mut result_sig = None;
                        for attempt in 1..=5u8 {
                            let blockhash = match state.rpc.get_latest_blockhash() {
                                Ok(bh) => bh,
                                Err(e) => {
                                    warn!("Final to pocket attempt {}/5: Failed to get blockhash: {}", attempt, e);
                                    last_err = e.to_string();
                                    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
                                    continue;
                                }
                            };
                            let ix = system_instruction::transfer(&keypair.pubkey(), &dest_pubkey, transfer_amount);
                            let tx = Transaction::new_signed_with_payer(
                                &[ix],
                                Some(&keypair.pubkey()),
                                &[&keypair],
                                blockhash,
                            );
                            let config = RpcSendTransactionConfig {
                                skip_preflight: true,
                                preflight_commitment: None,
                                encoding: None,
                                max_retries: Some(3),
                                min_context_slot: None,
                            };
                            match state.rpc.send_transaction_with_config(&tx, config) {
                                Ok(s) => {
                                    if attempt > 1 {
                                        info!("Final to pocket TX succeeded on attempt {}/5", attempt);
                                    }
                                    result_sig = Some(s);
                                    break;
                                }
                                Err(e) => {
                                    let err_str = e.to_string();
                                    if err_str.contains("connection") || err_str.contains("timeout") || err_str.contains("closed") {
                                        warn!("Final to pocket attempt {}/5: {}", attempt, err_str);
                                        last_err = err_str;
                                        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
                                        continue;
                                    }
                                    return Err(MazeError::TransactionError(format!("TX failed: {}", e)));
                                }
                            }
                        }
                        result_sig.ok_or_else(|| MazeError::TransactionError(format!("TX failed after 5 attempts: {}", last_err)))?
                    };
                    final_sig = Some(sig.to_string());
                    info!("Final transfer to pocket: {} lamports ({})", transfer_amount, sig);
                }
            }
        }

        state.db.update_node_status(request_id, node.index, "completed", final_sig.as_deref())?;
        return Ok(());
    }

    // Wait for incoming funds (level 0 already has deposit from user)
    let mut attempts = 0;
    let balance = loop {
        let bal = match get_balance_with_retry(&state.rpc, &keypair.pubkey(), 5).await {
            Ok(b) => b,
            Err(_) => continue,
        };
        if bal > TX_FEE_LAMPORTS {
            info!("Node {} has balance: {} lamports", node.index, bal);
            break bal;
        }
        attempts += 1;
        if attempts > 120 {
            return Err(MazeError::TransactionError(
                format!("Timeout waiting for funds at node {}", node.index)
            ));
        }
        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
    };

    let num_outputs = outputs.len();
    let total_fees = TX_FEE_LAMPORTS * num_outputs as u64;
    let distributable = balance.saturating_sub(total_fees);

    if distributable == 0 {
        return Err(MazeError::InsufficientFunds {
            required: total_fees + 1,
            available: balance,
        });
    }

    // Calculate all transfer amounts DETERMINISTICALLY upfront
    let base_amount = distributable / num_outputs as u64;
    let remainder = distributable % num_outputs as u64;

    let mut amounts: Vec<u64> = Vec::with_capacity(num_outputs);
    for i in 0..num_outputs {
        if i == num_outputs - 1 {
            amounts.push(base_amount + remainder);
        } else {
            amounts.push(base_amount);
        }
    }

    // Verify math
    let total_to_send: u64 = amounts.iter().sum();
    if total_to_send + total_fees != balance {
        error!("Amount calculation mismatch: {} + {} != {}", total_to_send, total_fees, balance);
        return Err(MazeError::InsufficientFunds {
            required: total_to_send + total_fees,
            available: balance,
        });
    }

    // Sequential transfers with pre-calculated amounts
    let mut last_sig = String::new();
    for (i, &output_idx) in outputs.iter().enumerate() {
        if let Some(output_node) = maze.nodes.get(output_idx as usize) {
            let output_pubkey = Pubkey::from_str(&output_node.address)
                .map_err(|e| MazeError::InvalidParameters(e.to_string()))?;

            let transfer_amount = amounts[i];
            if transfer_amount == 0 {
                continue;
            }

            let sig = {
                let mut last_err = String::new();
                let mut result_sig = None;
                for attempt in 1..=5u8 {
                    let blockhash = match state.rpc.get_latest_blockhash() {
                        Ok(bh) => bh,
                        Err(e) => {
                            warn!("Node {} attempt {}/5: Failed to get blockhash: {}", node.index, attempt, e);
                            last_err = e.to_string();
                            tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
                            continue;
                        }
                    };
                    let ix = system_instruction::transfer(&keypair.pubkey(), &output_pubkey, transfer_amount);
                    let tx = Transaction::new_signed_with_payer(
                        &[ix],
                        Some(&keypair.pubkey()),
                        &[&keypair],
                        blockhash,
                    );
                    let config = RpcSendTransactionConfig {
                        skip_preflight: true,
                        preflight_commitment: None,
                        encoding: None,
                        max_retries: Some(3),
                        min_context_slot: None,
                    };
                    match state.rpc.send_transaction_with_config(&tx, config) {
                        Ok(s) => {
                            if attempt > 1 {
                                info!("Node {} TX succeeded on attempt {}/5", node.index, attempt);
                            }
                            result_sig = Some(s);
                            break;
                        }
                        Err(e) => {
                            let err_str = e.to_string();
                            if err_str.contains("connection") || err_str.contains("timeout") || err_str.contains("closed") {
                                warn!("Node {} attempt {}/5: {}", node.index, attempt, err_str);
                                last_err = err_str;
                                tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
                                continue;
                            }
                            return Err(MazeError::TransactionError(format!("TX failed: {}", e)));
                        }
                    }
                }
                result_sig.ok_or_else(|| MazeError::TransactionError(format!("TX failed after 5 attempts: {}", last_err)))?
            };

            // Wait for confirmation
            let mut confirmed = false;
            for _ in 0..30 {
                tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
                if let Ok(status) = state.rpc.get_signature_status(&sig) {
                    if let Some(result) = status {
                        if result.is_ok() {
                            confirmed = true;
                            break;
                        } else if let Err(e) = result {
                            return Err(MazeError::TransactionError(format!("TX failed: {:?}", e)));
                        }
                    }
                }
            }

            if !confirmed {
                return Err(MazeError::TransactionError("TX confirmation timeout".into()));
            }

            last_sig = sig.to_string();
            info!("Node {} transfer {}/{}: {} lamports to {} ({})",
                node.index, i + 1, num_outputs, transfer_amount, output_idx, last_sig);
        }
    }

    state.db.update_node_status(request_id, node.index, "completed", Some(&last_sig))?;
    info!("Node {} completed all {} transfers", node.index, num_outputs);

    Ok(())
}

/// Execute sweep maze routing (called from background task)
async fn execute_sweep_maze(
    state: Arc<AppState>,
    sweep_id: &str,
) -> Result<()> {
    info!("Executing sweep maze for {}", sweep_id);

    // Update status to processing so frontend can show progress
    state.db.update_sweep_status(sweep_id, "processing", None, None)?;

    // Get sweep request from database to get pocket_id and destination
    let sweep_req = state.db.get_sweep_request(sweep_id)?
        .ok_or(MazeError::RequestNotFound(sweep_id.into()))?;
    
    let pocket_id = sweep_req.1.clone();
    let destination = sweep_req.2.clone();

    // Get sweep maze graph
    let maze_json = state.db.get_sweep_maze_graph(sweep_id)?;
    let maze: MazeGraph = serde_json::from_str(&maze_json)
        .map_err(|e| MazeError::DatabaseError(e.to_string()))?;

    // Execute maze level by level (start from 0)
    for level in 0..=maze.total_levels {
        let nodes_at_level: Vec<&MazeNode> = maze.nodes.iter()
            .filter(|n| n.level == level)
            .collect();

        info!("Sweep level {} with {} nodes", level, nodes_at_level.len());

        for node in nodes_at_level {
            if let Some(status) = state.db.get_sweep_node_status(sweep_id, node.index)? {
                if status == "completed" {
                    continue;
                }
            }

            execute_sweep_node(state.clone(), sweep_id, node, &maze, &destination).await?;

            let delay_ms = calculate_delay(&maze.parameters, node.level);
            if delay_ms > 0 {
                tokio::time::sleep(tokio::time::Duration::from_millis(delay_ms)).await;
            }
        }
    }

    // Mark sweep as completed
    state.db.update_sweep_status(sweep_id, "completed", None, None)?;
    state.db.mark_pocket_swept(&pocket_id)?;

    info!("Sweep maze completed for {}", sweep_id);
    Ok(())
}

async fn execute_sweep_node(
    state: Arc<AppState>,
    sweep_id: &str,
    node: &MazeNode,
    maze: &MazeGraph,
    final_destination: &str,
) -> Result<()> {
    // Decrypt node keypair
    let keypair_bytes = state.db.decrypt(&node.keypair_encrypted)?;
    let keypair = Keypair::from_bytes(&keypair_bytes)
        .map_err(|e| MazeError::CryptoError(e.to_string()))?;
    
    let outputs = &node.outputs;
    
    // If no outputs, this is the final node - transfer to user destination
    if outputs.is_empty() {
        let dest_pubkey = Pubkey::from_str(final_destination)
            .map_err(|e| MazeError::ParseError(e.to_string()))?;
        
        // Wait for incoming funds
        let mut attempts = 0;
        let balance = loop {
            let bal = match get_balance_with_retry(&state.rpc, &keypair.pubkey(), 5).await {
                Ok(b) => b,
                Err(_) => continue,
            };
            if bal > TX_FEE_LAMPORTS {
                info!("Final sweep node {} has balance: {} lamports", node.index, bal);
                break bal;
            }
            attempts += 1;
            if attempts > 120 {
                return Err(MazeError::TransactionError(
                    format!("Timeout waiting for funds at final sweep node {}", node.index)
                ));
            }
            tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
        };
        let transfer_amount = balance.saturating_sub(TX_FEE_LAMPORTS);
        
        if transfer_amount > 0 {
            let sig = {
                let mut last_err = String::new();
                let mut result_sig = None;
                for attempt in 1..=5u8 {
                    let blockhash = match state.rpc.get_latest_blockhash() {
                        Ok(bh) => bh,
                        Err(e) => {
                            warn!("Final sweep attempt {}/5: Failed to get blockhash: {}", attempt, e);
                            last_err = e.to_string();
                            tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
                            continue;
                        }
                    };
                    let ix = system_instruction::transfer(&keypair.pubkey(), &dest_pubkey, transfer_amount);
                    let tx = Transaction::new_signed_with_payer(
                        &[ix],
                        Some(&keypair.pubkey()),
                        &[&keypair],
                        blockhash,
                    );
                    let config = RpcSendTransactionConfig {
                        skip_preflight: true,
                        preflight_commitment: None,
                        encoding: None,
                        max_retries: Some(3),
                        min_context_slot: None,
                    };
                    match state.rpc.send_transaction_with_config(&tx, config) {
                        Ok(s) => {
                            if attempt > 1 {
                                info!("Final sweep TX succeeded on attempt {}/5", attempt);
                            }
                            result_sig = Some(s);
                            break;
                        }
                        Err(e) => {
                            let err_str = e.to_string();
                            if err_str.contains("connection") || err_str.contains("timeout") || err_str.contains("closed") {
                                warn!("Final sweep attempt {}/5: {}", attempt, err_str);
                                last_err = err_str;
                                tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
                                continue;
                            }
                            return Err(MazeError::TransactionError(format!("TX failed: {}", e)));
                        }
                    }
                }
                result_sig.ok_or_else(|| MazeError::TransactionError(format!("TX failed after 5 attempts: {}", last_err)))?
            };
            info!("Final sweep transfer: {} lamports to {} ({})", transfer_amount, final_destination, sig);
            
            // Wait for confirmation
            for _ in 0..30 {
                tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
                if let Ok(Some(result)) = state.rpc.get_signature_status(&sig) {
                    if result.is_ok() {
                        break;
                    }
                }
            }
        }
        
        state.db.update_sweep_node_status(sweep_id, node.index, "completed", None)?;
        return Ok(());
    }
    
    // Wait for incoming funds from previous level
    let mut attempts = 0;
    let balance = loop {
        let bal = match get_balance_with_retry(&state.rpc, &keypair.pubkey(), 5).await {
            Ok(b) => b,
            Err(_) => continue,
        };
        if bal > TX_FEE_LAMPORTS {
            info!("Sweep node {} has balance: {} lamports", node.index, bal);
            break bal;
        }
        attempts += 1;
        if attempts > 120 {
            return Err(MazeError::TransactionError(
                format!("Timeout waiting for funds at sweep node {}", node.index)
            ));
        }
        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
    };

    let num_outputs = outputs.len();
    let total_fees = TX_FEE_LAMPORTS * num_outputs as u64;
    let distributable = balance.saturating_sub(total_fees);
    
    if distributable == 0 {
        return Err(MazeError::InsufficientFunds {
            required: total_fees + 1,
            available: balance,
        });
    }
    
    let base_amount = distributable / num_outputs as u64;
    let remainder = distributable % num_outputs as u64;
    
    let mut amounts: Vec<u64> = Vec::with_capacity(num_outputs);
    for i in 0..num_outputs {
        if i == num_outputs - 1 {
            amounts.push(base_amount + remainder);
        } else {
            amounts.push(base_amount);
        }
    }

    // Verify math: total_amounts + total_fees == initial_balance
    let total_to_send: u64 = amounts.iter().sum();
    if total_to_send + total_fees != balance {
        error!("Sweep amount calculation mismatch: {} + {} != {}", total_to_send, total_fees, balance);
        return Err(MazeError::InsufficientFunds {
            required: total_to_send + total_fees,
            available: balance,
        });
    }
    
    let mut last_sig = String::new();
    for (i, &output_idx) in outputs.iter().enumerate() {
        if let Some(output_node) = maze.nodes.get(output_idx as usize) {
            let output_pubkey = Pubkey::from_str(&output_node.address)
                .map_err(|e| MazeError::InvalidParameters(e.to_string()))?;
            
            let transfer_amount = amounts[i];
            if transfer_amount == 0 {
                continue;
            }
            
            let sig = {
                let mut last_err = String::new();
                let mut result_sig = None;
                for attempt in 1..=5u8 {
                    let blockhash = match state.rpc.get_latest_blockhash() {
                        Ok(bh) => bh,
                        Err(e) => {
                            warn!("Sweep node {} attempt {}/5: Failed to get blockhash: {}", node.index, attempt, e);
                            last_err = e.to_string();
                            tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
                            continue;
                        }
                    };
                    let ix = system_instruction::transfer(&keypair.pubkey(), &output_pubkey, transfer_amount);
                    let tx = Transaction::new_signed_with_payer(
                        &[ix],
                        Some(&keypair.pubkey()),
                        &[&keypair],
                        blockhash,
                    );
                    let config = RpcSendTransactionConfig {
                        skip_preflight: true,
                        preflight_commitment: None,
                        encoding: None,
                        max_retries: Some(3),
                        min_context_slot: None,
                    };
                    match state.rpc.send_transaction_with_config(&tx, config) {
                        Ok(s) => {
                            if attempt > 1 {
                                info!("Sweep node {} TX succeeded on attempt {}/5", node.index, attempt);
                            }
                            result_sig = Some(s);
                            break;
                        }
                        Err(e) => {
                            let err_str = e.to_string();
                            if err_str.contains("connection") || err_str.contains("timeout") || err_str.contains("closed") {
                                warn!("Sweep node {} attempt {}/5: {}", node.index, attempt, err_str);
                                last_err = err_str;
                                tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
                                continue;
                            }
                            return Err(MazeError::TransactionError(format!("TX failed: {}", e)));
                        }
                    }
                }
                result_sig.ok_or_else(|| MazeError::TransactionError(format!("TX failed after 5 attempts: {}", last_err)))?
            };
            
            // Wait for confirmation
            let mut confirmed = false;
            for _ in 0..30 {
                tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
                if let Ok(Some(result)) = state.rpc.get_signature_status(&sig) {
                    if result.is_ok() {
                        confirmed = true;
                        break;
                    } else if let Err(e) = result {
                        return Err(MazeError::TransactionError(format!("TX failed: {:?}", e)));
                    }
                }
            }
            
            if !confirmed {
                return Err(MazeError::TransactionError("Sweep TX confirmation timeout".into()));
            }
            
            last_sig = sig.to_string();
            info!("Sweep node {} transfer {}/{}: {} lamports ({})", 
                  node.index, i + 1, num_outputs, transfer_amount, last_sig);
        }
    }
    
    state.db.update_sweep_node_status(sweep_id, node.index, "completed", Some(&last_sig))?;
    Ok(())
}


/// Resume a failed sweep from where it left off
async fn resume_sweep(
    State(state): State<Arc<AppState>>,
    Path(sweep_id): Path<String>,
) -> std::result::Result<Json<SweepResponse>, AppError> {
    info!("Resuming sweep {}", sweep_id);
    
    // Get sweep request
    let sweep_req = state.db.get_sweep_request(&sweep_id)?
        .ok_or(MazeError::RequestNotFound(sweep_id.clone()))?;
    
    let pocket_id = sweep_req.1.clone();
    let destination = sweep_req.2.clone();
    let status = sweep_req.5.clone();
    
    // Only resume failed sweeps
    if status != "failed" && status != "processing" {
        return Ok(Json(SweepResponse {
            sweep_id: None,
            success: false,
            message: format!("Sweep status is '{}', can only resume failed/processing sweeps", status),
            amount_swept: None,
            destination: None,
            tx_signature: None,
        }));
    }
    
    // Update status to processing
    state.db.update_sweep_status(&sweep_id, "processing", None, None)?;
    
    // Get maze graph
    let maze_json = state.db.get_sweep_maze_graph(&sweep_id)?;
    let maze: MazeGraph = serde_json::from_str(&maze_json)
        .map_err(|e| MazeError::DatabaseError(e.to_string()))?;
    
    // Find first node with balance > 0
    let mut start_node_idx: Option<usize> = None;
    let mut start_balance: u64 = 0;
    
    for (idx, node) in maze.nodes.iter().enumerate() {
        let pubkey = Pubkey::from_str(&node.address)
            .map_err(|e| MazeError::ParseError(e.to_string()))?;
        let balance = state.rpc.get_balance(&pubkey).map_err(|e| MazeError::RpcError(e.to_string()))?;
        if balance > TX_FEE_LAMPORTS {
            start_node_idx = Some(idx);
            start_balance = balance;
            info!("Found funds at node {}: {} lamports", idx, balance);
            break;
        }
    }
    
    let start_idx = match start_node_idx {
        Some(idx) => idx,
        None => {
            state.db.update_sweep_status(&sweep_id, "failed", None, Some("No funds found in any node"))?;
            return Ok(Json(SweepResponse {
                sweep_id: None,
                success: false,
                message: "No funds found in any maze node".to_string(),
                amount_swept: None,
                destination: None,
                tx_signature: None,
            }));
        }
    };
    
    // Execute sweep from the node with funds directly to destination
    let node = &maze.nodes[start_idx];
    let keypair_bytes = state.db.decrypt(&node.keypair_encrypted)?;
    let keypair = Keypair::from_bytes(&keypair_bytes)
        .map_err(|e| MazeError::CryptoError(e.to_string()))?;
    
    let dest_pubkey = Pubkey::from_str(&destination)
        .map_err(|e| MazeError::ParseError(e.to_string()))?;
    
    let transfer_amount = start_balance.saturating_sub(TX_FEE_LAMPORTS);
    
    let sig = {
        let mut last_err = String::new();
        let mut result_sig = None;
        for attempt in 1..=5u8 {
            let blockhash = match state.rpc.get_latest_blockhash() {
                Ok(bh) => bh,
                Err(e) => {
                    warn!("Recovery attempt {}/5: Failed to get blockhash: {}", attempt, e);
                    last_err = e.to_string();
                    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
                    continue;
                }
            };
            let ix = system_instruction::transfer(&keypair.pubkey(), &dest_pubkey, transfer_amount);
            let tx = Transaction::new_signed_with_payer(
                &[ix],
                Some(&keypair.pubkey()),
                &[&keypair],
                blockhash,
            );
            let config = RpcSendTransactionConfig {
                skip_preflight: true,
                preflight_commitment: None,
                encoding: None,
                max_retries: Some(3),
                min_context_slot: None,
            };
            match state.rpc.send_transaction_with_config(&tx, config) {
                Ok(s) => {
                    if attempt > 1 {
                        info!("Recovery TX succeeded on attempt {}/5", attempt);
                    }
                    result_sig = Some(s);
                    break;
                }
                Err(e) => {
                    let err_str = e.to_string();
                    if err_str.contains("connection") || err_str.contains("timeout") || err_str.contains("closed") {
                        warn!("Recovery attempt {}/5: {}", attempt, err_str);
                        last_err = err_str;
                        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
                        continue;
                    }
                    return Err(AppError(MazeError::TransactionError(format!("TX failed: {}", e))));
                }
            }
        }
        match result_sig {
            Some(s) => s,
            None => {
                return Err(AppError(MazeError::TransactionError(format!("TX failed after 5 attempts: {}", last_err))));
            }
        }
    };
    
    // Wait for confirmation
    let mut confirmed = false;
    for _ in 0..30 {
        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
        if let Ok(Some(result)) = state.rpc.get_signature_status(&sig) {
            if result.is_ok() {
                confirmed = true;
                break;
            } else if let Err(e) = result {
                state.db.update_sweep_status(&sweep_id, "failed", None, Some(&format!("TX failed: {:?}", e)))?;
                return Ok(Json(SweepResponse {
                    sweep_id: None,
                    success: false,
                    message: format!("Recovery transfer failed: {:?}", e),
                    amount_swept: None,
                    destination: None,
                    tx_signature: None,
                }));
            }
        }
    }
    
    if !confirmed {
        state.db.update_sweep_status(&sweep_id, "failed", None, Some("Recovery TX timeout"))?;
        return Ok(Json(SweepResponse {
            sweep_id: None,
            success: false,
            message: "Recovery transfer confirmation timeout".to_string(),
            amount_swept: None,
            destination: None,
            tx_signature: None,
        }));
    }
    
    // Mark sweep as completed
    state.db.update_sweep_status(&sweep_id, "completed", Some(&sig.to_string()), None)?;
    state.db.mark_pocket_swept(&pocket_id)?;
    
    info!("Sweep {} recovered: {} lamports from node {} to {}", sweep_id, transfer_amount, start_idx, destination);
    
    Ok(Json(SweepResponse {
        sweep_id: Some(sweep_id.clone()),
        success: true,
        message: format!("Sweep recovered from node {}", start_idx),
        amount_swept: Some(transfer_amount),
        destination: Some(destination),
        tx_signature: Some(sig.to_string()),
    }))
}

fn calculate_delay(params: &MazeParameters, level: u8) -> u64 {
    match params.delay_pattern {
        DelayPattern::None => 0,
        DelayPattern::Linear => params.delay_ms * level as u64,
        DelayPattern::Exponential => params.delay_ms * (2u64.pow(level as u32)),
        DelayPattern::Fibonacci => {
            use sdp_mazepocket::core::fibonacci;
            params.delay_ms * fibonacci(level)
        }
        DelayPattern::Random => {
            let variation = (rand::random::<u64>() % (params.delay_ms + 1)) as i64;
            (params.delay_ms as i64 + variation - (params.delay_ms as i64 / 2)).max(0) as u64
        }
    }
}

// ============ RECOVERY HANDLERS ============

#[derive(Debug, Deserialize)]
struct RecoverRequest {
    meta_address: String,
}

#[derive(Debug, Serialize)]
struct RecoverResponse {
    success: bool,
    message: String,
    recovered_lamports: Option<u64>,
    recovered_sol: Option<f64>,
    tx_signatures: Vec<String>,
}

/// Recover stuck funding - transfers funds from stuck maze nodes to pocket
async fn recover_funding(
    State(state): State<Arc<AppState>>,
    Path(pocket_id): Path<String>,
    Json(req): Json<RecoverRequest>,
) -> std::result::Result<Json<RecoverResponse>, AppError> {
    let owner_meta_hash = hash_meta_address(&req.meta_address);
    
    // Verify ownership
    let pocket = state.db.get_pocket_for_owner(&pocket_id, &owner_meta_hash)?
        .ok_or(MazeError::PocketNotFound(pocket_id.clone()))?;
    
    let dest_pubkey = Pubkey::from_str(&pocket.stealth_pubkey)
        .map_err(|e| MazeError::InvalidParameters(e.to_string()))?;
    
    // Get funding request
    let fund_id = format!("fund_{}", &pocket_id[7..]);
    let funding_req = state.db.get_funding_request(&fund_id)?
        .ok_or(MazeError::RequestNotFound(fund_id.clone()))?;
    
    if funding_req.status == "completed" {
        return Ok(Json(RecoverResponse {
            success: false,
            message: "Funding already completed".to_string(),
            recovered_lamports: None,
            recovered_sol: None,
            tx_signatures: vec![],
        }));
    }
    
    // Get maze graph
    let maze_json = state.db.get_maze_graph(&fund_id)?;
    let maze: MazeGraph = serde_json::from_str(&maze_json)
        .map_err(|e| MazeError::DatabaseError(e.to_string()))?;
    
    info!("Recovering funding {} with {} nodes", fund_id, maze.nodes.len());
    
    let mut total_recovered: u64 = 0;
    let mut tx_sigs: Vec<String> = vec![];
    
    // Find and recover funds from all nodes with balance
    for node in &maze.nodes {
        let node_pubkey = Pubkey::from_str(&node.address)
            .map_err(|e| MazeError::InvalidParameters(e.to_string()))?;
        
        let balance = state.rpc.get_balance(&node_pubkey).unwrap_or(0);
        
        if balance > TX_FEE_LAMPORTS {
            // Decrypt keypair
            let keypair_bytes = state.db.decrypt(&node.keypair_encrypted)?;
            let keypair = Keypair::from_bytes(&keypair_bytes)
                .map_err(|e| MazeError::KeypairError(e.to_string()))?;
            
            let transfer_amount = balance.saturating_sub(TX_FEE_LAMPORTS);
            
            if transfer_amount > 0 {
                let mut tx_success = false;
                let mut last_sig = None;
                for attempt in 1..=5u8 {
                    let blockhash = match state.rpc.get_latest_blockhash() {
                        Ok(bh) => bh,
                        Err(e) => {
                            warn!("Recover node {} attempt {}/5: Failed to get blockhash: {}", node.index, attempt, e);
                            tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
                            continue;
                        }
                    };
                    let ix = system_instruction::transfer(&keypair.pubkey(), &dest_pubkey, transfer_amount);
                    let tx = Transaction::new_signed_with_payer(
                        &[ix],
                        Some(&keypair.pubkey()),
                        &[&keypair],
                        blockhash,
                    );
                    let config = RpcSendTransactionConfig {
                        skip_preflight: true,
                        preflight_commitment: None,
                        encoding: None,
                        max_retries: Some(3),
                        min_context_slot: None,
                    };
                    match state.rpc.send_transaction_with_config(&tx, config) {
                        Ok(sig) => {
                            if attempt > 1 {
                                info!("Recover node {} TX succeeded on attempt {}/5", node.index, attempt);
                            }
                            last_sig = Some(sig);
                            tx_success = true;
                            break;
                        }
                        Err(e) => {
                            let err_str = e.to_string();
                            if err_str.contains("connection") || err_str.contains("timeout") || err_str.contains("closed") {
                                warn!("Recover node {} attempt {}/5: {}", node.index, attempt, err_str);
                                tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
                                continue;
                            }
                            warn!("Failed to recover from node {}: {}", node.index, e);
                            break;
                        }
                    }
                }
                if tx_success {
                    if let Some(sig) = last_sig {
                        info!("Recovered {} lamports from node {} ({})", transfer_amount, node.index, sig);
                        total_recovered += transfer_amount;
                        tx_sigs.push(sig.to_string());
                        let _ = state.db.update_node_status(&fund_id, node.index, "completed", Some(&sig.to_string()));
                    }
                }
            }
        }
    }
    
    // Update funding status if recovered
    if total_recovered > 0 {
        let _ = state.db.update_funding_status(&fund_id, "completed", None);
        info!("Funding {} recovered: {} lamports", fund_id, total_recovered);
    }
    
    Ok(Json(RecoverResponse {
        success: total_recovered > 0,
        message: if total_recovered > 0 {
            format!("Recovered {} lamports from {} transactions", total_recovered, tx_sigs.len())
        } else {
            "No funds to recover".to_string()
        },
        recovered_lamports: Some(total_recovered),
        recovered_sol: Some(total_recovered as f64 / 1_000_000_000.0),
        tx_signatures: tx_sigs,
    }))
}

/// Recover stuck sweep - transfers funds from stuck sweep nodes to destination
async fn recover_sweep(
    State(state): State<Arc<AppState>>,
    Path(sweep_id): Path<String>,
    Json(req): Json<RecoverRequest>,
) -> std::result::Result<Json<RecoverResponse>, AppError> {
    let owner_meta_hash = hash_meta_address(&req.meta_address);
    
    // Get sweep request
    let sweep_req = state.db.get_sweep_request(&sweep_id)?
        .ok_or(MazeError::RequestNotFound(sweep_id.clone()))?;
    
    let pocket_id = sweep_req.1.clone();
    let destination = sweep_req.2.clone();
    let status = sweep_req.5.clone();
    
    // Verify ownership
    let _pocket = state.db.get_pocket_for_owner(&pocket_id, &owner_meta_hash)?
        .ok_or(MazeError::PocketNotFound(pocket_id.clone()))?;
    
    if status == "completed" {
        return Ok(Json(RecoverResponse {
            success: false,
            message: "Sweep already completed".to_string(),
            recovered_lamports: None,
            recovered_sol: None,
            tx_signatures: vec![],
        }));
    }
    
    let dest_pubkey = Pubkey::from_str(&destination)
        .map_err(|e| MazeError::InvalidParameters(e.to_string()))?;
    
    // Get sweep maze graph
    let maze_json = state.db.get_sweep_maze_graph(&sweep_id)?;
    let maze: MazeGraph = serde_json::from_str(&maze_json)
        .map_err(|e| MazeError::DatabaseError(e.to_string()))?;
    
    info!("Recovering sweep {} with {} nodes", sweep_id, maze.nodes.len());
    
    let mut total_recovered: u64 = 0;
    let mut tx_sigs: Vec<String> = vec![];
    
    // Find and recover funds from all nodes with balance
    for node in &maze.nodes {
        let node_pubkey = Pubkey::from_str(&node.address)
            .map_err(|e| MazeError::InvalidParameters(e.to_string()))?;
        
        let balance = state.rpc.get_balance(&node_pubkey).unwrap_or(0);
        
        if balance > TX_FEE_LAMPORTS {
            // Decrypt keypair
            let keypair_bytes = state.db.decrypt(&node.keypair_encrypted)?;
            let keypair = Keypair::from_bytes(&keypair_bytes)
                .map_err(|e| MazeError::KeypairError(e.to_string()))?;
            
            let transfer_amount = balance.saturating_sub(TX_FEE_LAMPORTS);
            
            if transfer_amount > 0 {
                let mut tx_success = false;
                let mut last_sig = None;
                for attempt in 1..=5u8 {
                    let blockhash = match state.rpc.get_latest_blockhash() {
                        Ok(bh) => bh,
                        Err(e) => {
                            warn!("Recover sweep node {} attempt {}/5: Failed to get blockhash: {}", node.index, attempt, e);
                            tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
                            continue;
                        }
                    };
                    let ix = system_instruction::transfer(&keypair.pubkey(), &dest_pubkey, transfer_amount);
                    let tx = Transaction::new_signed_with_payer(
                        &[ix],
                        Some(&keypair.pubkey()),
                        &[&keypair],
                        blockhash,
                    );
                    let config = RpcSendTransactionConfig {
                        skip_preflight: true,
                        preflight_commitment: None,
                        encoding: None,
                        max_retries: Some(3),
                        min_context_slot: None,
                    };
                    match state.rpc.send_transaction_with_config(&tx, config) {
                        Ok(sig) => {
                            if attempt > 1 {
                                info!("Recover sweep node {} TX succeeded on attempt {}/5", node.index, attempt);
                            }
                            last_sig = Some(sig);
                            tx_success = true;
                            break;
                        }
                        Err(e) => {
                            let err_str = e.to_string();
                            if err_str.contains("connection") || err_str.contains("timeout") || err_str.contains("closed") {
                                warn!("Recover sweep node {} attempt {}/5: {}", node.index, attempt, err_str);
                                tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
                                continue;
                            }
                            warn!("Failed to recover from sweep node {}: {}", node.index, e);
                            break;
                        }
                    }
                }
                if tx_success {
                    if let Some(sig) = last_sig {
                        info!("Recovered {} lamports from sweep node {} ({})", transfer_amount, node.index, sig);
                        total_recovered += transfer_amount;
                        tx_sigs.push(sig.to_string());
                        let _ = state.db.update_sweep_node_status(&sweep_id, node.index, "completed", Some(&sig.to_string()));
                    }
                }
            }
        }
    }
    
    // Update sweep status if recovered
    if total_recovered > 0 {
        let _ = state.db.update_sweep_status(&sweep_id, "completed", None, None);
        let _ = state.db.mark_pocket_swept(&pocket_id);
        info!("Sweep {} recovered: {} lamports", sweep_id, total_recovered);
    }
    
    Ok(Json(RecoverResponse {
        success: total_recovered > 0,
        message: if total_recovered > 0 {
            format!("Recovered {} lamports from {} transactions", total_recovered, tx_sigs.len())
        } else {
            "No funds to recover".to_string()
        },
        recovered_lamports: Some(total_recovered),
        recovered_sol: Some(total_recovered as f64 / 1_000_000_000.0),
        tx_signatures: tx_sigs,
    }))
}

// ============ DEPOSIT MONITOR ============

async fn deposit_monitor(state: Arc<AppState>) {
    info!("Starting deposit monitor task");
    
    loop {
        tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;

        // Get pending funding requests
        let pending = match state.db.get_pending_funding_requests() {
            Ok(p) => p,
            Err(e) => {
                error!("Failed to get pending requests: {}", e);
                continue;
            }
        };

        for (request_id, deposit_address, expected_amount) in pending {
            // Check balance
            let pubkey = match Pubkey::from_str(&deposit_address) {
                Ok(p) => p,
                Err(_) => continue,
            };

            let balance = match state.rpc.get_balance(&pubkey) {
                Ok(b) => b,
                Err(_) => continue,
            };

            // Check if deposit received (with some buffer for fees)
            if balance >= (expected_amount as u64).saturating_sub(TX_FEE_LAMPORTS * 10) {
                info!("Deposit received for {}: {} lamports", request_id, balance);

                // Update status
                if let Err(e) = state.db.update_funding_status(&request_id, "deposit_received", None) {
                    error!("Failed to update status: {}", e);
                    continue;
                }

                // Execute maze
                let state_clone = state.clone();
                let req_id = request_id.clone();
                tokio::spawn(async move {
                    match execute_maze(state_clone.clone(), &req_id).await {
                        Ok(_) => {
                            info!("Maze execution completed for {}", req_id);
                        }
                        Err(e) => {
                            error!("Maze execution failed for {}: {}", req_id, sanitize_error(&e.to_string()));
                            let _ = state_clone.db.update_funding_status(&req_id, "failed", Some(&sanitize_error(&e.to_string())));
                        }
                    }
                });
            }
        }
    }
}


// ============ SWEEP ALL POCKETS HANDLER (Phase 3) ============

/// Sweep all pockets to a single destination
async fn sweep_all_pockets(
    State(state): State<Arc<AppState>>,
    Json(req): Json<SweepAllPocketsRequest>,
) -> std::result::Result<Json<SweepAllPocketsResponse>, AppError> {
    // Determine destination - prefer slot, then direct address
    let destination = if let Some(slot) = req.destination_slot {
        if slot < 1 || slot > 5 {
            return Ok(Json(SweepAllPocketsResponse {
                success: false,
                total_pockets: 0,
                successful_sweeps: 0,
                failed_sweeps: 0,
                total_amount_swept: 0,
                destination: "".to_string(),
                results: vec![SweepAllPocketResult {
                    pocket_id: "".to_string(),
                    success: false,
                    sweep_id: None,
                    amount_swept: None,
                    error: Some("Invalid slot. Must be 1-5".to_string()),
                }],
            }));
        }
        let owner_hash_temp = hash_meta_address(&req.meta_address);
        match state.db.get_destination_wallet(&owner_hash_temp, slot)? {
            Some(addr) => addr,
            None => return Ok(Json(SweepAllPocketsResponse {
                success: false,
                total_pockets: 0,
                successful_sweeps: 0,
                failed_sweeps: 0,
                total_amount_swept: 0,
                destination: "".to_string(),
                results: vec![SweepAllPocketResult {
                    pocket_id: "".to_string(),
                    success: false,
                    sweep_id: None,
                    amount_swept: None,
                    error: Some(format!("No wallet saved in slot {}", slot)),
                }],
            })),
        }
    } else if let Some(ref addr) = req.destination {
        addr.clone()
    } else {
        return Ok(Json(SweepAllPocketsResponse {
            success: false,
            total_pockets: 0,
            successful_sweeps: 0,
            failed_sweeps: 0,
            total_amount_swept: 0,
            destination: "".to_string(),
            results: vec![SweepAllPocketResult {
                pocket_id: "".to_string(),
                success: false,
                sweep_id: None,
                amount_swept: None,
                error: Some("Must specify destination_slot (1-5) or destination address".to_string()),
            }],
        }));
    };

    info!("Sweep all pockets request to {}", &destination[..20.min(destination.len())]);

    // Validate destination is valid Solana address
    Pubkey::from_str(&destination)
        .map_err(|_| MazeError::InvalidParameters("Invalid destination address".into()))?;


    let owner_meta_hash = hash_meta_address(&req.meta_address);

    // Get all active pockets for this user
    let pockets = state.db.list_pockets(&owner_meta_hash)?;

    if pockets.is_empty() {
        return Ok(Json(SweepAllPocketsResponse {
            success: true,
            total_pockets: 0,
            successful_sweeps: 0,
            failed_sweeps: 0,
            total_amount_swept: 0,
            destination: destination.clone(),
            results: vec![],
        }));
    }

    let maze_params = parse_maze_config(req.maze_config);
    let mut results: Vec<SweepAllPocketResult> = Vec::new();
    let mut successful_sweeps = 0usize;
    let mut failed_sweeps = 0usize;
    let mut total_amount_swept = 0u64;

    for pocket in &pockets {
        // Skip non-active pockets
        if pocket.status != PocketStatus::Active {
            results.push(SweepAllPocketResult {
                pocket_id: pocket.id.clone(),
                success: false,
                sweep_id: None,
                amount_swept: None,
                error: Some(format!("Pocket status is {}", pocket.status.as_str())),
            });
            failed_sweeps += 1;
            continue;
        }

        // Get pocket keypair
        let keypair_bytes = match state.db.decrypt(&pocket.keypair_encrypted) {
            Ok(bytes) => bytes,
            Err(e) => {
                results.push(SweepAllPocketResult {
                    pocket_id: pocket.id.clone(),
                    success: false,
                    sweep_id: None,
                    amount_swept: None,
                    error: Some(format!("Decrypt error: {}", e)),
                });
                failed_sweeps += 1;
                continue;
            }
        };

        let pocket_keypair = match Keypair::from_bytes(&keypair_bytes) {
            Ok(kp) => kp,
            Err(e) => {
                results.push(SweepAllPocketResult {
                    pocket_id: pocket.id.clone(),
                    success: false,
                    sweep_id: None,
                    amount_swept: None,
                    error: Some(format!("Keypair error: {}", e)),
                });
                failed_sweeps += 1;
                continue;
            }
        };

        // Check balance
        let balance = match state.rpc.get_balance(&pocket_keypair.pubkey()) {
            Ok(b) => b,
            Err(e) => {
                results.push(SweepAllPocketResult {
                    pocket_id: pocket.id.clone(),
                    success: false,
                    sweep_id: None,
                    amount_swept: None,
                    error: Some(format!("RPC error: {}", e)),
                });
                failed_sweeps += 1;
                continue;
            }
        };

        // Skip if insufficient balance
        if balance <= TX_FEE_LAMPORTS * 20 {
            results.push(SweepAllPocketResult {
                pocket_id: pocket.id.clone(),
                success: false,
                sweep_id: None,
                amount_swept: None,
                error: Some("Insufficient balance for sweep".to_string()),
            });
            failed_sweeps += 1;
            continue;
        }

        // Mark as sweeping
        if let Err(e) = state.db.update_pocket_status(&pocket.id, PocketStatus::Sweeping) {
            results.push(SweepAllPocketResult {
                pocket_id: pocket.id.clone(),
                success: false,
                sweep_id: None,
                amount_swept: None,
                error: Some(format!("Status update error: {}", e)),
            });
            failed_sweeps += 1;
            continue;
        }

        // Generate sweep maze
        let generator = MazeGenerator::new(maze_params.clone());
        let sweep_amount = balance.saturating_sub(TX_FEE_LAMPORTS);
        let encrypt_fn = |data: &[u8]| state.db.encrypt(data);

        let maze = match generator.generate(sweep_amount, encrypt_fn) {
            Ok(m) => m,
            Err(e) => {
                let _ = state.db.update_pocket_status(&pocket.id, PocketStatus::Active);
                results.push(SweepAllPocketResult {
                    pocket_id: pocket.id.clone(),
                    success: false,
                    sweep_id: None,
                    amount_swept: None,
                    error: Some(format!("Maze generation error: {}", e)),
                });
                failed_sweeps += 1;
                continue;
            }
        };

        let sweep_id = format!("sweep_{}", &pocket.id[7..]);
        let maze_json = serde_json::to_string(&maze).unwrap_or_default();

        // Save sweep request
        if let Err(e) = state.db.create_sweep_request(&sweep_id, &pocket.id, &destination, sweep_amount, &maze_json) {
            let _ = state.db.update_pocket_status(&pocket.id, PocketStatus::Active);
            results.push(SweepAllPocketResult {
                pocket_id: pocket.id.clone(),
                success: false,
                sweep_id: None,
                amount_swept: None,
                error: Some(format!("DB error: {}", e)),
            });
            failed_sweeps += 1;
            continue;
        }

        // Store maze nodes
        let mut store_failed = false;
        for node in &maze.nodes {
            if let Err(e) = state.db.store_sweep_node(&sweep_id, node) {
                let _ = state.db.update_pocket_status(&pocket.id, PocketStatus::Active);
                results.push(SweepAllPocketResult {
                    pocket_id: pocket.id.clone(),
                    success: false,
                    sweep_id: None,
                    amount_swept: None,
                    error: Some(format!("Failed to store maze node: {}", e)),
                });
                failed_sweeps += 1;
                store_failed = true;
                break;
            }
        }
        if store_failed {
            continue;
        }
        // Transfer from pocket to first maze node
        let first_node = &maze.nodes[0];
        let first_node_pubkey = match Pubkey::from_str(&first_node.address) {
            Ok(p) => p,
            Err(e) => {
                let _ = state.db.update_pocket_status(&pocket.id, PocketStatus::Active);
                results.push(SweepAllPocketResult {
                    pocket_id: pocket.id.clone(),
                    success: false,
                    sweep_id: Some(sweep_id),
                    amount_swept: None,
                    error: Some(format!("Invalid node address: {}", e)),
                });
                failed_sweeps += 1;
                continue;
            }
        };

        // Send initial transaction with retry
        let (sig, last_err) = {
            let mut last_err = String::new();
            let mut result_sig = None;
            for attempt in 1..=5u8 {
                let blockhash = match state.rpc.get_latest_blockhash() {
                    Ok(bh) => bh,
                    Err(e) => {
                        warn!("Sweep all attempt {}/5 for {}: Failed to get blockhash: {}", attempt, pocket.id, e);
                        last_err = e.to_string();
                        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
                        continue;
                    }
                };
                let ix = system_instruction::transfer(
                    &pocket_keypair.pubkey(),
                    &first_node_pubkey,
                    sweep_amount,
                );
                let tx = Transaction::new_signed_with_payer(
                    &[ix],
                    Some(&pocket_keypair.pubkey()),
                    &[&pocket_keypair],
                    blockhash,
                );
                let config = RpcSendTransactionConfig {
                    skip_preflight: true,
                    preflight_commitment: None,
                    encoding: None,
                    max_retries: Some(3),
                    min_context_slot: None,
                };
                match state.rpc.send_transaction_with_config(&tx, config) {
                    Ok(s) => {
                        if attempt > 1 {
                            info!("Sweep all TX succeeded on attempt {}/5 for {}", attempt, pocket.id);
                        }
                        result_sig = Some(s);
                        break;
                    }
                    Err(e) => {
                        let err_str = e.to_string();
                        if err_str.contains("connection") || err_str.contains("timeout") || err_str.contains("closed") {
                            warn!("Sweep all attempt {}/5 for {}: {}", attempt, pocket.id, err_str);
                            last_err = err_str;
                            tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
                            continue;
                        }
                        last_err = err_str;
                        break;
                    }
                }
            }
            (result_sig, last_err)
        };

        let sig = match sig {
            Some(s) => s,
            None => {
                let _ = state.db.update_pocket_status(&pocket.id, PocketStatus::Active);
                results.push(SweepAllPocketResult {
                    pocket_id: pocket.id.clone(),
                    success: false,
                    sweep_id: Some(sweep_id),
                    amount_swept: None,
                    error: Some(format!("TX failed: {}", last_err)),
                });
                failed_sweeps += 1;
                continue;
            }
        };

        // Wait for confirmation
        let mut confirmed = false;
        for _ in 0..30 {
            tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
            if let Ok(Some(result)) = state.rpc.get_signature_status(&sig) {
                if result.is_ok() {
                    confirmed = true;
                    break;
                } else if let Err(e) = result {
                    let _ = state.db.update_pocket_status(&pocket.id, PocketStatus::Active);
                    results.push(SweepAllPocketResult {
                        pocket_id: pocket.id.clone(),
                        success: false,
                        sweep_id: Some(sweep_id.clone()),
                        amount_swept: None,
                        error: Some(format!("TX failed: {:?}", e)),
                    });
                    failed_sweeps += 1;
                    continue;
                }
            }
        }

        if !confirmed {
            let _ = state.db.update_pocket_status(&pocket.id, PocketStatus::Active);
            results.push(SweepAllPocketResult {
                pocket_id: pocket.id.clone(),
                success: false,
                sweep_id: Some(sweep_id),
                amount_swept: None,
                error: Some("TX confirmation timeout".to_string()),
            });
            failed_sweeps += 1;
            continue;
        }

        // Spawn background task for maze execution
        let state_clone = state.clone();
        let sweep_id_clone = sweep_id.clone();
        let pocket_id_clone = pocket.id.clone();
        tokio::spawn(async move {
            match execute_sweep_maze(state_clone.clone(), &sweep_id_clone).await {
                Ok(_) => {
                    let _ = state_clone.db.mark_pocket_swept(&pocket_id_clone);
                    info!("Sweep all: maze completed for {}", pocket_id_clone);
                }
                Err(e) => {
                    error!("Sweep all: maze failed for {}: {}", pocket_id_clone, sanitize_error(&e.to_string()));
                    let _ = state_clone.db.update_pocket_status(&pocket_id_clone, PocketStatus::Active);
                    let _ = state_clone.db.update_sweep_status(&sweep_id_clone, "failed", None, Some(&sanitize_error(&e.to_string())));
                }
            }
        });

        results.push(SweepAllPocketResult {
            pocket_id: pocket.id.clone(),
            success: true,
            sweep_id: Some(sweep_id),
            amount_swept: Some(sweep_amount),
            error: None,
        });
        successful_sweeps += 1;
        total_amount_swept += sweep_amount;

        info!("Sweep all: initiated for pocket {} ({} lamports)", pocket.id, sweep_amount);
    }

    Ok(Json(SweepAllPocketsResponse {
        success: successful_sweeps > 0 || pockets.is_empty(),
        total_pockets: pockets.len(),
        successful_sweeps,
        failed_sweeps,
        total_amount_swept,
        destination: destination,
        results,
    }))
}
// ============ MAIN ============

#[tokio::main]
async fn main() {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::Level::INFO.into())
        )
        .init();

    // Load environment
    dotenv::dotenv().ok();
    
    info!("Starting SDP Maze Pocket Relay Server");

    // Initialize config
    let config = Config::from_env();

    // Initialize database
    let db = PocketDatabase::new(Some(&config.database_path), &config.master_key)
        .expect("Failed to initialize database");
    info!("Database initialized");

    // Initialize RPC client
    let rpc = RpcClient::new_with_commitment(
        config.rpc_url.clone(),
        CommitmentConfig::confirmed(),
    );
    // Log RPC URL without exposing API key
    let rpc_display = config.rpc_url.split('?').next().unwrap_or("unknown");
    info!("RPC client connected to {}", rpc_display);

    // Create app state
    let state = Arc::new(AppState { db, rpc, config: config.clone() });

    // Start deposit monitor
    let monitor_state = state.clone();
    tokio::spawn(async move {
        deposit_monitor(monitor_state).await;
    });
    info!("Deposit monitor started");

    // Build router
    let app = Router::new()
        .route("/health", get(health_check))
        .route("/stats", get(stats_handler))
        .route("/pocket", post(create_pocket))
        .route("/route", post(create_route))
        .route("/pockets", get(list_pockets))
        .route("/pockets/sweep-all", post(sweep_all_pockets))
        .route("/pocket/:pocket_id", get(get_pocket))
        .route("/pocket/:pocket_id/sweep", post(sweep_pocket))
        .route("/pocket/:pocket_id/rename", post(rename_pocket_handler))
        .route("/pocket/:pocket_id/archive", post(archive_pocket_handler))
        .route("/pocket/:pocket_id", axum::routing::delete(delete_pocket_handler))
        .route("/status/:request_id", get(get_funding_status))
        .route("/wallets", get(list_wallets))
        .route("/sweep/:sweep_id/status", get(get_sweep_status))
        .route("/sweep/:sweep_id/resume", post(resume_sweep))
        .route("/pocket/:pocket_id/recover", post(recover_funding))
        .route("/sweep/:sweep_id/recover", post(recover_sweep))
        .route("/wallet", post(add_wallet))
        .route("/wallet/:slot", axum::routing::delete(delete_wallet))
        .route("/mcp/register", post(mcp_register))
        .route("/mcp/validate-key", post(mcp_validate_key))
        .route("/tier-config", get(tier_config))
        .route("/route-history", get(get_route_history))
        .route("/usage-stats", get(get_usage_stats))
        .route("/pocket/:pocket_id/transactions", get(get_pocket_transactions))
        .route("/admin/partners", get(list_partners_handler))
        .route("/admin/partners", post(add_partner_handler))
        .route("/admin/partners/:id", axum::routing::delete(delete_partner_handler))
        .layer(CorsLayer::new()
            .allow_origin(Any)
            .allow_methods(Any)
            .allow_headers(Any))
        .with_state(state);

    // Start server
    let addr = format!("0.0.0.0:{}", config.port);
    info!("Listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

// Wrapper for delete handler (axum routing needs different signature)
async fn delete_pocket_handler(
    State(state): State<Arc<AppState>>,
    Path(pocket_id): Path<String>,
    Json(req): Json<DeletePocketRequest>,
) -> std::result::Result<Json<DeletePocketResponse>, AppError> {
    delete_pocket(State(state), Path(pocket_id), Json(req)).await
}

// === Wallet Management Handlers ===

#[derive(Debug, Deserialize)]
struct AddWalletRequest {
    meta_address: String,
    slot: u8,
    wallet_address: String,
}

#[derive(Debug, Serialize)]
struct AddWalletResponse {
    success: bool,
    slot: u8,
    wallet_address: String,
}

#[derive(Debug, Deserialize)]
struct ListWalletsQuery {
    meta_address: String,
}

#[derive(Debug, Serialize)]
struct WalletInfo {
    slot: u8,
    address: String,
}

#[derive(Debug, Serialize)]
struct ListWalletsResponse {
    success: bool,
    wallets: Vec<WalletInfo>,
}

#[derive(Debug, Deserialize)]
struct DeleteWalletQuery {
    meta_address: String,
}

#[derive(Debug, Serialize)]
struct DeleteWalletResponse {
    success: bool,
    deleted: bool,
}

async fn add_wallet(
    State(state): State<Arc<AppState>>,
    Json(req): Json<AddWalletRequest>,
) -> std::result::Result<Json<AddWalletResponse>, AppError> {
    // Validate slot
    if req.slot < 1 || req.slot > 5 {
        return Err(MazeError::InvalidParameters("Slot must be 1-5".into()).into());
    }

    // Validate wallet address
    Pubkey::from_str(&req.wallet_address)
        .map_err(|_| MazeError::InvalidParameters("Invalid Solana address".into()))?;

    let owner_meta_hash = hash_meta_address(&req.meta_address);
    state.db.add_destination_wallet(&owner_meta_hash, req.slot, &req.wallet_address)?;

    info!("Added wallet slot {} for user", req.slot);

    Ok(Json(AddWalletResponse {
        success: true,
        slot: req.slot,
        wallet_address: req.wallet_address,
    }))
}

async fn list_wallets(
    State(state): State<Arc<AppState>>,
    Query(query): Query<ListWalletsQuery>,
) -> std::result::Result<Json<ListWalletsResponse>, AppError> {
    let owner_meta_hash = hash_meta_address(&query.meta_address);
    let wallets = state.db.get_destination_wallets(&owner_meta_hash)?;

    let wallet_infos: Vec<WalletInfo> = wallets
        .into_iter()
        .map(|(slot, address)| WalletInfo { slot, address })
        .collect();

    Ok(Json(ListWalletsResponse {
        success: true,
        wallets: wallet_infos,
    }))
}

async fn delete_wallet(
    State(state): State<Arc<AppState>>,
    Path(slot): Path<u8>,
    Query(query): Query<DeleteWalletQuery>,
) -> std::result::Result<Json<DeleteWalletResponse>, AppError> {
    let owner_meta_hash = hash_meta_address(&query.meta_address);
    let deleted = state.db.delete_destination_wallet(&owner_meta_hash, slot)?;

    Ok(Json(DeleteWalletResponse {
        success: true,
        deleted,
    }))
}


// ============ POCKET MANAGEMENT (Phase 1) ============

#[derive(Debug, Deserialize)]
struct RenamePocketRequest {
    meta_address: String,
    label: Option<String>,
}

#[derive(Debug, Serialize)]
struct RenamePocketResponse {
    success: bool,
    pocket_id: String,
    label: Option<String>,
}

async fn rename_pocket_handler(
    State(state): State<Arc<AppState>>,
    Path(pocket_id): Path<String>,
    Json(req): Json<RenamePocketRequest>,
) -> std::result::Result<Json<RenamePocketResponse>, AppError> {
    let owner_meta_hash = hash_meta_address(&req.meta_address);
    
    let updated = state.db.rename_pocket(&pocket_id, &owner_meta_hash, req.label.as_deref())?;
    
    if !updated {
        return Err(MazeError::PocketNotFound(pocket_id.clone()).into());
    }
    
    info!("Pocket {} renamed to {:?}", pocket_id, req.label);
    
    Ok(Json(RenamePocketResponse {
        success: true,
        pocket_id,
        label: req.label,
    }))
}

#[derive(Debug, Deserialize)]
struct ArchivePocketRequest {
    meta_address: String,
    archived: bool,
}

#[derive(Debug, Serialize)]
struct ArchivePocketResponse {
    success: bool,
    pocket_id: String,
    archived: bool,
}

async fn archive_pocket_handler(
    State(state): State<Arc<AppState>>,
    Path(pocket_id): Path<String>,
    Json(req): Json<ArchivePocketRequest>,
) -> std::result::Result<Json<ArchivePocketResponse>, AppError> {
    let owner_meta_hash = hash_meta_address(&req.meta_address);
    
    let updated = state.db.archive_pocket(&pocket_id, &owner_meta_hash, req.archived)?;
    
    if !updated {
        return Err(MazeError::PocketNotFound(pocket_id.clone()).into());
    }
    
    info!("Pocket {} archived={}", pocket_id, req.archived);
    
    Ok(Json(ArchivePocketResponse {
        success: true,
        pocket_id,
        archived: req.archived,
    }))
}


// ============ PHASE 2: ROUTE HISTORY & STATS ============

#[derive(Debug, Deserialize)]
struct RouteHistoryQuery {
    meta_address: String,
    limit: Option<u32>,
}

#[derive(Debug, Serialize)]
struct RouteHistoryEntryResponse {
    id: String,
    route_type: String,
    amount_lamports: u64,
    amount_sol: f64,
    fee_lamports: u64,
    status: String,
    destination: Option<String>,
    created_at: i64,
    completed_at: Option<i64>,
    tx_signature: Option<String>,
}

#[derive(Debug, Serialize)]
struct RouteHistoryResponse {
    success: bool,
    routes: Vec<RouteHistoryEntryResponse>,
    count: usize,
}

async fn get_route_history(
    State(state): State<Arc<AppState>>,
    Query(query): Query<RouteHistoryQuery>,
) -> std::result::Result<Json<RouteHistoryResponse>, AppError> {
    let owner_meta_hash = hash_meta_address(&query.meta_address);
    let limit = query.limit.unwrap_or(50).min(100);
    
    let history = state.db.get_route_history(&owner_meta_hash, limit)?;
    
    let routes: Vec<RouteHistoryEntryResponse> = history.into_iter().map(|h| RouteHistoryEntryResponse {
        id: h.id,
        route_type: h.route_type,
        amount_lamports: h.amount_lamports,
        amount_sol: lamports_to_sol(h.amount_lamports),
        fee_lamports: h.fee_lamports,
        status: h.status,
        destination: h.destination,
        created_at: h.created_at,
        completed_at: h.completed_at,
        tx_signature: h.tx_signature,
    }).collect();
    
    let count = routes.len();
    
    Ok(Json(RouteHistoryResponse {
        success: true,
        routes,
        count,
    }))
}

#[derive(Debug, Deserialize)]
struct UsageStatsQuery {
    meta_address: String,
}

#[derive(Debug, Serialize)]
struct UsageStatsResponse {
    success: bool,
    routes_today: i64,
    routes_this_week: i64,
    routes_this_month: i64,
    total_volume_lamports: u64,
    total_volume_sol: f64,
}

async fn get_usage_stats(
    State(state): State<Arc<AppState>>,
    Query(query): Query<UsageStatsQuery>,
) -> std::result::Result<Json<UsageStatsResponse>, AppError> {
    let owner_meta_hash = hash_meta_address(&query.meta_address);
    
    let stats = state.db.get_usage_stats(&owner_meta_hash)?;
    
    Ok(Json(UsageStatsResponse {
        success: true,
        routes_today: stats.routes_today,
        routes_this_week: stats.routes_this_week,
        routes_this_month: stats.routes_this_month,
        total_volume_lamports: stats.total_volume_lamports,
        total_volume_sol: lamports_to_sol(stats.total_volume_lamports),
    }))
}


// ============ TOOL #22: GET POCKET TRANSACTIONS (Simple) ============

#[derive(Debug, Deserialize)]
struct PocketTransactionsQuery {
    meta_address: String,
    limit: Option<usize>,
}

#[derive(Debug, Serialize)]
struct TransactionInfo {
    signature: String,
    slot: u64,
    block_time: Option<i64>,
    status: String,
}

#[derive(Debug, Serialize)]
struct PocketTransactionsResponse {
    success: bool,
    pocket_id: String,
    address: String,
    transactions: Vec<TransactionInfo>,
    count: usize,
}

async fn get_pocket_transactions(
    State(state): State<Arc<AppState>>,
    Path(pocket_id): Path<String>,
    Query(query): Query<PocketTransactionsQuery>,
) -> std::result::Result<Json<PocketTransactionsResponse>, AppError> {
    let owner_meta_hash = hash_meta_address(&query.meta_address);
    let limit = query.limit.unwrap_or(20).min(50);
    
    // Get pocket and verify ownership
    let pocket = state.db.get_pocket_for_owner(&pocket_id, &owner_meta_hash)?
        .ok_or(MazeError::PocketNotFound(pocket_id.clone()))?;
    
    let pocket_pubkey = Pubkey::from_str(&pocket.stealth_pubkey)
        .map_err(|e| MazeError::InvalidParameters(e.to_string()))?;
    
    // Get signatures from Solana RPC (simple version - 1 RPC call)
    use solana_client::rpc_client::GetConfirmedSignaturesForAddress2Config;
    
    let config = GetConfirmedSignaturesForAddress2Config {
        limit: Some(limit),
        ..Default::default()
    };
    
    let signatures = state.rpc
        .get_signatures_for_address_with_config(&pocket_pubkey, config)
        .unwrap_or_default();
    
    let transactions: Vec<TransactionInfo> = signatures.into_iter().map(|sig| {
        TransactionInfo {
            signature: sig.signature,
            slot: sig.slot,
            block_time: sig.block_time,
            status: if sig.err.is_none() { "success".to_string() } else { "failed".to_string() },
        }
    }).collect();
    
    let count = transactions.len();
    
    Ok(Json(PocketTransactionsResponse {
        success: true,
        pocket_id,
        address: pocket.stealth_pubkey,
        transactions,
        count,
    }))
}



// ============ MCP API KEY ============

#[derive(Debug, Deserialize)]
struct McpRegisterRequest {
    wallet_address: String,
    signature: String,
    message: String,
    timestamp: i64,
}

#[derive(Debug, Serialize)]
struct McpRegisterResponse {
    success: bool,
    api_key: Option<String>,
    tier: Option<String>,
    error: Option<String>,
}


async fn mcp_register(
    State(state): State<Arc<AppState>>,
    Json(req): Json<McpRegisterRequest>,
) -> std::result::Result<Json<McpRegisterResponse>, AppError> {
    use sha2::{Sha256, Digest};
    
    info!("MCP register request for wallet: {}", &req.wallet_address);
    
    // Validate timestamp (within 5 minutes)
    let now = chrono::Utc::now().timestamp_millis();
    if (now - req.timestamp).abs() > 300_000 {
        return Ok(Json(McpRegisterResponse {
            success: false,
            api_key: None,
            tier: None,
            error: Some("Request expired".into()),
        }));
    }
    
    // Validate wallet address
    let _pubkey = Pubkey::from_str(&req.wallet_address)
        .map_err(|_| MazeError::InvalidParameters("Invalid wallet address".into()))?;
    
    // Verify signature exists (basic check - frontend signs with wallet)
    if req.signature.is_empty() || req.message.is_empty() {
        return Ok(Json(McpRegisterResponse {
            success: false,
            api_key: None,
            tier: None,
            error: Some("Missing signature or message".into()),
        }));
    }
    
    // Generate API key
    let random_bytes: [u8; 16] = rand::random();
    let api_key = format!("kl_{}", hex::encode(random_bytes));
    
    // Hash API key for storage
    let mut hasher = Sha256::new();
    hasher.update(api_key.as_bytes());
    let api_key_hash = hex::encode(hasher.finalize());
    
    // Store in database
    let owner_meta_hash = hash_meta_address(&req.wallet_address);
    state.db.store_mcp_api_key(&api_key_hash, &req.wallet_address, &owner_meta_hash)?;
    
    info!("MCP API key generated for wallet: {}", &req.wallet_address);
    
    Ok(Json(McpRegisterResponse {
        success: true,
        api_key: Some(api_key),
        tier: None,
        error: None,
    }))
}

// ============ MCP VALIDATE API KEY ============

#[derive(Debug, Deserialize)]
struct McpValidateKeyRequest {
    api_key: String,
}

#[derive(Debug, Serialize)]
struct McpValidateKeyResponse {
    valid: bool,
    wallet_address: Option<String>,
}

async fn mcp_validate_key(
    State(state): State<Arc<AppState>>,
    Json(req): Json<McpValidateKeyRequest>,
) -> Json<McpValidateKeyResponse> {
    use sha2::{Sha256, Digest};
    
    // Hash the API key
    let mut hasher = Sha256::new();
    hasher.update(req.api_key.as_bytes());
    let api_key_hash = hex::encode(hasher.finalize());
    
    // Lookup in database
    match state.db.validate_mcp_api_key(&api_key_hash) {
        Ok(Some(wallet_address)) => Json(McpValidateKeyResponse {
            valid: true,
            wallet_address: Some(wallet_address),
        }),
        _ => Json(McpValidateKeyResponse {
            valid: false,
            wallet_address: None,
        }),
    }
}

// ============ ADMIN PARTNER MANAGEMENT ============

// Admin auth helper
fn verify_admin_key(state: &AppState, headers: &axum::http::HeaderMap) -> std::result::Result<(), AppError> {
    let admin_key = match &state.config.admin_api_key {
        Some(key) => key,
        None => return Err(MazeError::InvalidParameters("Admin API not configured".into()).into()),
    };
    
    let provided_key = headers
        .get("X-Admin-Key")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    
    if provided_key != admin_key {
        return Err(MazeError::InvalidParameters("Invalid admin key".into()).into());
    }
    
    Ok(())
}

#[derive(Debug, Deserialize)]
struct AddPartnerRequest {
    token_symbol: String,
    token_mint: String,
    tier_basic: i64,
    tier_pro: i64,
    is_official: Option<bool>,
}

#[derive(Debug, Serialize)]
struct AddPartnerResponse {
    success: bool,
    partner_id: String,
    message: String,
}

#[derive(Debug, Serialize)]
struct ListPartnersResponse {
    success: bool,
    partners: Vec<PartnerInfo>,
    count: usize,
}

#[derive(Debug, Serialize)]
struct PartnerInfo {
    id: String,
    token_symbol: String,
    token_mint: String,
    tier_basic: i64,
    tier_pro: i64,
    is_official_partner: bool,
    status: String,
}

#[derive(Debug, Serialize)]
struct DeletePartnerResponse {
    success: bool,
    message: String,
}
async fn add_partner_handler(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Json(req): Json<AddPartnerRequest>,

) -> std::result::Result<Json<AddPartnerResponse>, AppError> {
    verify_admin_key(&state, &headers)?;
    use sdp_mazepocket::relay::database::Partner;
    
    let now = chrono::Utc::now().timestamp();
    let partner_id = format!("partner_{}", &generate_pocket_id()[7..]);
    
    let partner = Partner {
        id: partner_id.clone(),
        token_symbol: req.token_symbol.clone(),
        token_mint: req.token_mint.clone(),
        tier_basic: req.tier_basic,
        tier_pro: req.tier_pro,
        is_official_partner: req.is_official.unwrap_or(false),
        status: "active".to_string(),
        created_at: now,
        updated_at: now,
    };
    
    state.db.create_partner(&partner)?;
    
    info!("Partner {} added: {} ({})", partner_id, req.token_symbol, req.token_mint);
    
    Ok(Json(AddPartnerResponse {
        success: true,
        partner_id,
        message: format!("Partner {} added successfully", req.token_symbol),
    }))
}

async fn list_partners_handler(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
) -> std::result::Result<Json<ListPartnersResponse>, AppError> {
    verify_admin_key(&state, &headers)?;
    let partners = state.db.list_partners()?;
    
    let partner_infos: Vec<PartnerInfo> = partners.iter().map(|p| PartnerInfo {
        id: p.id.clone(),
        token_symbol: p.token_symbol.clone(),
        token_mint: p.token_mint.clone(),
        tier_basic: p.tier_basic,
        tier_pro: p.tier_pro,
        is_official_partner: p.is_official_partner,
        status: p.status.clone(),
    }).collect();
    
    let count = partner_infos.len();
    
    Ok(Json(ListPartnersResponse {
        success: true,
        partners: partner_infos,
        count,
    }))
}

async fn delete_partner_handler(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Path(partner_id): Path<String>,
) -> std::result::Result<Json<DeletePartnerResponse>, AppError> {
    verify_admin_key(&state, &headers)?;
    let deleted = state.db.delete_partner(&partner_id)?;
    
    if deleted {
        info!("Partner {} deleted", partner_id);
        Ok(Json(DeletePartnerResponse {
            success: true,
            message: format!("Partner {} deleted", partner_id),
        }))
    } else {
        Ok(Json(DeletePartnerResponse {
            success: false,
            message: "Partner not found".to_string(),
        }))
    }
}
