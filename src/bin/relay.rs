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
        TX_FEE_LAMPORTS, FEE_PERCENT, MIN_AMOUNT_SOL, EXPIRY_SECONDS, SEND_LINK_EXPIRY_SECONDS, FEE_WALLET, PROTOCOL_FEE_BPS,
    },
    core::{lamports_to_sol, sol_to_lamports, generate_pocket_id},
    relay::{
        PocketDatabase, MazeGenerator, MazeGraph, MazeNode,
        database::{MazePocket, PocketStatus, FundingRequest, P2pTransfer, Contact, MazePreferences, GateEndpoint, SendLink, XAccountLink},
    },
    error::{MazeError, Result},
    swap::{self, SwapQuoteRequest, SwapQuoteResponse, SwapResult},
    tokens::{self, TokenInfo},
    printr::{self, PrintrCreateRequest},
    payment_router,
    evm,
    perps,
    genesis,
    conduit,
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
        let (status, _code) = match &self.0 {
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
    pool_lock: Arc<tokio::sync::Semaphore>,
    http_client: reqwest::Client,
    kausa_prompt: String,
    openrouter_api_key: String,
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
    label: Option<String>,
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
    total_volume_lamports: u64,
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

// ============ P2P TRANSFER TYPES ============

#[derive(Debug, Deserialize)]
struct SendToPocketRequest {
    meta_address: String,
    recipient_pocket_id: String,
    amount_sol: f64,
    maze_config: Option<CustomMazeConfig>,
}

#[derive(Debug, Serialize)]
struct SendToPocketResponse {
    success: bool,
    transfer_id: String,
    amount_lamports: u64,
    fee_lamports: u64,
    status: String,
    maze_info: MazeInfo,
}

#[derive(Debug, Serialize)]
struct P2pStatusResponse {
    success: bool,
    transfer_id: String,
    status: String,
    progress: Option<MazeProgress>,
    error: Option<String>,
}

// ============ SPAWN POCKET TYPES ============

#[derive(Debug, Deserialize)]
struct SpawnPocketRequest {
    meta_address: String,
    amount_sol: f64,
    label: Option<String>,
    maze_config: Option<CustomMazeConfig>,
}

#[derive(Debug, Serialize)]
struct SpawnPocketResponse {
    success: bool,
    new_pocket_id: String,
    new_pocket_address: String,
    source_pocket_id: String,
    transfer_id: String,
    amount_lamports: u64,
    fee_lamports: u64,
    status: String,
    maze_info: MazeInfo,
}

// ============ SEND LINK TYPES (KausaLink) ============

#[derive(Debug, Deserialize)]
struct CreateSendLinkRequest {
    meta_address: String,
    pocket_id: String,
    amount_sol: f64,
    label: Option<String>,
}

#[derive(Debug, Serialize)]
struct CreateSendLinkResponse {
    success: bool,
    link_id: String,
    link_url: String,
    amount_lamports: u64,
    expires_at: i64,
}

#[derive(Debug, Deserialize)]
struct SendLinkInfoQuery {
    s: String, // secret
}

#[derive(Debug, Serialize)]
struct SendLinkInfoResponse {
    success: bool,
    amount_sol: f64,
    label: Option<String>,
    status: String,
    created_at: i64,
}

#[derive(Debug, Deserialize)]
struct ClaimSendLinkRequest {
    secret: String,
    wallet_address: String,
    signature: String,
    message: String,
}

#[derive(Debug, Serialize)]
struct ClaimSendLinkResponse {
    success: bool,
    pocket_id: Option<String>,
    meta_address: Option<String>,
    amount_sol: f64,
    message: String,
}

#[derive(Debug, Deserialize)]
struct ListSendLinksQuery {
    meta_address: String,
}

#[derive(Debug, Serialize)]
struct SendLinkEntry {
    id: String,
    amount_sol: f64,
    label: Option<String>,
    status: String,
    created_at: i64,
    expires_at: i64,
    claimed_at: Option<i64>,
    link_url: Option<String>,
}

#[derive(Debug, Serialize)]
struct ListSendLinksResponse {
    success: bool,
    links: Vec<SendLinkEntry>,
    count: usize,
}

// ============ UTILITY FUNCTIONS ============

fn hash_meta_address(meta: &str) -> String {
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(meta.as_bytes());
    hex::encode(hasher.finalize())
}

fn parse_maze_config(config: Option<CustomMazeConfig>, pool_address: Option<String>, pool_private_key: Option<String>) -> MazeParameters {
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
    

    // Inject pool config if available
    params.pool_address = pool_address;
    if let Some(ref pk_str) = pool_private_key {
        if let Ok(pk_bytes) = bs58::decode(pk_str).into_vec() {
            params.pool_private_key_bytes = Some(pk_bytes);
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
        total_volume_lamports: stats.total_volume_lamports,
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
    let maze_params = parse_maze_config(req.maze_config, state.config.pool_address.clone(), state.config.pool_private_key.clone());

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
        evm_address: None,
        evm_keypair_encrypted: None,
        usepod_token: None,
        usepod_deposit_address: None,
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
    let maze_params = parse_maze_config(req.maze_config, state.config.pool_address.clone(), state.config.pool_private_key.clone());

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
        evm_address: None,
        evm_keypair_encrypted: None,
        usepod_token: None,
        usepod_deposit_address: None,
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
            label: pocket.label.clone(),
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
    let maze_params = parse_maze_config(req.maze_config, state.config.pool_address.clone(), state.config.pool_private_key.clone());
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
                error!("Sweep maze failed for {}, starting auto-recover: {}", pocket_id_clone, sanitize_error(&e.to_string()));
                // Auto-recover: get sweep maze and destination, recover silently
                let mut recovered = false;
                if let Ok(Some(sweep_req)) = state_clone.db.get_sweep_request(&sweep_id_clone) {
                    let destination = sweep_req.2.clone();
                    if let Ok(maze_json) = state_clone.db.get_sweep_maze_graph(&sweep_id_clone) {
                        if let Ok(maze) = serde_json::from_str::<MazeGraph>(&maze_json) {
                            let amount = auto_recover_nodes_to_destination(
                                state_clone.clone(), &maze.nodes, &destination, &sweep_id_clone, 3
                            ).await;
                            if amount > 0 {
                                info!("Auto-recover sweep {}: recovered {} lamports", sweep_id_clone, amount);
                                let _ = state_clone.db.update_sweep_status(&sweep_id_clone, "completed", None, None);
                                let _ = state_clone.db.mark_pocket_swept(&pocket_id_clone);
                                recovered = true;
                            }
                        }
                    }
                }
                if !recovered {
                    error!("Auto-recover sweep {} exhausted, marking failed", sweep_id_clone);
                    let _ = state_clone.db.update_pocket_status(&pocket_id_clone, PocketStatus::Active);
                    let _ = state_clone.db.update_sweep_status(&sweep_id_clone, "failed", None, Some(&sanitize_error(&e.to_string())));
                }
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

// ============ AUTO-RECOVERY HELPER ============

/// Automatic silent recovery for failed maze routing.
/// Scans all maze nodes for stuck funds and transfers them to destination.
/// Retries up to max_attempts with exponential backoff.
/// Returns total recovered lamports, or 0 if nothing recovered.
async fn auto_recover_nodes_to_destination(
    state: Arc<AppState>,
    nodes: &[MazeNode],
    destination: &str,
    route_id: &str,
    max_attempts: u8,
) -> u64 {
    let dest_pubkey = match Pubkey::from_str(destination) {
        Ok(p) => p,
        Err(e) => {
            error!("Auto-recover {}: invalid destination {}: {}", route_id, destination, e);
            return 0;
        }
    };

    for attempt in 1..=max_attempts {
        // Cooldown before each attempt: 10s, 20s, 40s (exponential backoff)
        let cooldown_secs = 10u64 * (1u64 << (attempt as u64 - 1));
        info!("Auto-recover {}: attempt {}/{} after {}s cooldown", route_id, attempt, max_attempts, cooldown_secs);
        tokio::time::sleep(tokio::time::Duration::from_secs(cooldown_secs)).await;

        let mut total_recovered: u64 = 0;
        let mut any_error = false;

        for node in nodes {
            let node_pubkey = match Pubkey::from_str(&node.address) {
                Ok(p) => p,
                Err(_) => continue,
            };

            let balance = match state.rpc.get_balance(&node_pubkey) {
                Ok(b) => b,
                Err(e) => {
                    warn!("Auto-recover {}: get_balance failed for node {}: {}", route_id, node.index, e);
                    any_error = true;
                    continue;
                }
            };

            if balance <= TX_FEE_LAMPORTS {
                continue;
            }

            // Decrypt keypair
            let keypair_bytes = match state.db.decrypt(&node.keypair_encrypted) {
                Ok(b) => b,
                Err(e) => {
                    warn!("Auto-recover {}: decrypt failed for node {}: {}", route_id, node.index, e);
                    any_error = true;
                    continue;
                }
            };
            let keypair = match Keypair::from_bytes(&keypair_bytes) {
                Ok(k) => k,
                Err(e) => {
                    warn!("Auto-recover {}: keypair error for node {}: {}", route_id, node.index, e);
                    any_error = true;
                    continue;
                }
            };

            let transfer_amount = balance.saturating_sub(TX_FEE_LAMPORTS);
            if transfer_amount == 0 {
                continue;
            }

            // Transfer with retry (5 internal retries per node)
            let mut tx_success = false;
            for tx_attempt in 1..=5u8 {
                let blockhash = match state.rpc.get_latest_blockhash() {
                    Ok(bh) => bh,
                    Err(e) => {
                        warn!("Auto-recover {}: node {} blockhash attempt {}/5: {}", route_id, node.index, tx_attempt, e);
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
                        // Wait for confirmation
                        let mut confirmed = false;
                        for _ in 0..30 {
                            tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
                            if let Ok(Some(result)) = state.rpc.get_signature_status(&sig) {
                                if result.is_ok() {
                                    confirmed = true;
                                    break;
                                }
                            }
                        }
                        if confirmed {
                            info!("Auto-recover {}: recovered {} lamports from node {} ({})", route_id, transfer_amount, node.index, sig);
                            total_recovered += transfer_amount;
                            tx_success = true;
                            break;
                        } else {
                            warn!("Auto-recover {}: node {} TX sent but confirmation timeout", route_id, node.index);
                        }
                    }
                    Err(e) => {
                        let err_str = e.to_string();
                        if err_str.contains("connection") || err_str.contains("timeout") || err_str.contains("closed") {
                            warn!("Auto-recover {}: node {} TX attempt {}/5: {}", route_id, node.index, tx_attempt, err_str);
                            tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
                            continue;
                        }
                        warn!("Auto-recover {}: node {} TX failed: {}", route_id, node.index, err_str);
                        break;
                    }
                }
            }

            if !tx_success {
                any_error = true;
            }
        }

        if total_recovered > 0 {
            info!("Auto-recover {}: attempt {}/{} recovered {} lamports total", route_id, attempt, max_attempts, total_recovered);
            return total_recovered;
        }

        if !any_error {
            // No errors but no funds found either — nothing to recover
            info!("Auto-recover {}: attempt {}/{} no funds found in any node", route_id, attempt, max_attempts);
            return 0;
        }

        // Had errors, will retry on next attempt
        warn!("Auto-recover {}: attempt {}/{} failed with errors, will retry", route_id, attempt, max_attempts);
    }

    error!("Auto-recover {}: all {} attempts exhausted", route_id, max_attempts);
    0
}


async fn execute_maze(state: Arc<AppState>, request_id: &str) -> Result<()> {
    info!("Executing maze for funding request {}", request_id);

    // Update status to processing so frontend can show progress
    state.db.update_funding_status(request_id, "processing", None)?;

    // Get maze graph from database
    let maze_json = state.db.get_maze_graph(request_id)?;
    let maze: MazeGraph = serde_json::from_str(&maze_json)
        .map_err(|e| MazeError::DatabaseError(e.to_string()))?;

    // Detect pool node level (if pool mode is active)
    let pool_level: Option<u8> = if let Some(ref pool_addr) = state.config.pool_address {
        maze.nodes.iter()
            .find(|n| n.address == *pool_addr)
            .map(|n| n.level)
    } else {
        None
    };

    // Execute level by level with pool queue
    let mut _pool_guard: Option<tokio::sync::SemaphorePermit<'_>> = None;

    for level in 0..=maze.total_levels {
        // Acquire pool lock before pool level (timeout 180s)
        if let Some(pl) = pool_level {
            if level == pl && _pool_guard.is_none() {
                info!("Waiting for pool lock (request {})", request_id);
                match tokio::time::timeout(
                    tokio::time::Duration::from_secs(180),
                    state.pool_lock.acquire()
                ).await {
                    Ok(Ok(permit)) => {
                        info!("Pool lock acquired (request {})", request_id);
                        _pool_guard = Some(permit);
                    }
                    Ok(Err(_)) => {
                        return Err(MazeError::TransactionError("Pool semaphore closed".into()));
                    }
                    Err(_) => {
                        return Err(MazeError::TransactionError("Pool busy, timeout after 180s. Please retry.".into()));
                    }
                }
            }
        }

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

    // Pool lock auto-released when _pool_guard is dropped
    drop(_pool_guard);

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
    let mut distributable = balance.saturating_sub(total_fees);

    if distributable == 0 {
        return Err(MazeError::InsufficientFunds {
            required: total_fees + 1,
            available: balance,
        });
    }

    // === PROTOCOL FEE DEDUCTION (pool node only) ===
    let mut protocol_fee_deducted: u64 = 0;
    if let Some(ref pool_addr) = state.config.pool_address {
        if node.address == *pool_addr {
            let fee_amount = distributable * PROTOCOL_FEE_BPS / 10_000;
            if fee_amount > TX_FEE_LAMPORTS * 2 {
                let fee_wallet_pubkey = match Pubkey::from_str(FEE_WALLET) {
                    Ok(pk) => pk,
                    Err(e) => {
                        warn!("Invalid FEE_WALLET address, skipping fee: {}", e);
                        Pubkey::default()
                    }
                };
                if fee_wallet_pubkey != Pubkey::default() {
                    let fee_result: std::result::Result<(), String> = async {
                        let blockhash = state.rpc.get_latest_blockhash()
                            .map_err(|e| e.to_string())?;
                        let fee_ix = system_instruction::transfer(
                            &keypair.pubkey(),
                            &fee_wallet_pubkey,
                            fee_amount,
                        );
                        let fee_tx = Transaction::new_signed_with_payer(
                            &[fee_ix],
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
                        let sig = state.rpc.send_transaction_with_config(&fee_tx, config)
                            .map_err(|e| e.to_string())?;
                        for _ in 0..30 {
                            tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
                            if let Ok(Some(result)) = state.rpc.get_signature_status(&sig) {
                                if result.is_ok() {
                                    info!("Protocol fee collected: {} lamports, tx: {}", fee_amount, sig);
                                    return Ok(());
                                }
                            }
                        }
                        Err("Fee TX confirmation timeout".to_string())
                    }.await;

                    match fee_result {
                        Ok(()) => {
                            distributable = distributable - fee_amount - TX_FEE_LAMPORTS;
                            protocol_fee_deducted = fee_amount + TX_FEE_LAMPORTS;
                            info!("Protocol fee deducted: {} lamports (fee) + {} lamports (gas)", fee_amount, TX_FEE_LAMPORTS);
                        }
                        Err(e) => {
                            warn!("Protocol fee collection failed, skipping: {}", e);
                        }
                    }
                }
            } else {
                info!("Protocol fee too small ({} lamports), skipping", fee_amount);
            }
        }
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

    // Verify math (account for protocol fee if deducted)
    let total_to_send: u64 = amounts.iter().sum();
    if total_to_send + total_fees + protocol_fee_deducted != balance {
        error!("Amount calculation mismatch: {} + {} + {} != {}", total_to_send, total_fees, protocol_fee_deducted, balance);
        return Err(MazeError::InsufficientFunds {
            required: total_to_send + total_fees + protocol_fee_deducted,
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

    // Detect pool node level (if pool mode is active)
    let pool_level: Option<u8> = if let Some(ref pool_addr) = state.config.pool_address {
        maze.nodes.iter()
            .find(|n| n.address == *pool_addr)
            .map(|n| n.level)
    } else {
        None
    };

    // Execute maze level by level with pool queue
    let mut _pool_guard: Option<tokio::sync::SemaphorePermit<'_>> = None;

    for level in 0..=maze.total_levels {
        // Acquire pool lock before pool level (timeout 180s)
        if let Some(pl) = pool_level {
            if level == pl && _pool_guard.is_none() {
                info!("Sweep waiting for pool lock ({})", sweep_id);
                match tokio::time::timeout(
                    tokio::time::Duration::from_secs(180),
                    state.pool_lock.acquire()
                ).await {
                    Ok(Ok(permit)) => {
                        info!("Sweep pool lock acquired ({})", sweep_id);
                        _pool_guard = Some(permit);
                    }
                    Ok(Err(_)) => {
                        return Err(MazeError::TransactionError("Pool semaphore closed".into()));
                    }
                    Err(_) => {
                        return Err(MazeError::TransactionError("Pool busy, timeout after 180s. Please retry.".into()));
                    }
                }
            }
        }

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

    // Pool lock auto-released when _pool_guard is dropped
    drop(_pool_guard);

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
    let mut distributable = balance.saturating_sub(total_fees);
    
    if distributable == 0 {
        return Err(MazeError::InsufficientFunds {
            required: total_fees + 1,
            available: balance,
        });
    }

    // === PROTOCOL FEE DEDUCTION (pool node only) ===
    let mut protocol_fee_deducted: u64 = 0;
    if let Some(ref pool_addr) = state.config.pool_address {
        if node.address == *pool_addr {
            let fee_amount = distributable * PROTOCOL_FEE_BPS / 10_000;
            if fee_amount > TX_FEE_LAMPORTS * 2 {
                let fee_wallet_pubkey = match Pubkey::from_str(FEE_WALLET) {
                    Ok(pk) => pk,
                    Err(e) => {
                        warn!("Invalid FEE_WALLET address, skipping fee: {}", e);
                        Pubkey::default()
                    }
                };
                if fee_wallet_pubkey != Pubkey::default() {
                    let fee_result: std::result::Result<(), String> = async {
                        let blockhash = state.rpc.get_latest_blockhash()
                            .map_err(|e| e.to_string())?;
                        let fee_ix = system_instruction::transfer(
                            &keypair.pubkey(),
                            &fee_wallet_pubkey,
                            fee_amount,
                        );
                        let fee_tx = Transaction::new_signed_with_payer(
                            &[fee_ix],
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
                        let sig = state.rpc.send_transaction_with_config(&fee_tx, config)
                            .map_err(|e| e.to_string())?;
                        for _ in 0..30 {
                            tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
                            if let Ok(Some(result)) = state.rpc.get_signature_status(&sig) {
                                if result.is_ok() {
                                    info!("Protocol fee collected: {} lamports, tx: {}", fee_amount, sig);
                                    return Ok(());
                                }
                            }
                        }
                        Err("Fee TX confirmation timeout".to_string())
                    }.await;

                    match fee_result {
                        Ok(()) => {
                            distributable = distributable - fee_amount - TX_FEE_LAMPORTS;
                            protocol_fee_deducted = fee_amount + TX_FEE_LAMPORTS;
                            info!("Protocol fee deducted: {} lamports (fee) + {} lamports (gas)", fee_amount, TX_FEE_LAMPORTS);
                        }
                        Err(e) => {
                            warn!("Protocol fee collection failed, skipping: {}", e);
                        }
                    }
                }
            } else {
                info!("Protocol fee too small ({} lamports), skipping", fee_amount);
            }
        }
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

    // Verify math: total_amounts + total_fees + protocol_fee == initial_balance
    let total_to_send: u64 = amounts.iter().sum();
    if total_to_send + total_fees + protocol_fee_deducted != balance {
        error!("Sweep amount calculation mismatch: {} + {} + {} != {}", total_to_send, total_fees, protocol_fee_deducted, balance);
        return Err(MazeError::InsufficientFunds {
            required: total_to_send + total_fees + protocol_fee_deducted,
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

// ============ P2P TRANSFER HANDLERS ============

/// Send SOL from one pocket to another via maze routing
async fn send_to_pocket(
    State(state): State<Arc<AppState>>,
    Path(pocket_id): Path<String>,
    Json(req): Json<SendToPocketRequest>,
) -> std::result::Result<Json<SendToPocketResponse>, AppError> {
    let owner_meta_hash = hash_meta_address(&req.meta_address);

    // Validate amount
    if req.amount_sol < MIN_AMOUNT_SOL {
        return Err(MazeError::InvalidParameters(format!("Minimum amount is {} SOL", MIN_AMOUNT_SOL)).into());
    }

    // Get sender pocket and verify ownership
    let sender_pocket = state.db.get_pocket_for_owner(&pocket_id, &owner_meta_hash)?;
    let sender_pocket = match sender_pocket {
        Some(p) => p,
        None => return Err(MazeError::PocketNotFound(format!("Sender pocket not found or access denied: {}", pocket_id)).into()),
    };

    if sender_pocket.status != PocketStatus::Active {
        return Err(MazeError::InvalidParameters(format!("Sender pocket status is {}, must be active", sender_pocket.status.as_str())).into());
    }

    // Get receiver pocket (no ownership check - anyone can receive)
    let receiver_pocket = state.db.get_pocket(&req.recipient_pocket_id)?;
    let receiver_pocket = match receiver_pocket {
        Some(p) => p,
        None => return Err(MazeError::PocketNotFound(format!("Receiver pocket not found: {}", req.recipient_pocket_id)).into()),
    };

    if receiver_pocket.status != PocketStatus::Active {
        return Err(MazeError::InvalidParameters("Receiver pocket is not active".into()).into());
    }

    // Prevent sending to same pocket
    if pocket_id == req.recipient_pocket_id {
        return Err(MazeError::InvalidParameters("Cannot send to same pocket".into()).into());
    }

    // Get sender keypair and check balance
    let keypair_bytes = state.db.decrypt(&sender_pocket.keypair_encrypted)?;
    let sender_keypair = Keypair::from_bytes(&keypair_bytes)
        .map_err(|e| MazeError::KeypairError(e.to_string()))?;

    let balance = state.rpc.get_balance(&sender_keypair.pubkey())
        .map_err(|e| MazeError::RpcError(e.to_string()))?;

    let amount_lamports = sol_to_lamports(req.amount_sol);
    let fee_lamports = (amount_lamports as f64 * FEE_PERCENT / 100.0) as u64;
    let total_needed = amount_lamports + fee_lamports + (TX_FEE_LAMPORTS * 50);

    if balance < total_needed {
        return Err(MazeError::InsufficientFunds {
            required: total_needed,
            available: balance,
        }.into());
    }

    info!("P2P transfer: {} SOL from {} to {}", req.amount_sol, pocket_id, req.recipient_pocket_id);

    // Generate maze
    let maze_params = parse_maze_config(req.maze_config, state.config.pool_address.clone(), state.config.pool_private_key.clone());
    let generator = MazeGenerator::new(maze_params);
    let encrypt_fn = |data: &[u8]| state.db.encrypt(data);

    let maze = match generator.generate(total_needed, encrypt_fn) {
        Ok(m) => m,
        Err(e) => return Err(MazeError::MazeGenerationError(format!("Failed to generate maze: {}", e)).into()),
    };

    let transfer_id = format!("p2p_{}", &generate_pocket_id()[7..]);
    let maze_json = serde_json::to_string(&maze).unwrap_or_default();
    let now = chrono::Utc::now().timestamp();

    // Create P2P transfer record
    let transfer = P2pTransfer {
        id: transfer_id.clone(),
        sender_pocket_id: pocket_id.clone(),
        receiver_pocket_id: req.recipient_pocket_id.clone(),
        sender_meta_hash: owner_meta_hash.clone(),
        amount_lamports,
        fee_lamports,
        maze_graph_json: Some(maze_json.clone()),
        status: "pending".to_string(),
        created_at: now,
        completed_at: None,
        error_message: None,
        tx_signature: None,
    };

    state.db.create_p2p_transfer(&transfer)?;

    // Store maze nodes for progress tracking
    for node in &maze.nodes {
        state.db.store_p2p_node(&transfer_id, node)?;
    }

    // Transfer from sender pocket to first maze node
    let first_node = &maze.nodes[0];
    let first_node_pubkey = Pubkey::from_str(&first_node.address)
        .map_err(|e| MazeError::InvalidParameters(e.to_string()))?;

    let transfer_to_maze = amount_lamports + fee_lamports + (TX_FEE_LAMPORTS * maze.total_transactions as u64);

    let sig = {
        let mut last_err = String::new();
        let mut result_sig = None;
        for attempt in 1..=5u8 {
            let blockhash = match state.rpc.get_latest_blockhash() {
                Ok(bh) => bh,
                Err(e) => {
                    warn!("P2P initial attempt {}/5: Failed to get blockhash: {}", attempt, e);
                    last_err = e.to_string();
                    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
                    continue;
                }
            };
            let ix = system_instruction::transfer(
                &sender_keypair.pubkey(),
                &first_node_pubkey,
                transfer_to_maze,
            );
            let tx = Transaction::new_signed_with_payer(
                &[ix],
                Some(&sender_keypair.pubkey()),
                &[&sender_keypair],
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
                        info!("P2P initial TX succeeded on attempt {}/5", attempt);
                    }
                    result_sig = Some(s);
                    break;
                }
                Err(e) => {
                    let err_str = e.to_string();
                    if err_str.contains("connection") || err_str.contains("timeout") || err_str.contains("closed") {
                        warn!("P2P initial attempt {}/5: {}", attempt, err_str);
                        last_err = err_str;
                        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
                        continue;
                    }
                    let _ = state.db.update_p2p_status(&transfer_id, "failed", Some(&sanitize_error(&e.to_string())), None);
                    return Err(AppError(MazeError::TransactionError(format!("TX failed: {}", e))));
                }
            }
        }
        match result_sig {
            Some(s) => s,
            None => {
                let _ = state.db.update_p2p_status(&transfer_id, "failed", Some(&sanitize_error(&last_err)), None);
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
                let _ = state.db.update_p2p_status(&transfer_id, "failed", Some(&format!("Initial transfer failed: {:?}", e)), None);
                return Err(AppError(MazeError::TransactionError(format!("Initial transfer failed: {:?}", e))));
            }
        }
    }

    if !confirmed {
        let _ = state.db.update_p2p_status(&transfer_id, "failed", Some("Initial transfer confirmation timeout"), None);
        return Err(AppError(MazeError::TransactionError("Initial transfer confirmation timeout".into())));
    }

    info!("P2P transfer {} initiated: {} lamports via maze", transfer_id, amount_lamports);

    // Execute P2P maze in background
    let state_clone = state.clone();
    let transfer_id_clone = transfer_id.clone();
    let receiver_address = receiver_pocket.stealth_pubkey.clone();
    tokio::spawn(async move {
        match execute_p2p_maze(state_clone.clone(), &transfer_id_clone, &receiver_address).await {
            Ok(_) => {
                info!("P2P maze completed for {}", transfer_id_clone);
            }
            Err(e) => {
                error!("P2P maze failed for {}, starting auto-recover: {}", transfer_id_clone, sanitize_error(&e.to_string()));
                // Auto-recover: get P2P maze and recover to receiver address
                let mut recovered = false;
                if let Ok(maze_json) = state_clone.db.get_p2p_maze_graph(&transfer_id_clone) {
                    if let Ok(maze) = serde_json::from_str::<MazeGraph>(&maze_json) {
                        let amount = auto_recover_nodes_to_destination(
                            state_clone.clone(), &maze.nodes, &receiver_address, &transfer_id_clone, 3
                        ).await;
                        if amount > 0 {
                            info!("Auto-recover P2P {}: recovered {} lamports", transfer_id_clone, amount);
                            let _ = state_clone.db.update_p2p_status(&transfer_id_clone, "completed", None, None);
                            recovered = true;
                        }
                    }
                }
                if !recovered {
                    error!("Auto-recover P2P {} exhausted, marking failed", transfer_id_clone);
                    let _ = state_clone.db.update_p2p_status(&transfer_id_clone, "failed", Some(&sanitize_error(&e.to_string())), None);
                }
            }
        }
    });

    Ok(Json(SendToPocketResponse {
        success: true,
        transfer_id,
        amount_lamports,
        fee_lamports,
        status: "processing".to_string(),
        maze_info: MazeInfo {
            nodes: maze.nodes.len(),
            levels: maze.total_levels,
            estimated_time_seconds: (maze.nodes.len() as u32) * 2,
        },
    }))
}

/// Execute P2P maze routing (called from background task)
async fn execute_p2p_maze(
    state: Arc<AppState>,
    transfer_id: &str,
    receiver_address: &str,
) -> Result<()> {
    info!("Executing P2P maze for {}", transfer_id);

    // Update status to processing
    state.db.update_p2p_status(transfer_id, "processing", None, None)?;

    // Get maze graph
    let maze_json = state.db.get_p2p_maze_graph(transfer_id)?;
    let maze: MazeGraph = serde_json::from_str(&maze_json)
        .map_err(|e| MazeError::DatabaseError(e.to_string()))?;

    // Execute maze level by level
    // Detect pool node level (if pool mode is active)
    let pool_level: Option<u8> = if let Some(ref pool_addr) = state.config.pool_address {
        maze.nodes.iter()
            .find(|n| n.address == *pool_addr)
            .map(|n| n.level)
    } else {
        None
    };

    // Execute maze level by level with pool queue
    let mut _pool_guard: Option<tokio::sync::SemaphorePermit<'_>> = None;

    for level in 0..=maze.total_levels {
        // Acquire pool lock before pool level (timeout 180s)
        if let Some(pl) = pool_level {
            if level == pl && _pool_guard.is_none() {
                info!("P2P waiting for pool lock ({})", transfer_id);
                match tokio::time::timeout(
                    tokio::time::Duration::from_secs(180),
                    state.pool_lock.acquire()
                ).await {
                    Ok(Ok(permit)) => {
                        info!("P2P pool lock acquired ({})", transfer_id);
                        _pool_guard = Some(permit);
                    }
                    Ok(Err(_)) => {
                        return Err(MazeError::TransactionError("Pool semaphore closed".into()));
                    }
                    Err(_) => {
                        return Err(MazeError::TransactionError("Pool busy, timeout after 180s. Please retry.".into()));
                    }
                }
            }
        }

        let nodes_at_level: Vec<&MazeNode> = maze.nodes.iter()
            .filter(|n| n.level == level)
            .collect();

        info!("P2P level {} with {} nodes", level, nodes_at_level.len());

        for node in nodes_at_level {
            if let Some(status) = state.db.get_p2p_node_status(transfer_id, node.index)? {
                if status == "completed" {
                    continue;
                }
            }

            execute_p2p_node(state.clone(), transfer_id, node, &maze, receiver_address).await?;

            let delay_ms = calculate_delay(&maze.parameters, node.level);
            if delay_ms > 0 {
                tokio::time::sleep(tokio::time::Duration::from_millis(delay_ms)).await;
            }
        }
    }

    // Pool lock auto-released when _pool_guard is dropped
    drop(_pool_guard);

    // Mark P2P transfer as completed with final tx signature
    let final_tx_sig = state.db.get_p2p_final_tx_signature(transfer_id)?;
    state.db.update_p2p_status(transfer_id, "completed", None, final_tx_sig.as_deref())?;

    info!("P2P maze completed for {}", transfer_id);
    Ok(())
}

async fn execute_p2p_node(
    state: Arc<AppState>,
    transfer_id: &str,
    node: &MazeNode,
    maze: &MazeGraph,
    receiver_address: &str,
) -> Result<()> {
    // Decrypt node keypair
    let keypair_bytes = state.db.decrypt(&node.keypair_encrypted)?;
    let keypair = Keypair::from_bytes(&keypair_bytes)
        .map_err(|e| MazeError::CryptoError(e.to_string()))?;

    let outputs = &node.outputs;

    // If no outputs, this is the final node - transfer to receiver pocket
    if outputs.is_empty() {
        let dest_pubkey = Pubkey::from_str(receiver_address)
            .map_err(|e| MazeError::ParseError(e.to_string()))?;

        // Wait for incoming funds
        let mut attempts = 0;
        let balance = loop {
            let bal = match get_balance_with_retry(&state.rpc, &keypair.pubkey(), 5).await {
                Ok(b) => b,
                Err(_) => continue,
            };
            if bal > TX_FEE_LAMPORTS {
                info!("P2P final node {} has balance: {} lamports", node.index, bal);
                break bal;
            }
            attempts += 1;
            if attempts > 120 {
                return Err(MazeError::TransactionError(
                    format!("Timeout waiting for funds at P2P final node {}", node.index)
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
                            warn!("P2P final attempt {}/5: Failed to get blockhash: {}", attempt, e);
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
                                info!("P2P final TX succeeded on attempt {}/5", attempt);
                            }
                            result_sig = Some(s);
                            break;
                        }
                        Err(e) => {
                            let err_str = e.to_string();
                            if err_str.contains("connection") || err_str.contains("timeout") || err_str.contains("closed") {
                                warn!("P2P final attempt {}/5: {}", attempt, err_str);
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
            info!("P2P final transfer: {} lamports to {} ({})", transfer_amount, receiver_address, sig);

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

        state.db.update_p2p_node_status(transfer_id, node.index, "completed", None)?;
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
            info!("P2P node {} has balance: {} lamports", node.index, bal);
            break bal;
        }
        attempts += 1;
        if attempts > 120 {
            return Err(MazeError::TransactionError(
                format!("Timeout waiting for funds at P2P node {}", node.index)
            ));
        }
        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
    };
    let num_outputs = outputs.len();
    let total_fees = TX_FEE_LAMPORTS * num_outputs as u64;
    let mut distributable = balance.saturating_sub(total_fees);

    if distributable == 0 {
        return Err(MazeError::InsufficientFunds {
            required: total_fees + 1,
            available: balance,
        });
    }

    // === PROTOCOL FEE DEDUCTION (pool node only) ===
    let mut protocol_fee_deducted: u64 = 0;
    if let Some(ref pool_addr) = state.config.pool_address {
        if node.address == *pool_addr {
            let fee_amount = distributable * PROTOCOL_FEE_BPS / 10_000;
            if fee_amount > TX_FEE_LAMPORTS * 2 {
                let fee_wallet_pubkey = match Pubkey::from_str(FEE_WALLET) {
                    Ok(pk) => pk,
                    Err(e) => {
                        warn!("Invalid FEE_WALLET address, skipping fee: {}", e);
                        Pubkey::default()
                    }
                };
                if fee_wallet_pubkey != Pubkey::default() {
                    let fee_result: std::result::Result<(), String> = async {
                        let blockhash = state.rpc.get_latest_blockhash()
                            .map_err(|e| e.to_string())?;
                        let fee_ix = system_instruction::transfer(
                            &keypair.pubkey(),
                            &fee_wallet_pubkey,
                            fee_amount,
                        );
                        let fee_tx = Transaction::new_signed_with_payer(
                            &[fee_ix],
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
                        let sig = state.rpc.send_transaction_with_config(&fee_tx, config)
                            .map_err(|e| e.to_string())?;
                        for _ in 0..30 {
                            tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
                            if let Ok(Some(result)) = state.rpc.get_signature_status(&sig) {
                                if result.is_ok() {
                                    info!("Protocol fee collected: {} lamports, tx: {}", fee_amount, sig);
                                    return Ok(());
                                }
                            }
                        }
                        Err("Fee TX confirmation timeout".to_string())
                    }.await;

                    match fee_result {
                        Ok(()) => {
                            distributable = distributable - fee_amount - TX_FEE_LAMPORTS;
                            protocol_fee_deducted = fee_amount + TX_FEE_LAMPORTS;
                            info!("Protocol fee deducted: {} lamports (fee) + {} lamports (gas)", fee_amount, TX_FEE_LAMPORTS);
                        }
                        Err(e) => {
                            warn!("Protocol fee collection failed, skipping: {}", e);
                        }
                    }
                }
            } else {
                info!("Protocol fee too small ({} lamports), skipping", fee_amount);
            }
        }
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

    // Verify math (account for protocol fee if deducted)
    let total_to_send: u64 = amounts.iter().sum();
    if total_to_send + total_fees + protocol_fee_deducted != balance {
        error!("P2P amount calculation mismatch: {} + {} + {} != {}", total_to_send, total_fees, protocol_fee_deducted, balance);
        return Err(MazeError::InsufficientFunds {
            required: total_to_send + total_fees + protocol_fee_deducted,
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
                            warn!("P2P node {} attempt {}/5: Failed to get blockhash: {}", node.index, attempt, e);
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
                                info!("P2P node {} TX succeeded on attempt {}/5", node.index, attempt);
                            }
                            result_sig = Some(s);
                            break;
                        }
                        Err(e) => {
                            let err_str = e.to_string();
                            if err_str.contains("connection") || err_str.contains("timeout") || err_str.contains("closed") {
                                warn!("P2P node {} attempt {}/5: {}", node.index, attempt, err_str);
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
                return Err(MazeError::TransactionError("P2P TX confirmation timeout".into()));
            }

            last_sig = sig.to_string();
            info!("P2P node {} transfer {}/{}: {} lamports to {} ({})",
                node.index, i + 1, num_outputs, transfer_amount, output_idx, last_sig);
        }
    }

    state.db.update_p2p_node_status(transfer_id, node.index, "completed", Some(&last_sig))?;
    info!("P2P node {} completed all {} transfers", node.index, num_outputs);

    Ok(())
}

/// Get P2P transfer status
async fn get_p2p_status(
    State(state): State<Arc<AppState>>,
    Path(transfer_id): Path<String>,
) -> std::result::Result<Json<P2pStatusResponse>, AppError> {
    let transfer = state.db.get_p2p_transfer(&transfer_id)?;

    match transfer {
        Some(t) => {
            let progress = if t.status == "processing" {
                if let Ok((completed, total, current_level, total_levels)) = state.db.get_p2p_maze_progress(&transfer_id) {
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

            Ok(Json(P2pStatusResponse {
                success: true,
                transfer_id,
                status: t.status,
                progress,
                error: t.error_message,
            }))
        }
        None => Ok(Json(P2pStatusResponse {
            success: false,
            transfer_id,
            status: "not_found".to_string(),
            progress: None,
            error: Some("P2P transfer not found".to_string()),
        })),
    }
}


/// Spawn a new pocket funded from an existing pocket via maze routing
async fn spawn_pocket(
    State(state): State<Arc<AppState>>,
    Path(pocket_id): Path<String>,
    Json(req): Json<SpawnPocketRequest>,
) -> std::result::Result<Json<SpawnPocketResponse>, AppError> {
    let owner_meta_hash = hash_meta_address(&req.meta_address);

    // Validate amount
    if req.amount_sol < MIN_AMOUNT_SOL {
        return Err(MazeError::InvalidParameters(format!("Minimum amount is {} SOL", MIN_AMOUNT_SOL)).into());
    }

    // Get source pocket and verify ownership
    let source_pocket = state.db.get_pocket_for_owner(&pocket_id, &owner_meta_hash)?;
    let source_pocket = match source_pocket {
        Some(p) => p,
        None => return Err(MazeError::PocketNotFound(format!("Source pocket not found or access denied: {}", pocket_id)).into()),
    };

    if source_pocket.status != PocketStatus::Active {
        return Err(MazeError::InvalidParameters(format!("Source pocket status is {}, must be active", source_pocket.status.as_str())).into());
    }

    // Get source pocket keypair and check balance
    let keypair_bytes = state.db.decrypt(&source_pocket.keypair_encrypted)?;
    let source_keypair = Keypair::from_bytes(&keypair_bytes)
        .map_err(|e| MazeError::KeypairError(e.to_string()))?;

    let balance = state.rpc.get_balance(&source_keypair.pubkey())
        .map_err(|e| MazeError::RpcError(e.to_string()))?;

    let amount_lamports = sol_to_lamports(req.amount_sol);
    let fee_lamports = (amount_lamports as f64 * FEE_PERCENT / 100.0) as u64;
    let total_needed = amount_lamports + fee_lamports + (TX_FEE_LAMPORTS * 50);

    if balance < total_needed {
        return Err(MazeError::InsufficientFunds {
            required: total_needed,
            available: balance,
        }.into());
    }

    info!("Spawn pocket: {} SOL from {} by {}", req.amount_sol, pocket_id, &req.meta_address[..20.min(req.meta_address.len())]);

    // === Step 1: Create new pocket ===
    let new_pocket_keypair = Keypair::new();
    let new_pocket_pubkey = new_pocket_keypair.pubkey().to_string();
    let new_pocket_id = generate_pocket_id();
    let new_keypair_encrypted = state.db.encrypt(&new_pocket_keypair.to_bytes())?;
    let now = chrono::Utc::now().timestamp();

    let new_pocket = MazePocket {
        id: new_pocket_id.clone(),
        owner_meta_hash: owner_meta_hash.clone(),
        stealth_pubkey: new_pocket_pubkey.clone(),
        keypair_encrypted: new_keypair_encrypted,
        funding_maze_id: None,
        funding_amount_lamports: amount_lamports,
        created_at: now,
        last_sweep_at: None,
        status: PocketStatus::Active,
        label: req.label.clone(),
        archived: false,
        evm_address: None,
        evm_keypair_encrypted: None,
        usepod_token: None,
        usepod_deposit_address: None,
    };

    state.db.create_pocket(&new_pocket)?;

    info!("Spawn pocket: new pocket {} created with address {}", new_pocket_id, new_pocket_pubkey);

    // === Step 2: Generate maze and initiate P2P transfer ===
    let maze_params = parse_maze_config(req.maze_config, state.config.pool_address.clone(), state.config.pool_private_key.clone());
    let generator = MazeGenerator::new(maze_params);
    let encrypt_fn = |data: &[u8]| state.db.encrypt(data);

    let maze = match generator.generate(total_needed, encrypt_fn) {
        Ok(m) => m,
        Err(e) => {
            // Clean up: delete the pocket we just created
            let _ = state.db.delete_pocket(&new_pocket_id, &owner_meta_hash);
            return Err(MazeError::MazeGenerationError(format!("Failed to generate maze: {}", e)).into());
        }
    };

    let transfer_id = format!("p2p_{}", &generate_pocket_id()[7..]);
    let maze_json = serde_json::to_string(&maze).unwrap_or_default();

    // Create P2P transfer record (reuse existing P2P infrastructure)
    let transfer = P2pTransfer {
        id: transfer_id.clone(),
        sender_pocket_id: pocket_id.clone(),
        receiver_pocket_id: new_pocket_id.clone(),
        sender_meta_hash: owner_meta_hash.clone(),
        amount_lamports,
        fee_lamports,
        maze_graph_json: Some(maze_json.clone()),
        status: "pending".to_string(),
        created_at: now,
        completed_at: None,
        error_message: None,
        tx_signature: None,
    };

    state.db.create_p2p_transfer(&transfer)?;

    // Store maze nodes for progress tracking
    for node in &maze.nodes {
        state.db.store_p2p_node(&transfer_id, node)?;
    }

    // Transfer from source pocket to first maze node
    let first_node = &maze.nodes[0];
    let first_node_pubkey = Pubkey::from_str(&first_node.address)
        .map_err(|e| MazeError::InvalidParameters(e.to_string()))?;

    let transfer_to_maze = amount_lamports + fee_lamports + (TX_FEE_LAMPORTS * maze.total_transactions as u64);

    let sig = {
        let mut last_err = String::new();
        let mut result_sig = None;
        for attempt in 1..=5u8 {
            let blockhash = match state.rpc.get_latest_blockhash() {
                Ok(bh) => bh,
                Err(e) => {
                    warn!("Spawn initial attempt {}/5: Failed to get blockhash: {}", attempt, e);
                    last_err = e.to_string();
                    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
                    continue;
                }
            };
            let ix = system_instruction::transfer(
                &source_keypair.pubkey(),
                &first_node_pubkey,
                transfer_to_maze,
            );
            let tx = Transaction::new_signed_with_payer(
                &[ix],
                Some(&source_keypair.pubkey()),
                &[&source_keypair],
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
                        info!("Spawn initial TX succeeded on attempt {}/5", attempt);
                    }
                    result_sig = Some(s);
                    break;
                }
                Err(e) => {
                    let err_str = e.to_string();
                    if err_str.contains("connection") || err_str.contains("timeout") || err_str.contains("closed") {
                        warn!("Spawn initial attempt {}/5: {}", attempt, err_str);
                        last_err = err_str;
                        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
                        continue;
                    }
                    let _ = state.db.update_p2p_status(&transfer_id, "failed", Some(&sanitize_error(&e.to_string())), None);
                    return Err(AppError(MazeError::TransactionError(format!("TX failed: {}", e))));
                }
            }
        }
        match result_sig {
            Some(s) => s,
            None => {
                let _ = state.db.update_p2p_status(&transfer_id, "failed", Some(&sanitize_error(&last_err)), None);
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
                let _ = state.db.update_p2p_status(&transfer_id, "failed", Some(&format!("Initial transfer failed: {:?}", e)), None);
                return Err(AppError(MazeError::TransactionError(format!("Initial transfer failed: {:?}", e))));
            }
        }
    }

    if !confirmed {
        let _ = state.db.update_p2p_status(&transfer_id, "failed", Some("Initial transfer confirmation timeout"), None);
        return Err(AppError(MazeError::TransactionError("Initial transfer confirmation timeout".into())));
    }

    info!("Spawn pocket {} transfer initiated: {} lamports via maze from {}", new_pocket_id, amount_lamports, pocket_id);

    // Execute P2P maze in background (reuse existing P2P maze execution)
    let state_clone = state.clone();
    let transfer_id_clone = transfer_id.clone();
    let receiver_address = new_pocket_pubkey.clone();
    let new_pocket_id_clone = new_pocket_id.clone();
    tokio::spawn(async move {
        match execute_p2p_maze(state_clone.clone(), &transfer_id_clone, &receiver_address).await {
            Ok(_) => {
                info!("Spawn pocket maze completed: {} funded from {}", new_pocket_id_clone, transfer_id_clone);
            }
            Err(e) => {
                error!("Spawn pocket maze failed for {}, starting auto-recover: {}", transfer_id_clone, sanitize_error(&e.to_string()));
                let mut recovered = false;
                if let Ok(maze_json) = state_clone.db.get_p2p_maze_graph(&transfer_id_clone) {
                    if let Ok(maze) = serde_json::from_str::<MazeGraph>(&maze_json) {
                        let amount = auto_recover_nodes_to_destination(
                            state_clone.clone(), &maze.nodes, &receiver_address, &transfer_id_clone, 3
                        ).await;
                        if amount > 0 {
                            info!("Auto-recover spawn {}: recovered {} lamports", transfer_id_clone, amount);
                            let _ = state_clone.db.update_p2p_status(&transfer_id_clone, "completed", None, None);
                            recovered = true;
                        }
                    }
                }
                if !recovered {
                    error!("Auto-recover spawn {} exhausted, marking failed", transfer_id_clone);
                    let _ = state_clone.db.update_p2p_status(&transfer_id_clone, "failed", Some(&sanitize_error(&e.to_string())), None);
                }
            }
        }
    });

    // Log to transaction_log
    let _ = state.db.insert_transaction_log(
        &transfer_id,
        &owner_meta_hash, "spawn_pocket", "completed",
        Some(amount_lamports as i64),
        Some(&format!("{} SOL", lamports_to_sol(amount_lamports))),
        Some(&format!("Spawn pocket {} from {}", new_pocket_id, pocket_id)),
        None,
        None,
    );

    Ok(Json(SpawnPocketResponse {
        success: true,
        new_pocket_id,
        new_pocket_address: new_pocket_pubkey,
        source_pocket_id: pocket_id,
        transfer_id,
        amount_lamports,
        fee_lamports,
        status: "processing".to_string(),
        maze_info: MazeInfo {
            nodes: maze.nodes.len(),
            levels: maze.total_levels,
            estimated_time_seconds: (maze.nodes.len() as u32) * 2,
        },
    }))
}

/// Recover a failed P2P transfer
async fn recover_p2p_transfer(
    State(state): State<Arc<AppState>>,
    Path(transfer_id): Path<String>,
    Json(req): Json<RecoverRequest>,
) -> std::result::Result<Json<RecoverResponse>, AppError> {
    let owner_meta_hash = hash_meta_address(&req.meta_address);

    // Get P2P transfer
    let transfer = state.db.get_p2p_transfer(&transfer_id)?
        .ok_or(MazeError::RequestNotFound(transfer_id.clone()))?;

    // Verify ownership (sender owns the transfer)
    if transfer.sender_meta_hash != owner_meta_hash {
        return Err(MazeError::PocketNotFound("Access denied".into()).into());
    }

    if transfer.status == "completed" {
        return Ok(Json(RecoverResponse {
            success: false,
            message: "P2P transfer already completed".to_string(),
            recovered_lamports: None,
            recovered_sol: None,
            tx_signatures: vec![],
        }));
    }

    // Get receiver pocket address
    let receiver_pocket = state.db.get_pocket(&transfer.receiver_pocket_id)?
        .ok_or(MazeError::PocketNotFound(transfer.receiver_pocket_id.clone()))?;

    let dest_pubkey = Pubkey::from_str(&receiver_pocket.stealth_pubkey)
        .map_err(|e| MazeError::InvalidParameters(e.to_string()))?;

    // Get maze graph
    let maze_json = state.db.get_p2p_maze_graph(&transfer_id)?;
    let maze: MazeGraph = serde_json::from_str(&maze_json)
        .map_err(|e| MazeError::DatabaseError(e.to_string()))?;

    info!("Recovering P2P transfer {} with {} nodes", transfer_id, maze.nodes.len());

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
                            warn!("P2P recover node {} attempt {}/5: Failed to get blockhash: {}", node.index, attempt, e);
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
                                info!("P2P recover node {} TX succeeded on attempt {}/5", node.index, attempt);
                            }
                            last_sig = Some(sig);
                            tx_success = true;
                            break;
                        }
                        Err(e) => {
                            let err_str = e.to_string();
                            if err_str.contains("connection") || err_str.contains("timeout") || err_str.contains("closed") {
                                warn!("P2P recover node {} attempt {}/5: {}", node.index, attempt, err_str);
                                tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
                                continue;
                            }
                            warn!("Failed to recover from P2P node {}: {}", node.index, e);
                            break;
                        }
                    }
                }
                if tx_success {
                    if let Some(sig) = last_sig {
                        info!("P2P recovered {} lamports from node {} ({})", transfer_amount, node.index, sig);
                        total_recovered += transfer_amount;
                        tx_sigs.push(sig.to_string());
                        let _ = state.db.update_p2p_node_status(&transfer_id, node.index, "completed", Some(&sig.to_string()));
                    }
                }
            }
        }
    }

    // Update P2P status if recovered
    if total_recovered > 0 {
        let _ = state.db.update_p2p_status(&transfer_id, "completed", None, None);
        info!("P2P transfer {} recovered: {} lamports", transfer_id, total_recovered);
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

// ============ SEND LINK HANDLERS (KausaLink) ============

/// Create a send link - generate escrow wallet and maze route funds to it
async fn create_send_link(
    State(state): State<Arc<AppState>>,
    Json(req): Json<CreateSendLinkRequest>,
) -> std::result::Result<Json<CreateSendLinkResponse>, AppError> {
    let owner_meta_hash = hash_meta_address(&req.meta_address);

    // Validate amount
    if req.amount_sol < MIN_AMOUNT_SOL {
        return Err(MazeError::InvalidParameters(format!("Minimum amount is {} SOL", MIN_AMOUNT_SOL)).into());
    }

    // Verify pocket ownership
    let sender_pocket = state.db.get_pocket_for_owner(&req.pocket_id, &owner_meta_hash)?
        .ok_or(MazeError::PocketNotFound(format!("Pocket not found or access denied: {}", req.pocket_id)))?;

    if sender_pocket.status != PocketStatus::Active {
        return Err(MazeError::InvalidParameters(format!("Pocket status is {}, must be active", sender_pocket.status.as_str())).into());
    }

    // Decrypt sender pocket keypair and check balance
    let keypair_bytes = state.db.decrypt(&sender_pocket.keypair_encrypted)?;
    let sender_keypair = Keypair::from_bytes(&keypair_bytes)
        .map_err(|e| MazeError::KeypairError(e.to_string()))?;

    let balance = state.rpc.get_balance(&sender_keypair.pubkey())
        .map_err(|e| MazeError::RpcError(e.to_string()))?;

    let amount_lamports = sol_to_lamports(req.amount_sol);
    let fee_lamports = (amount_lamports as f64 * FEE_PERCENT / 100.0) as u64;
    let total_needed = amount_lamports + fee_lamports + (TX_FEE_LAMPORTS * 50);

    if balance < total_needed {
        return Err(MazeError::InsufficientFunds {
            required: total_needed,
            available: balance,
        }.into());
    }

    info!("Creating send link: {} SOL from pocket {}", req.amount_sol, req.pocket_id);

    // Generate escrow wallet
    let escrow_keypair = Keypair::new();
    let escrow_address = escrow_keypair.pubkey().to_string();
    let escrow_keypair_encrypted = state.db.encrypt(&escrow_keypair.to_bytes())?;

    // Generate secret (32 bytes hex = 64 chars)
    let secret_bytes: [u8; 32] = rand::random();
    let secret = hex::encode(secret_bytes);

    // Hash secret for storage (SHA-256)
    let secret_hash = hash_meta_address(&secret);

    // Encrypt secret for recovery
    let secret_encrypted = state.db.encrypt(secret.as_bytes())
        .ok();

    // Generate link ID
    let link_id = format!("link_{}", &generate_pocket_id()[7..]);

    // Generate maze (WITH pool for protocol fee)
    let maze_params = parse_maze_config(None, state.config.pool_address.clone(), state.config.pool_private_key.clone());
    let generator = MazeGenerator::new(maze_params);
    let encrypt_fn = |data: &[u8]| state.db.encrypt(data);

    let maze = match generator.generate(total_needed, encrypt_fn) {
        Ok(m) => m,
        Err(e) => return Err(MazeError::MazeGenerationError(format!("Failed to generate maze: {}", e)).into()),
    };

    let maze_json = serde_json::to_string(&maze).unwrap_or_default();
    let now = chrono::Utc::now().timestamp();
    let expires_at = now + SEND_LINK_EXPIRY_SECONDS;

    // Save send link record
    let send_link = SendLink {
        id: link_id.clone(),
        sender_pocket_id: req.pocket_id.clone(),
        owner_meta_hash: owner_meta_hash.clone(),
        amount_lamports,
        label: req.label.clone(),
        escrow_address: escrow_address.clone(),
        escrow_keypair_encrypted,
        secret_hash,
        secret_encrypted,
        status: "active".to_string(),
        expires_at,
        claimed_by_meta_hash: None,
        claimed_pocket_id: None,
        claimed_at: None,
        refund_tx_signature: None,
        funding_maze_json: Some(maze_json.clone()),
        claim_maze_json: None,
        created_at: now,
    };

    state.db.create_send_link(&send_link)?;

    // Transfer from sender pocket to first maze node
    let first_node = &maze.nodes[0];
    let first_node_pubkey = Pubkey::from_str(&first_node.address)
        .map_err(|e| MazeError::InvalidParameters(e.to_string()))?;

    let transfer_to_maze = amount_lamports + fee_lamports + (TX_FEE_LAMPORTS * maze.total_transactions as u64);

    let sig = {
        let mut last_err = String::new();
        let mut result_sig = None;
        for attempt in 1..=5u8 {
            let blockhash = match state.rpc.get_latest_blockhash() {
                Ok(bh) => bh,
                Err(e) => {
                    warn!("SendLink initial attempt {}/5: Failed to get blockhash: {}", attempt, e);
                    last_err = e.to_string();
                    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
                    continue;
                }
            };
            let ix = system_instruction::transfer(
                &sender_keypair.pubkey(),
                &first_node_pubkey,
                transfer_to_maze,
            );
            let tx = Transaction::new_signed_with_payer(
                &[ix],
                Some(&sender_keypair.pubkey()),
                &[&sender_keypair],
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
                        info!("SendLink initial TX succeeded on attempt {}/5", attempt);
                    }
                    result_sig = Some(s);
                    break;
                }
                Err(e) => {
                    let err_str = e.to_string();
                    if err_str.contains("connection") || err_str.contains("timeout") || err_str.contains("closed") {
                        warn!("SendLink initial attempt {}/5: {}", attempt, err_str);
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
                return Err(AppError(MazeError::TransactionError(format!("Initial transfer failed: {:?}", e))));
            }
        }
    }

    if !confirmed {
        return Err(AppError(MazeError::TransactionError("Initial transfer confirmation timeout".into())));
    }

    info!("SendLink {} initiated: {} lamports via maze to escrow {}", link_id, amount_lamports, escrow_address);

    // Execute maze in background (pocket -> maze -> escrow)
    let state_clone = state.clone();
    let link_id_clone = link_id.clone();
    let escrow_addr = escrow_address.clone();
    tokio::spawn(async move {
        // Reuse sweep maze execution pattern: maze nodes -> final destination (escrow)
        match execute_sendlink_maze(state_clone.clone(), &link_id_clone, &escrow_addr).await {
            Ok(_) => {
                info!("SendLink maze completed for {}", link_id_clone);
            }
            Err(e) => {
                error!("SendLink maze failed for {}: {}", link_id_clone, sanitize_error(&e.to_string()));
                // Auto-recover to escrow
                if let Ok(Some(link)) = state_clone.db.get_send_link(&link_id_clone) {
                    if let Some(ref mj) = link.funding_maze_json {
                        if let Ok(maze) = serde_json::from_str::<MazeGraph>(mj) {
                            let amount = auto_recover_nodes_to_destination(
                                state_clone.clone(), &maze.nodes, &escrow_addr, &link_id_clone, 3
                            ).await;
                            if amount > 0 {
                                info!("Auto-recover SendLink {}: recovered {} lamports", link_id_clone, amount);
                            }
                        }
                    }
                }
            }
        }
    });

    // Log to transaction_log
    let _ = state.db.insert_transaction_log(
        &link_id,
        &owner_meta_hash, "send_link", "completed",
        Some(amount_lamports as i64),
        Some(&format!("{} SOL", lamports_to_sol(amount_lamports))),
        Some(&format!("Send link created: {}", req.label.as_deref().unwrap_or("no label"))),
        None,
        None,
    );

    let link_url = format!("https://kausalayer.com/claim/{}?s={}", link_id, secret);

    Ok(Json(CreateSendLinkResponse {
        success: true,
        link_id,
        link_url,
        amount_lamports,
        expires_at,
    }))
}

/// Execute send link maze routing (pocket -> maze -> escrow)
async fn execute_sendlink_maze(
    state: Arc<AppState>,
    link_id: &str,
    escrow_address: &str,
) -> Result<()> {
    let link = state.db.get_send_link(link_id)?
        .ok_or(MazeError::RequestNotFound(link_id.into()))?;

    let maze_json = link.funding_maze_json
        .ok_or(MazeError::DatabaseError("No maze graph for send link".into()))?;

    let maze: MazeGraph = serde_json::from_str(&maze_json)
        .map_err(|e| MazeError::DatabaseError(e.to_string()))?;

    // Detect pool node level
    let pool_level: Option<u8> = if let Some(ref pool_addr) = state.config.pool_address {
        maze.nodes.iter()
            .find(|n| n.address == *pool_addr)
            .map(|n| n.level)
    } else {
        None
    };

    let mut _pool_guard: Option<tokio::sync::SemaphorePermit<'_>> = None;

    for level in 0..=maze.total_levels {
        if let Some(pl) = pool_level {
            if level == pl && _pool_guard.is_none() {
                info!("SendLink waiting for pool lock ({})", link_id);
                match tokio::time::timeout(
                    tokio::time::Duration::from_secs(180),
                    state.pool_lock.acquire()
                ).await {
                    Ok(Ok(permit)) => {
                        info!("SendLink pool lock acquired ({})", link_id);
                        _pool_guard = Some(permit);
                    }
                    Ok(Err(_)) => return Err(MazeError::TransactionError("Pool semaphore closed".into())),
                    Err(_) => return Err(MazeError::TransactionError("Pool busy, timeout after 180s".into())),
                }
            }
        }

        let nodes_at_level: Vec<&MazeNode> = maze.nodes.iter()
            .filter(|n| n.level == level)
            .collect();

        for node in nodes_at_level {
            execute_sweep_node(state.clone(), link_id, node, &maze, escrow_address).await?;

            let delay_ms = calculate_delay(&maze.parameters, node.level);
            if delay_ms > 0 {
                tokio::time::sleep(tokio::time::Duration::from_millis(delay_ms)).await;
            }
        }
    }

    drop(_pool_guard);
    info!("SendLink maze completed for {}", link_id);
    Ok(())
}

/// Get send link info (public, no auth)
async fn get_send_link_info(
    State(state): State<Arc<AppState>>,
    Path(link_id): Path<String>,
    Query(query): Query<SendLinkInfoQuery>,
) -> std::result::Result<Json<SendLinkInfoResponse>, AppError> {
    let link = state.db.get_send_link(&link_id)?;

    match link {
        Some(link) => {
            // Constant-time secret comparison
            let provided_hash = hash_meta_address(&query.s);
            if provided_hash != link.secret_hash {
                return Ok(Json(SendLinkInfoResponse {
                    success: false,
                    amount_sol: 0.0,
                    label: None,
                    status: "invalid".to_string(),
                    created_at: 0,
                }));
            }

            Ok(Json(SendLinkInfoResponse {
                success: true,
                amount_sol: lamports_to_sol(link.amount_lamports),
                label: link.label,
                status: link.status,
                created_at: link.created_at,
            }))
        }
        None => Ok(Json(SendLinkInfoResponse {
            success: false,
            amount_sol: 0.0,
            label: None,
            status: "not_found".to_string(),
            created_at: 0,
        })),
    }
}

/// Claim a send link (public, no auth - creates new pocket for recipient)
async fn claim_send_link(
    State(state): State<Arc<AppState>>,
    Path(link_id): Path<String>,
    Json(req): Json<ClaimSendLinkRequest>,
) -> std::result::Result<Json<ClaimSendLinkResponse>, AppError> {
    // Get send link
    let link = state.db.get_send_link(&link_id)?
        .ok_or(MazeError::RequestNotFound(link_id.clone()))?;

    // Validate secret
    let provided_hash = hash_meta_address(&req.secret);
    if provided_hash != link.secret_hash {
        return Ok(Json(ClaimSendLinkResponse {
            success: false,
            pocket_id: None,
            meta_address: None,
            amount_sol: 0.0,
            message: "Invalid secret".to_string(),
        }));
    }

    // Validate status
    if link.status != "active" {
        return Ok(Json(ClaimSendLinkResponse {
            success: false,
            pocket_id: None,
            meta_address: None,
            amount_sol: 0.0,
            message: format!("Link status is '{}', cannot claim", link.status),
        }));
    }

    // Check expiry
    let now = chrono::Utc::now().timestamp();
    if now > link.expires_at {
        return Ok(Json(ClaimSendLinkResponse {
            success: false,
            pocket_id: None,
            meta_address: None,
            amount_sol: 0.0,
            message: "Link has expired".to_string(),
        }));
    }

    // Validate wallet address
    let _wallet_pubkey = Pubkey::from_str(&req.wallet_address)
        .map_err(|_| MazeError::InvalidParameters("Invalid wallet address".into()))?;

    // Use meta_address derived by frontend (same derivation as ConnectWallet)
    // The "message" field now contains the frontend-derived meta_address string
    let claimer_meta = req.message.clone();
    let claimer_meta_hash = hash_meta_address(&claimer_meta);

    info!("Claiming send link {}: creating pocket for {}", link_id, &req.wallet_address[..20.min(req.wallet_address.len())]);

    // Create new pocket for recipient
    let pocket_keypair = Keypair::new();
    let pocket_pubkey = pocket_keypair.pubkey().to_string();
    let pocket_id = generate_pocket_id();
    let keypair_encrypted = state.db.encrypt(&pocket_keypair.to_bytes())?;

    let pocket = MazePocket {
        id: pocket_id.clone(),
        owner_meta_hash: claimer_meta_hash.clone(),
        stealth_pubkey: pocket_pubkey.clone(),
        keypair_encrypted,
        funding_maze_id: None,
        funding_amount_lamports: link.amount_lamports,
        created_at: now,
        last_sweep_at: None,
        status: PocketStatus::Active,
        label: link.label.clone(),
        archived: false,
        evm_address: None,
        evm_keypair_encrypted: None,
        usepod_token: None,
        usepod_deposit_address: None,
    };

    state.db.create_pocket(&pocket)?;

    // Decrypt escrow keypair
    let escrow_bytes = state.db.decrypt(&link.escrow_keypair_encrypted)?;
    let escrow_keypair = Keypair::from_bytes(&escrow_bytes)
        .map_err(|e| MazeError::KeypairError(e.to_string()))?;

    // Check escrow balance
    let escrow_balance = state.rpc.get_balance(&escrow_keypair.pubkey())
        .map_err(|e| MazeError::RpcError(e.to_string()))?;

    if escrow_balance <= TX_FEE_LAMPORTS * 20 {
        return Ok(Json(ClaimSendLinkResponse {
            success: false,
            pocket_id: None,
            meta_address: None,
            amount_sol: 0.0,
            message: "Escrow has insufficient funds. Link may still be processing.".to_string(),
        }));
    }

    // Generate maze WITHOUT pool (no protocol fee on claim)
    let maze_params = parse_maze_config(None, None, None);
    let generator = MazeGenerator::new(maze_params);
    let sweep_amount = escrow_balance.saturating_sub(TX_FEE_LAMPORTS);
    let encrypt_fn = |data: &[u8]| state.db.encrypt(data);

    let maze = match generator.generate(sweep_amount, encrypt_fn) {
        Ok(m) => m,
        Err(e) => {
            return Ok(Json(ClaimSendLinkResponse {
                success: false,
                pocket_id: None,
                meta_address: None,
                amount_sol: 0.0,
                message: format!("Failed to generate claim maze: {}", e),
            }));
        }
    };

    let claim_maze_json = serde_json::to_string(&maze).unwrap_or_default();

    // Transfer from escrow to first maze node
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
                    warn!("Claim initial attempt {}/5: Failed to get blockhash: {}", attempt, e);
                    last_err = e.to_string();
                    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
                    continue;
                }
            };
            let ix = system_instruction::transfer(
                &escrow_keypair.pubkey(),
                &first_node_pubkey,
                sweep_amount,
            );
            let tx = Transaction::new_signed_with_payer(
                &[ix],
                Some(&escrow_keypair.pubkey()),
                &[&escrow_keypair],
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
                        info!("Claim initial TX succeeded on attempt {}/5", attempt);
                    }
                    result_sig = Some(s);
                    break;
                }
                Err(e) => {
                    let err_str = e.to_string();
                    if err_str.contains("connection") || err_str.contains("timeout") || err_str.contains("closed") {
                        warn!("Claim initial attempt {}/5: {}", attempt, err_str);
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
            }
        }
    }

    if !confirmed {
        return Err(AppError(MazeError::TransactionError("Claim initial transfer confirmation timeout".into())));
    }

    // Mark as claimed
    state.db.update_send_link_claimed(&link_id, &claimer_meta_hash, &pocket_id, &claim_maze_json)?;

    info!("SendLink {} claimed: pocket {} for {}", link_id, pocket_id, &req.wallet_address[..20.min(req.wallet_address.len())]);

    // Execute claim maze in background (escrow -> maze -> new pocket)
    let state_clone = state.clone();
    let link_id_clone = link_id.clone();
    let pocket_pubkey_clone = pocket_pubkey.clone();
    let claim_maze_json_clone = claim_maze_json.clone();
    tokio::spawn(async move {
        match execute_sendlink_claim_maze(state_clone.clone(), &link_id_clone, &pocket_pubkey_clone, &claim_maze_json_clone).await {
            Ok(_) => {
                info!("SendLink claim maze completed for {}", link_id_clone);
            }
            Err(e) => {
                error!("SendLink claim maze failed for {}: {}", link_id_clone, sanitize_error(&e.to_string()));
                // Auto-recover to new pocket
                if let Ok(maze) = serde_json::from_str::<MazeGraph>(&claim_maze_json_clone) {
                    let amount = auto_recover_nodes_to_destination(
                        state_clone.clone(), &maze.nodes, &pocket_pubkey_clone, &link_id_clone, 3
                    ).await;
                    if amount > 0 {
                        info!("Auto-recover claim {}: recovered {} lamports", link_id_clone, amount);
                    }
                }
            }
        }
    });

    // Log to transaction_log
    let _ = state.db.insert_transaction_log(
        &link_id,
        &claimer_meta_hash, "send_link_claim", "completed",
        Some(link.amount_lamports as i64),
        Some(&format!("{} SOL", lamports_to_sol(link.amount_lamports))),
        Some(&format!("Send link claimed: {}", link_id)),
        None,
        None,
    );

    Ok(Json(ClaimSendLinkResponse {
        success: true,
        pocket_id: Some(pocket_id),
        meta_address: Some(claimer_meta),
        amount_sol: lamports_to_sol(link.amount_lamports),
        message: "Link claimed successfully. Pocket created with funds.".to_string(),
    }))
}

/// Execute claim maze routing (escrow -> maze -> new pocket) - NO pool, no protocol fee
async fn execute_sendlink_claim_maze(
    state: Arc<AppState>,
    link_id: &str,
    pocket_address: &str,
    maze_json: &str,
) -> Result<()> {
    let maze: MazeGraph = serde_json::from_str(maze_json)
        .map_err(|e| MazeError::DatabaseError(e.to_string()))?;

    // No pool lock needed - claim maze has no pool node
    for level in 0..=maze.total_levels {
        let nodes_at_level: Vec<&MazeNode> = maze.nodes.iter()
            .filter(|n| n.level == level)
            .collect();

        for node in nodes_at_level {
            execute_sweep_node(state.clone(), link_id, node, &maze, pocket_address).await?;

            let delay_ms = calculate_delay(&maze.parameters, node.level);
            if delay_ms > 0 {
                tokio::time::sleep(tokio::time::Duration::from_millis(delay_ms)).await;
            }
        }
    }

    info!("SendLink claim maze completed for {}", link_id);
    Ok(())
}

/// List send links for a user
async fn list_send_links(
    State(state): State<Arc<AppState>>,
    Query(query): Query<ListSendLinksQuery>,
) -> std::result::Result<Json<ListSendLinksResponse>, AppError> {
    let owner_meta_hash = hash_meta_address(&query.meta_address);

    let links = state.db.list_send_links(&owner_meta_hash)?;

    let link_entries: Vec<SendLinkEntry> = links.iter().map(|l| {
        let link_url = if l.status == "active" {
            l.secret_encrypted.as_ref().and_then(|enc| {
                state.db.decrypt(enc).ok().and_then(|bytes| {
                    String::from_utf8(bytes).ok().map(|secret| {
                        format!("https://kausalayer.com/claim/{}?s={}", l.id, secret)
                    })
                })
            })
        } else {
            None
        };
        SendLinkEntry {
            id: l.id.clone(),
            amount_sol: lamports_to_sol(l.amount_lamports),
            label: l.label.clone(),
            status: l.status.clone(),
            created_at: l.created_at,
            expires_at: l.expires_at,
            claimed_at: l.claimed_at,
            link_url,
        }
    }).collect();

    let count = link_entries.len();

    Ok(Json(ListSendLinksResponse {
        success: true,
        links: link_entries,
        count,
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
                            error!("Maze execution failed for {}, starting auto-recover: {}", req_id, sanitize_error(&e.to_string()));
                            // Auto-recover: get maze graph and pocket destination, then recover silently
                            let mut recovered = false;
                            if let Ok(maze_json) = state_clone.db.get_maze_graph(&req_id) {
                                if let Ok(maze) = serde_json::from_str::<MazeGraph>(&maze_json) {
                                    // Determine destination: pocket stealth_pubkey
                                    if let Ok(Some(funding_req)) = state_clone.db.get_funding_request(&req_id) {
                                        if let Ok(Some(pocket)) = state_clone.db.get_pocket(&funding_req.pocket_id) {
                                            let dest = pocket.stealth_pubkey.clone();
                                            let amount = auto_recover_nodes_to_destination(
                                                state_clone.clone(), &maze.nodes, &dest, &req_id, 3
                                            ).await;
                                            if amount > 0 {
                                                info!("Auto-recover funding {}: recovered {} lamports", req_id, amount);
                                                let _ = state_clone.db.update_funding_status(&req_id, "completed", None);
                                                recovered = true;
                                            }
                                        }
                                    }
                                }
                            }
                            if !recovered {
                                error!("Auto-recover funding {} exhausted, marking failed", req_id);
                                let _ = state_clone.db.update_funding_status(&req_id, "failed", Some(&sanitize_error(&e.to_string())));
                            }
                        }
                    }
                });
            }
        }

        // === KausaLink: Check expired send links and refund ===
        if let Ok(expired_links) = state.db.get_expired_send_links() {
            for link in expired_links {
                // Decrypt escrow keypair
                let escrow_bytes = match state.db.decrypt(&link.escrow_keypair_encrypted) {
                    Ok(b) => b,
                    Err(e) => {
                        warn!("SendLink refund: decrypt failed for {}: {}", link.id, e);
                        let _ = state.db.update_send_link_expired(&link.id);
                        continue;
                    }
                };
                let escrow_keypair = match Keypair::from_bytes(&escrow_bytes) {
                    Ok(k) => k,
                    Err(e) => {
                        warn!("SendLink refund: keypair error for {}: {}", link.id, e);
                        let _ = state.db.update_send_link_expired(&link.id);
                        continue;
                    }
                };

                // Check escrow balance
                let balance = match state.rpc.get_balance(&escrow_keypair.pubkey()) {
                    Ok(b) => b,
                    Err(_) => {
                        continue; // Will retry next iteration
                    }
                };

                if balance <= TX_FEE_LAMPORTS {
                    // No funds to refund
                    let _ = state.db.update_send_link_expired(&link.id);
                    info!("SendLink {} expired, no balance to refund", link.id);
                    continue;
                }

                // Get sender pocket address for refund
                let sender_pocket = match state.db.get_pocket(&link.sender_pocket_id) {
                    Ok(Some(p)) => p,
                    _ => {
                        warn!("SendLink refund: sender pocket {} not found for {}", link.sender_pocket_id, link.id);
                        let _ = state.db.update_send_link_expired(&link.id);
                        continue;
                    }
                };

                let dest_pubkey = match Pubkey::from_str(&sender_pocket.stealth_pubkey) {
                    Ok(p) => p,
                    Err(_) => {
                        let _ = state.db.update_send_link_expired(&link.id);
                        continue;
                    }
                };

                // Direct refund (no maze routing - saves fees)
                let transfer_amount = balance.saturating_sub(TX_FEE_LAMPORTS);
                if transfer_amount == 0 {
                    let _ = state.db.update_send_link_expired(&link.id);
                    continue;
                }

                let refund_result: std::result::Result<String, String> = async {
                    let blockhash = state.rpc.get_latest_blockhash()
                        .map_err(|e| e.to_string())?;
                    let ix = system_instruction::transfer(
                        &escrow_keypair.pubkey(),
                        &dest_pubkey,
                        transfer_amount,
                    );
                    let tx = Transaction::new_signed_with_payer(
                        &[ix],
                        Some(&escrow_keypair.pubkey()),
                        &[&escrow_keypair],
                        blockhash,
                    );
                    let config = RpcSendTransactionConfig {
                        skip_preflight: true,
                        preflight_commitment: None,
                        encoding: None,
                        max_retries: Some(3),
                        min_context_slot: None,
                    };
                    let sig = state.rpc.send_transaction_with_config(&tx, config)
                        .map_err(|e| e.to_string())?;
                    // Wait for confirmation
                    for _ in 0..30 {
                        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
                        if let Ok(Some(result)) = state.rpc.get_signature_status(&sig) {
                            if result.is_ok() {
                                return Ok(sig.to_string());
                            }
                        }
                    }
                    Err("Refund TX confirmation timeout".to_string())
                }.await;

                match refund_result {
                    Ok(sig) => {
                        let _ = state.db.update_send_link_refunded(&link.id, &sig);
                        info!("SendLink {} refunded: {} lamports to sender pocket ({})", link.id, transfer_amount, sig);
                        // Log to transaction_log
                        let _ = state.db.insert_transaction_log(
                            &format!("refund_{}", chrono::Utc::now().timestamp_millis()),
                            &link.owner_meta_hash, "send_link_refund", "completed",
                            Some(transfer_amount as i64),
                            Some(&format!("{} SOL", lamports_to_sol(transfer_amount))),
                            Some(&format!("Send link expired, refunded: {}", link.id)),
                            Some(&sig),
                            None,
                        );
                    }
                    Err(e) => {
                        warn!("SendLink {} refund failed: {}", link.id, e);
                        // Will retry next iteration
                    }
                }
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

    let maze_params = parse_maze_config(req.maze_config, state.config.pool_address.clone(), state.config.pool_private_key.clone());
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
                    error!("Sweep all: maze failed for {}, starting auto-recover: {}", pocket_id_clone, sanitize_error(&e.to_string()));
                    // Auto-recover: get sweep maze and destination, recover silently
                    let mut recovered = false;
                    if let Ok(Some(sweep_req)) = state_clone.db.get_sweep_request(&sweep_id_clone) {
                        let destination = sweep_req.2.clone();
                        if let Ok(maze_json) = state_clone.db.get_sweep_maze_graph(&sweep_id_clone) {
                            if let Ok(maze) = serde_json::from_str::<MazeGraph>(&maze_json) {
                                let amount = auto_recover_nodes_to_destination(
                                    state_clone.clone(), &maze.nodes, &destination, &sweep_id_clone, 3
                                ).await;
                                if amount > 0 {
                                    info!("Auto-recover sweep-all {}: recovered {} lamports", sweep_id_clone, amount);
                                    let _ = state_clone.db.update_sweep_status(&sweep_id_clone, "completed", None, None);
                                    let _ = state_clone.db.mark_pocket_swept(&pocket_id_clone);
                                    recovered = true;
                                }
                            }
                        }
                    }
                    if !recovered {
                        error!("Auto-recover sweep-all {} exhausted, marking failed", sweep_id_clone);
                        let _ = state_clone.db.update_pocket_status(&pocket_id_clone, PocketStatus::Active);
                        let _ = state_clone.db.update_sweep_status(&sweep_id_clone, "failed", None, Some(&sanitize_error(&e.to_string())));
                    }
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


// ============ TOKEN BALANCE HANDLER ============

#[derive(Debug, Deserialize)]
struct TokenBalancesQuery {
    meta_address: String,
}

#[derive(Debug, Serialize)]
struct TokenBalancesResponse {
    success: bool,
    pocket_id: String,
    sol_balance: f64,
    tokens: Vec<swap::TokenBalance>,
    error: Option<String>,
}

async fn token_balances_handler(
    State(state): State<Arc<AppState>>,
    Path(pocket_id): Path<String>,
    Query(query): Query<TokenBalancesQuery>,
) -> std::result::Result<Json<TokenBalancesResponse>, AppError> {
    let owner_meta_hash = hash_meta_address(&query.meta_address);

    let pocket = state.db.get_pocket_for_owner(&pocket_id, &owner_meta_hash)?
        .ok_or(MazeError::PocketNotFound(pocket_id.clone()))?;

    let pocket_pubkey = Pubkey::from_str(&pocket.stealth_pubkey)
        .map_err(|e| MazeError::InvalidParameters(e.to_string()))?;

    // Get SOL balance
    let sol_balance = state.rpc.get_balance(&pocket_pubkey).unwrap_or(0);

    // Scan token balances (SPL Token + Token-2022)
    let raw_balances = swap::scan_token_balances(&state.rpc, &pocket_pubkey);

    // Resolve metadata for each token
    let mut token_balances: Vec<swap::TokenBalance> = Vec::new();
    for (mint, amount, program) in raw_balances {
        // Try curated list first
        let token_info = match tokens::resolve_token(&mint) {
            Some(t) if t.symbol != "UNKNOWN" => {
                // If logo_uri missing, try DexScreener for logo
                if t.logo_uri.is_none() {
                    match swap::resolve_token_dexscreener(&state.http_client, &t.mint).await {
                        Some(resolved) if resolved.logo_uri.is_some() => tokens::TokenInfo {
                            logo_uri: resolved.logo_uri,
                            ..t
                        },
                        _ => t,
                    }
                } else {
                    t
                }
            },
            _ => {
                // Try DexScreener
                match swap::resolve_token_dexscreener(&state.http_client, &mint).await {
                    Some(t) => t,
                    None => tokens::TokenInfo {
                        symbol: format!("{}...{}", &mint[..4], &mint[mint.len()-4..]),
                        name: "Unknown Token".to_string(),
                        mint: mint.clone(),
                        decimals: 6,
                        logo_uri: None,
                    },
                }
            }
        };

        let decimals = token_info.decimals;
        let balance_formatted = amount as f64 / 10f64.powi(decimals as i32);

        token_balances.push(swap::TokenBalance {
            mint: token_info.mint,
            symbol: token_info.symbol,
            name: token_info.name,
            decimals,
            balance_raw: amount,
            balance_formatted,
            token_program: program,
            logo_uri: token_info.logo_uri,
        });
    }

    Ok(Json(TokenBalancesResponse {
        success: true,
        pocket_id,
        sol_balance: lamports_to_sol(sol_balance),
        tokens: token_balances,
        error: None,
    }))
}
// ============ SWAP HANDLERS ============

#[derive(Debug, Deserialize)]
struct SwapQuoteQuery {
    meta_address: String,
    output_token: String,
    amount_sol: f64,
    slippage_bps: Option<u16>,
    input_token: Option<String>,
    amount_raw: Option<u64>,
}

#[derive(Debug, Serialize)]
struct SwapQuoteApiResponse {
    success: bool,
    quote: Option<SwapQuoteResponse>,
    output_token: Option<TokenInfo>,
    error: Option<String>,
}

/// Get swap quote for a pocket
async fn swap_quote_handler(
    State(state): State<Arc<AppState>>,
    Path(pocket_id): Path<String>,
    Query(query): Query<SwapQuoteQuery>,
) -> std::result::Result<Json<SwapQuoteApiResponse>, AppError> {
    let owner_meta_hash = hash_meta_address(&query.meta_address);

    // Verify pocket ownership
    let pocket = state.db.get_pocket_for_owner(&pocket_id, &owner_meta_hash)?
        .ok_or(MazeError::PocketNotFound(pocket_id.clone()))?;

    if pocket.status != PocketStatus::Active {
        return Ok(Json(SwapQuoteApiResponse {
            success: false,
            quote: None,
            output_token: None,
            error: Some(format!("Pocket status is {}, must be active", pocket.status.as_str())),
        }));
    }

    // Determine swap direction
    if let Some(ref input_tok) = query.input_token {
        // Token -> SOL direction
        let input_token = match tokens::resolve_token(input_tok) {
            Some(t) if t.symbol != "UNKNOWN" => t,
            Some(t) => {
                match swap::resolve_token_dexscreener(&state.http_client, &t.mint).await {
                    Some(resolved) => resolved,
                    None => t,
                }
            }
            None => return Ok(Json(SwapQuoteApiResponse {
                success: false,
                quote: None,
                output_token: None,
                error: Some(format!("Input token not found: {}", input_tok)),
            })),
        };
        let amount = query.amount_raw.unwrap_or(0);
        if amount == 0 {
            return Ok(Json(SwapQuoteApiResponse {
                success: false,
                quote: None,
                output_token: None,
                error: Some("amount_raw must be greater than 0 for token->SOL".into()),
            }));
        }
        let quote_req = SwapQuoteRequest {
            input_mint: input_token.mint.clone(),
            output_mint: tokens::SOL_MINT.to_string(),
            amount,
            taker: pocket.stealth_pubkey.clone(),
            slippage_bps: query.slippage_bps,
        };
        let quote = swap::get_swap_quote(&state.http_client, &quote_req).await
            .map_err(|e| AppError(e))?;
        let sol_token = TokenInfo {
            symbol: "SOL".to_string(),
            name: "Solana".to_string(),
            mint: tokens::SOL_MINT.to_string(),
            decimals: 9,
            logo_uri: None,
        };
        return Ok(Json(SwapQuoteApiResponse {
            success: true,
            quote: Some(quote),
            output_token: Some(sol_token),
            error: None,
        }));
    }

    // SOL -> Token direction (existing logic)
    // Resolve output token (curated list first, then DexScreener for unknown CAs)
    let output_token = match tokens::resolve_token(&query.output_token) {
        Some(t) if t.symbol != "UNKNOWN" => t,
        Some(t) => {
            match swap::resolve_token_dexscreener(&state.http_client, &t.mint).await {
                Some(resolved) => resolved,
                None => t,
            }
        }
        None => return Ok(Json(SwapQuoteApiResponse {
            success: false,
            quote: None,
            output_token: None,
            error: Some(format!("Token not found: {}. Use symbol (BONK, USDC) or contract address.", query.output_token)),
        })),
    };
    let amount_lamports = sol_to_lamports(query.amount_sol);
    if amount_lamports == 0 {
        return Ok(Json(SwapQuoteApiResponse {
            success: false,
            quote: None,
            output_token: None,
            error: Some("Amount must be greater than 0".into()),
        }));
    }

    // Fetch quote from Jupiter
    let quote_req = SwapQuoteRequest {
        input_mint: tokens::SOL_MINT.to_string(),
        output_mint: output_token.mint.clone(),
        amount: amount_lamports,
        taker: pocket.stealth_pubkey.clone(),
        slippage_bps: query.slippage_bps,
    };

    let quote = swap::get_swap_quote(&state.http_client, &quote_req).await
        .map_err(|e| AppError(e))?;

    Ok(Json(SwapQuoteApiResponse {
        success: true,
        quote: Some(quote),
        output_token: Some(output_token),
        error: None,
    }))
}

#[derive(Debug, Deserialize)]
struct SwapExecuteRequest {
    meta_address: String,
    output_token: String,
    amount_sol: f64,
    slippage_bps: Option<u16>,
    input_token: Option<String>,
    amount_raw: Option<u64>,
}

#[derive(Debug, Serialize)]
struct SwapExecuteResponse {
    success: bool,
    swap_result: Option<SwapResult>,
    output_token: Option<TokenInfo>,
    error: Option<String>,
}

/// Execute a swap from a pocket
async fn swap_execute_handler(
    State(state): State<Arc<AppState>>,
    Path(pocket_id): Path<String>,
    Json(req): Json<SwapExecuteRequest>,
) -> std::result::Result<Json<SwapExecuteResponse>, AppError> {
    let owner_meta_hash = hash_meta_address(&req.meta_address);

    // Verify pocket ownership
    let pocket = state.db.get_pocket_for_owner(&pocket_id, &owner_meta_hash)?
        .ok_or(MazeError::PocketNotFound(pocket_id.clone()))?;

    if pocket.status != PocketStatus::Active {
        return Ok(Json(SwapExecuteResponse {
            success: false,
            swap_result: None,
            output_token: None,
            error: Some(format!("Pocket status is {}, must be active", pocket.status.as_str())),
        }));
    }

    // Resolve output token (curated list first, then DexScreener for unknown CAs)
    let output_token = match tokens::resolve_token(&req.output_token) {
        Some(t) if t.symbol != "UNKNOWN" => t,
        Some(t) => {
            match swap::resolve_token_dexscreener(&state.http_client, &t.mint).await {
                Some(resolved) => resolved,
                None => t,
            }
        }
        None => return Ok(Json(SwapExecuteResponse {
            success: false,
            swap_result: None,
            output_token: None,
            error: Some(format!("Token not found: {}", req.output_token)),
        })),
    };

    let amount_lamports = sol_to_lamports(req.amount_sol);
    let sell_amount_raw = req.amount_raw.unwrap_or(0);
    if amount_lamports == 0 && sell_amount_raw == 0 {
        return Ok(Json(SwapExecuteResponse {
            success: false,
            swap_result: None,
            output_token: None,
            error: Some("Amount must be greater than 0".into()),
        }));
    }

    // Check pocket balance
    let keypair_bytes = state.db.decrypt(&pocket.keypair_encrypted)?;
    let pocket_keypair = Keypair::from_bytes(&keypair_bytes)
        .map_err(|e| MazeError::KeypairError(e.to_string()))?;

    let balance = state.rpc.get_balance(&pocket_keypair.pubkey())
        .map_err(|e| MazeError::RpcError(e.to_string()))?;

    // Balance check depends on direction
    let buffer = 3_000_000; // 0.003 SOL buffer for tx fees + priority fees + rent
    if req.input_token.is_none() {
        // Buy (SOL -> Token): need SOL for swap amount + fees
        if balance < amount_lamports + buffer {
            return Ok(Json(SwapExecuteResponse {
                success: false,
                swap_result: None,
                output_token: None,
                error: Some(format!(
                    "Insufficient balance. Need {} SOL + fees, have {} SOL",
                    lamports_to_sol(amount_lamports),
                    lamports_to_sol(balance)
                )),
            }));
        }
    } else {
        // Sell (Token -> SOL): only need SOL for tx fees
        if balance < buffer {
            return Ok(Json(SwapExecuteResponse {
                success: false,
                swap_result: None,
                output_token: None,
                error: Some(format!(
                    "Insufficient SOL for transaction fees. Need ~0.003 SOL, have {} SOL",
                    lamports_to_sol(balance)
                )),
            }));
        }
    }
    // Determine swap direction
    let (swap_input_mint, swap_output_mint, swap_amount) = if let Some(ref input_tok) = req.input_token {
        // Token -> SOL (sell)
        let input_info = match tokens::resolve_token(input_tok) {
            Some(t) if t.symbol != "UNKNOWN" => t,
            Some(t) => {
                match swap::resolve_token_dexscreener(&state.http_client, &t.mint).await {
                    Some(resolved) => resolved,
                    None => t,
                }
            }
            None => return Ok(Json(SwapExecuteResponse {
                success: false,
                swap_result: None,
                output_token: None,
                error: Some(format!("Input token not found: {}", input_tok)),
            })),
        };
        let amt = req.amount_raw.unwrap_or(sol_to_lamports(req.amount_sol));
        info!("Swap execute: pocket {} selling {} {} -> SOL", pocket_id, amt, input_info.symbol);
        (input_info.mint.clone(), tokens::SOL_MINT.to_string(), amt)
    } else {
        // SOL -> Token (buy)
        info!("Swap execute: pocket {} buying {} SOL -> {}", pocket_id, req.amount_sol, output_token.symbol);
        (tokens::SOL_MINT.to_string(), output_token.mint.clone(), amount_lamports)
    };
    // Execute swap via Jupiter Ultra
    let result = swap::execute_swap(
        &state.http_client,
        &state.rpc,
        &pocket_keypair,
        &swap_input_mint,
        &swap_output_mint,
        swap_amount,
        req.slippage_bps,
    ).await.map_err(|e| AppError(e))?;

    let success = result.success;
    info!("Swap result for pocket {}: success={}", pocket_id, success);

    // Log to transaction_log
    if success {
        let swap_desc = if req.input_token.is_some() {
            format!("Sell {} -> SOL", req.output_token)
        } else {
            format!("Buy SOL -> {}", req.output_token)
        };
        let _ = state.db.insert_transaction_log(
            &format!("swap_{}", chrono::Utc::now().timestamp_millis()),
            &owner_meta_hash, "swap", "completed",
            Some(swap_amount as i64),
            Some(&format!("{} SOL", lamports_to_sol(swap_amount))),
            Some(&swap_desc),
            result.tx_signature.as_deref(),
            None,
        );
    }

    Ok(Json(SwapExecuteResponse {
        success,
        swap_result: Some(result),
        output_token: Some(output_token),
        error: None,
    }))
}

/// Get curated token list
async fn token_list_handler() -> Json<serde_json::Value> {
    let tokens_list = tokens::get_token_list();
    Json(serde_json::json!({
        "success": true,
        "tokens": tokens_list,
        "count": tokens_list.len(),
    }))
}

/// Resolve a token query
#[derive(Debug, Deserialize)]
struct TokenResolveQuery {
    query: String,
}

async fn token_resolve_handler(
    State(state): State<Arc<AppState>>,
    Query(q): Query<TokenResolveQuery>,
) -> Json<serde_json::Value> {
    match tokens::resolve_token(&q.query) {
        Some(t) if t.symbol != "UNKNOWN" => {
            // If logo_uri is missing, try DexScreener for logo only
            let token = if t.logo_uri.is_none() {
                match swap::resolve_token_dexscreener(&state.http_client, &t.mint).await {
                    Some(resolved) if resolved.logo_uri.is_some() => tokens::TokenInfo {
                        logo_uri: resolved.logo_uri,
                        ..t
                    },
                    _ => t,
                }
            } else {
                t
            };
            Json(serde_json::json!({
                "success": true,
                "token": token,
            }))
        },
        Some(t) => {
            // Unknown CA — try DexScreener
            match swap::resolve_token_dexscreener(&state.http_client, &t.mint).await {
                Some(resolved) => Json(serde_json::json!({
                    "success": true,
                    "token": resolved,
                })),
                None => Json(serde_json::json!({
                    "success": true,
                    "token": t,
                })),
            }
        }
        None => Json(serde_json::json!({
            "success": false,
            "error": format!("Token not found: {}", q.query),
        })),
    }
}

// ============ PRINTR TOKEN CREATION HANDLERS ============

#[derive(Debug, Deserialize)]
struct PocketPrintrCreateRequest {
    meta_address: String,
    name: String,
    symbol: String,
    description: Option<String>,
    image_url: Option<String>,
    image_path: Option<String>,
    chains: Option<Vec<String>>,
    initial_supply: Option<u64>,
    decimals: Option<u8>,
}

#[derive(Debug, Serialize)]
struct PocketPrintrCreateResponse {
    success: bool,
    pocket_id: String,
    token_id: Option<String>,
    mint_address: Option<String>,
    tx_signature: Option<String>,
    deployments: Vec<printr::ChainDeployment>,
    error: Option<String>,
}

/// Create a token from a pocket via Printr
async fn printr_create_handler(
    State(state): State<Arc<AppState>>,
    Path(pocket_id): Path<String>,
    Json(req): Json<PocketPrintrCreateRequest>,
) -> std::result::Result<Json<PocketPrintrCreateResponse>, AppError> {
    let owner_meta_hash = hash_meta_address(&req.meta_address);

    let pocket = state.db.get_pocket_for_owner(&pocket_id, &owner_meta_hash)?
        .ok_or(MazeError::PocketNotFound(pocket_id.clone()))?;

    if pocket.status != PocketStatus::Active {
        return Ok(Json(PocketPrintrCreateResponse {
            success: false,
            pocket_id,
            token_id: None,
            mint_address: None,
            tx_signature: None,
            deployments: vec![],
            error: Some(format!("Pocket status is {}, must be active", pocket.status.as_str())),
        }));
    }

    let keypair_bytes = state.db.decrypt(&pocket.keypair_encrypted)?;
    let pocket_keypair = Keypair::from_bytes(&keypair_bytes)
        .map_err(|e| MazeError::KeypairError(e.to_string()))?;

    let balance = state.rpc.get_balance(&pocket_keypair.pubkey())
        .map_err(|e| MazeError::RpcError(e.to_string()))?;

    let buffer = 5_000_000;
    if balance < buffer {
        return Ok(Json(PocketPrintrCreateResponse {
            success: false,
            pocket_id,
            token_id: None,
            mint_address: None,
            tx_signature: None,
            deployments: vec![],
            error: Some(format!("Insufficient balance. Have {} SOL, need at least 0.005 SOL for fees", lamports_to_sol(balance))),
        }));
    }

    let chains = req.chains.unwrap_or_else(|| vec!["solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp".to_string()]);
    let creator_accounts = vec![format!("solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp:{}", pocket.stealth_pubkey)];

    let create_req = PrintrCreateRequest {
        name: req.name,
        symbol: req.symbol,
        description: req.description,
        image_url: req.image_url,
        image_path: req.image_path,
        chains,
        creator_accounts,
        initial_supply: req.initial_supply,
        decimals: req.decimals,
    };

    let create_result = printr::create_token(&state.http_client, &create_req).await
        .map_err(|e| AppError(e))?;

    if !create_result.success {
        return Ok(Json(PocketPrintrCreateResponse {
            success: false,
            pocket_id,
            token_id: create_result.token_id,
            mint_address: create_result.mint_address,
            tx_signature: None,
            deployments: create_result.chains,
            error: create_result.error,
        }));
    }

    let mut tx_signature = None;
    if let Some(ref tx_data) = create_result.transaction_data {
        match printr::sign_and_submit_token(&state.http_client, &state.rpc, &pocket_keypair, tx_data).await {
            Ok(sig) => {
                info!("Printr token TX signed from pocket {}: {}", pocket_id, sig);
                tx_signature = Some(sig);
            }
            Err(e) => {
                return Ok(Json(PocketPrintrCreateResponse {
                    success: true,
                    pocket_id,
                    token_id: create_result.token_id,
                    mint_address: create_result.mint_address,
                    tx_signature: None,
                    deployments: create_result.chains,
                    error: Some(format!("Token created successfully. On-chain signing pending: {}", e)),
                }));
            }
        }
    }

    info!("Printr token created from pocket {}: {:?}", pocket_id, create_result.token_id);

    // Log to transaction_log
    let _ = state.db.insert_transaction_log(
        &format!("printr_{}", chrono::Utc::now().timestamp_millis()),
        &owner_meta_hash, "printr", "completed",
        None, None,
        Some(&format!("Token created: {}", create_result.token_id.as_deref().unwrap_or("unknown"))),
        tx_signature.as_deref(),
        None,
    );

    Ok(Json(PocketPrintrCreateResponse {
        success: true,
        pocket_id,
        token_id: create_result.token_id,
        mint_address: create_result.mint_address,
        tx_signature,
        deployments: create_result.chains,
        error: None,
    }))
}

#[derive(Debug, Deserialize)]
struct PrintrDeploymentQuery {
    token_id: String,
}

#[derive(Debug, Serialize)]
struct PocketPrintrDeploymentResponse {
    success: bool,
    token_id: String,
    deployments: Vec<printr::ChainDeployment>,
    error: Option<String>,
}

/// Get Printr deployment status
async fn printr_deployment_handler(
    State(state): State<Arc<AppState>>,
    Query(query): Query<PrintrDeploymentQuery>,
) -> std::result::Result<Json<PocketPrintrDeploymentResponse>, AppError> {
    let status = printr::get_deployment_status(&state.http_client, &query.token_id).await
        .map_err(|e| AppError(e))?;

    Ok(Json(PocketPrintrDeploymentResponse {
        success: status.success,
        token_id: status.token_id,
        deployments: status.deployments,
        error: status.error,
    }))
}

#[derive(Debug, Deserialize)]
struct PrintrTokenInfoQuery {
    token_id: String,
}

/// Get Printr token info
async fn printr_token_info_handler(
    State(state): State<Arc<AppState>>,
    Query(query): Query<PrintrTokenInfoQuery>,
) -> std::result::Result<Json<serde_json::Value>, AppError> {
    let info = printr::get_token_info(&state.http_client, &query.token_id).await
        .map_err(|e| AppError(e))?;

    Ok(Json(serde_json::json!({
        "success": true,
        "token": info,
    })))
}

// ============ CONDUIT PROTOCOL HANDLERS ============

#[derive(Debug, Deserialize)]
struct ConduitDiscoverPayload {
    category: Option<String>,
}

async fn conduit_discover_handler(
    State(state): State<Arc<AppState>>,
    Path(pocket_id): Path<String>,
    Json(payload): Json<ConduitDiscoverPayload>,
) -> std::result::Result<Json<serde_json::Value>, AppError> {
    // Verify pocket exists and caller owns it
    let pocket = state.db.get_pocket(&pocket_id)
        .map_err(|e| AppError(e))?
        .ok_or_else(|| AppError(MazeError::PocketNotFound(pocket_id.clone())))?;

    let _ = pocket; // ownership verified by pocket existence

    let req = conduit::ConduitDiscoverRequest {
        category: payload.category,
    };

    let result = conduit::discover(&req).await
        .map_err(|e| AppError(e))?;

    Ok(Json(serde_json::json!({
        "success": result.success,
        "network": result.network,
        "asset": result.asset,
        "endpoints": result.endpoints,
        "api_listings": result.api_listings,
        "endpoint_count": result.endpoint_count,
        "api_listing_count": result.api_listing_count,
        "error": result.error,
    })))
}

#[derive(Debug, Deserialize)]
struct ConduitCallPayload {
    resource_id: serde_json::Value,
    payload: serde_json::Value,
    password: String,
}

async fn conduit_call_handler(
    State(state): State<Arc<AppState>>,
    Path(pocket_id): Path<String>,
    Json(body): Json<ConduitCallPayload>,
) -> std::result::Result<Json<serde_json::Value>, AppError> {
    // Verify pocket exists
    let pocket = state.db.get_pocket(&pocket_id)
        .map_err(|e| AppError(e))?
        .ok_or_else(|| AppError(MazeError::PocketNotFound(pocket_id.clone())))?;

    // Decrypt keypair
    let keypair_bytes = state.db.decrypt(&pocket.keypair_encrypted)
        .map_err(|e| AppError(MazeError::CryptoError(format!("Keypair decrypt failed: {}", e))))?;
    let pocket_keypair = solana_sdk::signature::Keypair::from_bytes(&keypair_bytes)
        .map_err(|e| AppError(MazeError::CryptoError(format!("Invalid keypair: {}", e))))?;

    let req = conduit::ConduitCallRequest {
        resource_id: body.resource_id,
        payload: body.payload,
    };

    let result = conduit::call_capability(&pocket_keypair, &req).await
        .map_err(|e| AppError(e))?;

    // Log transaction
    let owner_meta_hash = pocket.owner_meta_hash.clone();
    let _ = state.db.insert_transaction_log(
        &format!("conduit_{}", chrono::Utc::now().timestamp_millis()),
        &owner_meta_hash, "conduit_call", "completed",
        None, None,
        Some(&format!("Conduit call from pocket {}", pocket_id)),
        result.signature.as_deref(),
        None,
    );

    Ok(Json(serde_json::json!({
        "success": result.success,
        "status": result.status,
        "body": result.body,
        "signature": result.signature,
        "error": result.error,
    })))
}


// ============ USEPOD INTEGRATION HANDLERS ============

#[derive(Debug, Deserialize)]
struct UsePodRegisterRequest {
    meta_address: String,
}

#[derive(Debug, Serialize)]
struct UsePodRegisterResponse {
    success: bool,
    pocket_id: String,
    usepod_token: Option<String>,
    usepod_deposit_address: Option<String>,
    error: Option<String>,
}

/// Register a UsePod token for a pocket
/// Calls UsePod POST /v1/register (no auth required)
/// Stores token + deposit address in pocket metadata
async fn usepod_register_handler(
    State(state): State<Arc<AppState>>,
    Path(pocket_id): Path<String>,
    Json(req): Json<UsePodRegisterRequest>,
) -> std::result::Result<Json<UsePodRegisterResponse>, AppError> {
    let owner_meta_hash = hash_meta_address(&req.meta_address);

    // Verify pocket ownership
    let pocket = state.db.get_pocket_for_owner(&pocket_id, &owner_meta_hash)?
        .ok_or(MazeError::PocketNotFound(pocket_id.clone()))?;

    if pocket.status != PocketStatus::Active {
        return Ok(Json(UsePodRegisterResponse {
            success: false,
            pocket_id,
            usepod_token: None,
            usepod_deposit_address: None,
            error: Some(format!("Pocket status is {}, must be active", pocket.status.as_str())),
        }));
    }

    // Check if already registered
    if pocket.usepod_token.is_some() {
        return Ok(Json(UsePodRegisterResponse {
            success: true,
            pocket_id,
            usepod_token: pocket.usepod_token,
            usepod_deposit_address: pocket.usepod_deposit_address,
            error: None,
        }));
    }

    // Call UsePod POST /v1/register (no auth required)
    let register_resp = match state.http_client
        .post("https://api.usepod.ai/v1/register")
        .header("Content-Type", "application/json")
        .send()
        .await
    {
        Ok(resp) => resp,
        Err(e) => {
            error!("UsePod register failed: {}", e);
            return Ok(Json(UsePodRegisterResponse {
                success: false,
                pocket_id,
                usepod_token: None,
                usepod_deposit_address: None,
                error: Some(format!("Failed to reach UsePod API: {}", e)),
            }));
        }
    };

    let status = register_resp.status();
    let body: serde_json::Value = match register_resp.json().await {
        Ok(v) => v,
        Err(e) => {
            error!("UsePod register parse failed: {}", e);
            return Ok(Json(UsePodRegisterResponse {
                success: false,
                pocket_id,
                usepod_token: None,
                usepod_deposit_address: None,
                error: Some("Failed to parse UsePod response".to_string()),
            }));
        }
    };

    if !status.is_success() {
        let err_msg = body["error"].as_str().unwrap_or("Unknown error");
        return Ok(Json(UsePodRegisterResponse {
            success: false,
            pocket_id,
            usepod_token: None,
            usepod_deposit_address: None,
            error: Some(format!("UsePod register error: {}", err_msg)),
        }));
    }

    // Extract token and deposit address from response
    let token = body["token"].as_str().map(|s| s.to_string());
    let deposit_address = body["deposit_address"].as_str().map(|s| s.to_string());

    if token.is_none() || deposit_address.is_none() {
        return Ok(Json(UsePodRegisterResponse {
            success: false,
            pocket_id,
            usepod_token: None,
            usepod_deposit_address: None,
            error: Some("UsePod response missing token or deposit_address".to_string()),
        }));
    }

    let token_str = token.as_ref().unwrap();
    let deposit_str = deposit_address.as_ref().unwrap();

    // Store in pocket metadata
    state.db.update_pocket_usepod(&pocket_id, &owner_meta_hash, token_str, deposit_str)?;

    info!("UsePod token registered for pocket {}: deposit {}", pocket_id, &deposit_str[..20.min(deposit_str.len())]);

    // Log to transaction_log
    let _ = state.db.insert_transaction_log(
        &format!("usepod_{}", chrono::Utc::now().timestamp_millis()),
        &owner_meta_hash, "usepod_register", "completed",
        None, None,
        Some(&format!("UsePod token registered for pocket {}", pocket_id)),
        None, None,
    );

    Ok(Json(UsePodRegisterResponse {
        success: true,
        pocket_id,
        usepod_token: token,
        usepod_deposit_address: deposit_address,
        error: None,
    }))
}

#[derive(Debug, Deserialize)]
struct UsePodFundRequest {
    meta_address: String,
    amount_sol: f64,
}

#[derive(Debug, Serialize)]
struct UsePodFundResponse {
    success: bool,
    pocket_id: String,
    usdc_amount: Option<f64>,
    deposit_address: Option<String>,
    tx_signature: Option<String>,
    error: Option<String>,
}

/// Fund a UsePod token balance from a pocket
/// Step 1: Swap SOL to USDC via Jupiter (existing swap infrastructure)
/// Step 2: Transfer USDC (SPL token) to UsePod deposit address
async fn usepod_fund_handler(
    State(state): State<Arc<AppState>>,
    Path(pocket_id): Path<String>,
    Json(req): Json<UsePodFundRequest>,
) -> std::result::Result<Json<UsePodFundResponse>, AppError> {
    let owner_meta_hash = hash_meta_address(&req.meta_address);

    // Verify pocket ownership
    let pocket = state.db.get_pocket_for_owner(&pocket_id, &owner_meta_hash)?
        .ok_or(MazeError::PocketNotFound(pocket_id.clone()))?;

    if pocket.status != PocketStatus::Active {
        return Ok(Json(UsePodFundResponse {
            success: false, pocket_id, usdc_amount: None,
            deposit_address: None, tx_signature: None,
            error: Some(format!("Pocket status is {}, must be active", pocket.status.as_str())),
        }));
    }

    // Check UsePod token is registered
    let deposit_address = match &pocket.usepod_deposit_address {
        Some(addr) => addr.clone(),
        None => {
            return Ok(Json(UsePodFundResponse {
                success: false, pocket_id, usdc_amount: None,
                deposit_address: None, tx_signature: None,
                error: Some("No UsePod token registered for this pocket. Call /usepod/register first.".to_string()),
            }));
        }
    };

    // Validate amount
    if req.amount_sol < 0.01 {
        return Ok(Json(UsePodFundResponse {
            success: false, pocket_id, usdc_amount: None,
            deposit_address: None, tx_signature: None,
            error: Some("Minimum 0.01 SOL".to_string()),
        }));
    }

    // Get pocket keypair and check balance
    let keypair_bytes = state.db.decrypt(&pocket.keypair_encrypted)?;
    let pocket_keypair = Keypair::from_bytes(&keypair_bytes)
        .map_err(|e| MazeError::KeypairError(e.to_string()))?;

    let balance = state.rpc.get_balance(&pocket_keypair.pubkey())
        .map_err(|e| MazeError::RpcError(e.to_string()))?;

    let amount_lamports = sol_to_lamports(req.amount_sol);
    let buffer = 5_000_000; // 0.005 SOL for tx fees
    if balance < amount_lamports + buffer {
        return Ok(Json(UsePodFundResponse {
            success: false, pocket_id, usdc_amount: None,
            deposit_address: None, tx_signature: None,
            error: Some(format!("Insufficient balance. Have {} SOL, need {} SOL + fees",
                lamports_to_sol(balance), req.amount_sol)),
        }));
    }

    info!("UsePod fund: {} SOL from pocket {} to deposit {}", req.amount_sol, pocket_id, &deposit_address[..20.min(deposit_address.len())]);

    // Step 1: Swap SOL to USDC via Jupiter
    let usdc_mint = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
    let swap_result = swap::execute_swap(
        &state.http_client,
        &state.rpc,
        &pocket_keypair,
        &tokens::SOL_MINT.to_string(),
        usdc_mint,
        amount_lamports,
        Some(100), // 1% slippage
    ).await.map_err(|e| AppError(e))?;

    if !swap_result.success {
        return Ok(Json(UsePodFundResponse {
            success: false, pocket_id, usdc_amount: None,
            deposit_address: None, tx_signature: None,
            error: Some(format!("Jupiter swap SOL->USDC failed: {}", swap_result.error.unwrap_or_default())),
        }));
    }

    let usdc_raw = swap_result.out_amount.parse::<u64>().unwrap_or(0);
    let usdc_amount = usdc_raw as f64 / 1_000_000.0; // USDC has 6 decimals
    info!("UsePod fund step 1: swapped to {} USDC", usdc_amount);

    // Step 2: Transfer USDC to UsePod deposit address
    let usdc_pubkey = Pubkey::from_str(usdc_mint)
        .map_err(|e| MazeError::InvalidParameters(e.to_string()))?;
    let deposit_pubkey = Pubkey::from_str(&deposit_address)
        .map_err(|e| MazeError::InvalidParameters(format!("Invalid UsePod deposit address: {}", e)))?;

    // Get pocket's USDC ATA
    let pocket_usdc_ata = spl_associated_token_account::get_associated_token_address(
        &pocket_keypair.pubkey(),
        &usdc_pubkey,
    );

    // Get actual USDC balance in ATA
    let actual_usdc = match state.rpc.get_token_account_balance(&pocket_usdc_ata) {
        Ok(bal) => bal.amount.parse::<u64>().unwrap_or(usdc_raw),
        Err(_) => usdc_raw,
    };

    if actual_usdc == 0 {
        return Ok(Json(UsePodFundResponse {
            success: false, pocket_id, usdc_amount: None,
            deposit_address: None, tx_signature: None,
            error: Some("No USDC balance after swap".to_string()),
        }));
    }

    // Get or create deposit address ATA
    let deposit_usdc_ata = spl_associated_token_account::get_associated_token_address(
        &deposit_pubkey,
        &usdc_pubkey,
    );

    // Build transfer instruction
    let mut instructions = vec![];

    // Create ATA for deposit address if needed
    instructions.push(
        spl_associated_token_account::instruction::create_associated_token_account_idempotent(
            &pocket_keypair.pubkey(),
            &deposit_pubkey,
            &usdc_pubkey,
            &spl_token::id(),
        )
    );

    // Transfer USDC
    instructions.push(
        spl_token::instruction::transfer(
            &spl_token::id(),
            &pocket_usdc_ata,
            &deposit_usdc_ata,
            &pocket_keypair.pubkey(),
            &[],
            actual_usdc,
        ).map_err(|e| MazeError::TransactionError(format!("SPL transfer instruction failed: {}", e)))?
    );

    // Send transaction
    let tx_sig = {
        let mut last_err = String::new();
        let mut result_sig = None;
        for attempt in 1..=5u8 {
            let blockhash = match state.rpc.get_latest_blockhash() {
                Ok(bh) => bh,
                Err(e) => {
                    warn!("UsePod fund TX attempt {}/5: blockhash failed: {}", attempt, e);
                    last_err = e.to_string();
                    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
                    continue;
                }
            };
            let tx = Transaction::new_signed_with_payer(
                &instructions,
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
                    result_sig = Some(s);
                    break;
                }
                Err(e) => {
                    let err_str = e.to_string();
                    if err_str.contains("connection") || err_str.contains("timeout") || err_str.contains("closed") {
                        warn!("UsePod fund TX attempt {}/5: {}", attempt, err_str);
                        last_err = err_str;
                        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
                        continue;
                    }
                    return Ok(Json(UsePodFundResponse {
                        success: false, pocket_id, usdc_amount: Some(usdc_amount),
                        deposit_address: Some(deposit_address), tx_signature: None,
                        error: Some(format!("USDC transfer failed: {}", e)),
                    }));
                }
            }
        }
        match result_sig {
            Some(s) => s,
            None => {
                return Ok(Json(UsePodFundResponse {
                    success: false, pocket_id, usdc_amount: Some(usdc_amount),
                    deposit_address: Some(deposit_address), tx_signature: None,
                    error: Some(format!("USDC transfer failed after 5 attempts: {}", last_err)),
                }));
            }
        }
    };

    // Wait for confirmation
    let mut confirmed = false;
    for _ in 0..30 {
        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
        if let Ok(Some(result)) = state.rpc.get_signature_status(&tx_sig) {
            if result.is_ok() {
                confirmed = true;
                break;
            }
        }
    }

    if !confirmed {
        warn!("UsePod fund: USDC transfer confirmation timeout for pocket {}", pocket_id);
    }

    info!("UsePod funded: {} USDC from pocket {} to {} ({})", usdc_amount, pocket_id, deposit_address, tx_sig);

    // Log to transaction_log
    let _ = state.db.insert_transaction_log(
        &format!("usepod_{}", chrono::Utc::now().timestamp_millis()),
        &owner_meta_hash, "usepod_fund", "completed",
        Some(amount_lamports as i64),
        Some(&format!("{:.2} USDC", usdc_amount)),
        Some(&format!("UsePod funded from pocket {}", pocket_id)),
        Some(&tx_sig.to_string()),
        None,
    );

    Ok(Json(UsePodFundResponse {
        success: true,
        pocket_id,
        usdc_amount: Some(usdc_amount),
        deposit_address: Some(deposit_address),
        tx_signature: Some(tx_sig.to_string()),
        error: None,
    }))
}


// ============ MAZE PREFERENCES HANDLERS ============

#[derive(Debug, Deserialize)]
struct GetMazePreferencesRequest {
    meta_address: String,
}

#[derive(Debug, Serialize)]
struct MazePreferencesResponse {
    success: bool,
    preferences: Option<MazePreferencesData>,
    error: Option<String>,
}

#[derive(Debug, Serialize)]
struct MazePreferencesData {
    hop_count: u8,
    split_ratio: f64,
    merge_strategy: String,
    delay_pattern: String,
    delay_ms: u64,
    delay_scope: String,
    updated_at: i64,
}

#[derive(Debug, Deserialize)]
struct SaveMazePreferencesRequest {
    meta_address: String,
    hop_count: Option<u8>,
    split_ratio: Option<f64>,
    merge_strategy: Option<String>,
    delay_pattern: Option<String>,
    delay_ms: Option<u64>,
    delay_scope: Option<String>,
}

#[derive(Debug, Serialize)]
struct SaveMazePreferencesResponse {
    success: bool,
    error: Option<String>,
}

async fn get_maze_preferences_handler(
    State(state): State<Arc<AppState>>,
    Json(req): Json<GetMazePreferencesRequest>,
) -> std::result::Result<Json<MazePreferencesResponse>, AppError> {
    let owner_meta_hash = hash_meta_address(&req.meta_address);

    let prefs = state.db.get_maze_preferences(&owner_meta_hash)?;

    match prefs {
        Some(p) => Ok(Json(MazePreferencesResponse {
            success: true,
            preferences: Some(MazePreferencesData {
                hop_count: p.hop_count,
                split_ratio: p.split_ratio,
                merge_strategy: p.merge_strategy,
                delay_pattern: p.delay_pattern,
                delay_ms: p.delay_ms,
                delay_scope: p.delay_scope,
                updated_at: p.updated_at,
            }),
            error: None,
        })),
        None => Ok(Json(MazePreferencesResponse {
            success: true,
            preferences: None,
            error: None,
        })),
    }
}

async fn save_maze_preferences_handler(
    State(state): State<Arc<AppState>>,
    Json(req): Json<SaveMazePreferencesRequest>,
) -> std::result::Result<Json<SaveMazePreferencesResponse>, AppError> {
    let owner_meta_hash = hash_meta_address(&req.meta_address);
    let now = chrono::Utc::now().timestamp();

    let prefs = MazePreferences {
        owner_meta_hash,
        hop_count: req.hop_count.unwrap_or(7).max(5).min(10),
        split_ratio: req.split_ratio.unwrap_or(1.618).max(1.1).min(3.0),
        merge_strategy: req.merge_strategy.unwrap_or_else(|| "random".to_string()),
        delay_pattern: req.delay_pattern.unwrap_or_else(|| "none".to_string()),
        delay_ms: req.delay_ms.unwrap_or(0).min(5000),
        delay_scope: req.delay_scope.unwrap_or_else(|| "node".to_string()),
        updated_at: now,
    };

    state.db.save_maze_preferences(&prefs)?;

    info!("Maze preferences saved for user");

    Ok(Json(SaveMazePreferencesResponse {
        success: true,
        error: None,
    }))
}

// ============ KAUSAPAY PAYMENT HANDLER ============

#[derive(Debug, Deserialize)]
struct KausaPayRequest {
    meta_address: String,
    url: String,
    max_amount_usdc: f64,
    #[serde(default = "default_http_method")]
    method: String,
    #[serde(default)]
    body: Option<String>,
}

fn default_http_method() -> String {
    "GET".to_string()
}

#[derive(Debug, Serialize)]
struct KausaPayResponse {
    success: bool,
    response_body: Option<String>,
    payment_signature: Option<String>,
    amount_paid_usdc: f64,
    protocol_used: String,
    token_symbol: String,
    error: Option<String>,
}

/// KausaPay: pay any x402/MPP endpoint from a pocket
async fn kausa_pay_handler(
    State(state): State<Arc<AppState>>,
    Path(pocket_id): Path<String>,
    Json(req): Json<KausaPayRequest>,
) -> std::result::Result<Json<KausaPayResponse>, AppError> {
    let owner_meta_hash = hash_meta_address(&req.meta_address);

    // Verify pocket ownership
    let pocket = state.db.get_pocket_for_owner(&pocket_id, &owner_meta_hash)?
        .ok_or(MazeError::PocketNotFound(pocket_id.clone()))?;

    if pocket.status != PocketStatus::Active {
        return Ok(Json(KausaPayResponse {
            success: false,
            response_body: None,
            payment_signature: None,
            amount_paid_usdc: 0.0,
            protocol_used: String::new(),
            token_symbol: String::new(),
            error: Some(format!("Pocket status is {}, must be active", pocket.status.as_str())),
        }));
    }

    // Decrypt pocket keypair
    let keypair_bytes = state.db.decrypt(&pocket.keypair_encrypted)?;
    let pocket_keypair = Keypair::from_bytes(&keypair_bytes)
        .map_err(|e| MazeError::KeypairError(e.to_string()))?;

    info!("KausaPay request: pocket {} -> {}", pocket_id, &req.url[..60.min(req.url.len())]);

    // Execute payment via router
    let result = payment_router::pay(
        &state.http_client,
        &state.rpc,
        &pocket_keypair,
        &req.url,
        req.max_amount_usdc,
        &req.method,
        req.body.as_deref(),
    ).await;

    match result {
        Ok(pay_result) => {
            if pay_result.success {
                info!("KausaPay success: pocket {} paid {} {} via {}",
                    pocket_id, pay_result.amount_paid_usdc, pay_result.token_symbol, pay_result.protocol_used);

                // Log to transaction_log
                let _ = state.db.insert_transaction_log(
                    &format!("pay_{}", chrono::Utc::now().timestamp_millis()),
                    &owner_meta_hash, "kausapay", "completed",
                    None,
                    Some(&format!("{} {}", pay_result.amount_paid_usdc, pay_result.token_symbol)),
                    Some(&format!("Payment via {} to {}", pay_result.protocol_used, &req.url[..60.min(req.url.len())])),
                    pay_result.payment_signature.as_deref(),
                    None,
                );
            }
            Ok(Json(KausaPayResponse {
                success: pay_result.success,
                response_body: pay_result.response_body,
                payment_signature: pay_result.payment_signature,
                amount_paid_usdc: pay_result.amount_paid_usdc,
                protocol_used: pay_result.protocol_used.to_string(),
                token_symbol: pay_result.token_symbol,
                error: pay_result.error,
            }))
        }
        Err(e) => {
            warn!("KausaPay failed for pocket {}: {}", pocket_id, sanitize_error(&e.to_string()));
            Ok(Json(KausaPayResponse {
                success: false,
                response_body: None,
                payment_signature: None,
                amount_paid_usdc: 0.0,
                protocol_used: String::new(),
                token_symbol: String::new(),
                error: Some(sanitize_error(&e.to_string())),
            }))
        }
    }
}

// ============ KAUSAGATE SPEC GENERATOR ============

/// Generate individual Pay.sh YAML spec for a gate endpoint
fn generate_gate_spec(endpoint: &GateEndpoint) -> String {
    let recipient_key = endpoint.pocket_id.replace('-', "_");
    
    let yaml = format!(
        r#"name: kausalayer-{}
subdomain: kausalayer
title: '{}'
description: '{}'
category: {}
version: v1
routing:
  type: proxy
  url: {}
operator:
  currencies:
    usd: ['USDC']
  network: mainnet
  fee_payer: false
recipients:
  {}:
    account: '{}'
    label: '{}'
endpoints:
  - method: {}
    path: /
    resource: '{}'
    description: '{}'
    metering:
      dimensions:
        - direction: usage
          unit: requests
          scale: 1
          tiers:
            - price_usd: {}
      splits:
        - recipient: {}
          percent: 100
          memo: 'Revenue for {}'
"#,
        endpoint.id,
        endpoint.description,
        endpoint.description,
        endpoint.category,
        endpoint.endpoint_url,
        recipient_key,
        endpoint.pocket_address,
        recipient_key,
        endpoint.method,
        endpoint.id,
        endpoint.description,
        endpoint.price_usdc,
        recipient_key,
        endpoint.id,
    );
    yaml
}

/// Save gate spec YAML to disk
fn save_gate_spec(endpoint: &GateEndpoint) {
    let spec_dir = "/root/sdp-mazepocket/gate-specs";
    
    // Create directory if it doesn't exist
    if let Err(e) = std::fs::create_dir_all(spec_dir) {
        error!("KausaGate: failed to create spec dir: {}", e);
        return;
    }
    
    let yaml_content = generate_gate_spec(endpoint);
    let file_path = format!("{}/{}.yml", spec_dir, endpoint.id);
    
    match std::fs::write(&file_path, &yaml_content) {
        Ok(_) => info!("KausaGate: spec saved to {}", file_path),
        Err(e) => error!("KausaGate: failed to save spec: {}", e),
    }
}

/// Delete gate spec YAML from disk
fn delete_gate_spec(endpoint_id: &str) {
    let file_path = format!("/root/sdp-mazepocket/gate-specs/{}.yml", endpoint_id);
    match std::fs::remove_file(&file_path) {
        Ok(_) => info!("KausaGate: spec deleted: {}", file_path),
        Err(e) => warn!("KausaGate: spec file not found or delete failed: {}", e),
    }
}

// ============ KAUSAGATE HANDLERS ============

#[derive(Debug, Deserialize)]
struct GateRegisterRequest {
    meta_address: String,
    endpoint_url: String,
    method: Option<String>,
    description: String,
    price_usdc: f64,
    category: String,
}

#[derive(Debug, Serialize)]
struct GateRegisterResponse {
    success: bool,
    endpoint_id: Option<String>,
    pocket_id: String,
    pocket_address: String,
    error: Option<String>,
}

#[derive(Debug, Serialize)]
struct GateEndpointInfo {
    id: String,
    endpoint_url: String,
    method: String,
    description: String,
    price_usdc: f64,
    category: String,
    status: String,
    created_at: i64,
}

#[derive(Debug, Serialize)]
struct GateListResponse {
    success: bool,
    pocket_id: String,
    endpoints: Vec<GateEndpointInfo>,
    count: usize,
}

#[derive(Debug, Serialize)]
struct GateListAllResponse {
    success: bool,
    endpoints: Vec<GateEndpointInfoFull>,
    count: usize,
}

#[derive(Debug, Serialize)]
struct GateEndpointInfoFull {
    id: String,
    pocket_id: String,
    pocket_address: String,
    endpoint_url: String,
    description: String,
    price_usdc: f64,
    category: String,
    status: String,
    created_at: i64,
}

#[derive(Debug, Deserialize)]
struct GateDeleteRequest {
    meta_address: String,
    endpoint_url: String,
}

#[derive(Debug, Serialize)]
struct GateDeleteResponse {
    success: bool,
    message: String,
}

/// Register an endpoint to a pocket via KausaGate
async fn gate_register(
    State(state): State<Arc<AppState>>,
    Path(pocket_id): Path<String>,
    Json(req): Json<GateRegisterRequest>,
) -> std::result::Result<Json<GateRegisterResponse>, AppError> {
    let owner_meta_hash = hash_meta_address(&req.meta_address);

    // Verify pocket ownership
    let pocket = state.db.get_pocket_for_owner(&pocket_id, &owner_meta_hash)?
        .ok_or(MazeError::PocketNotFound(pocket_id.clone()))?;

    if pocket.status != PocketStatus::Active {
        return Ok(Json(GateRegisterResponse {
            success: false,
            endpoint_id: None,
            pocket_id,
            pocket_address: String::new(),
            error: Some(format!("Pocket status is {}, must be active", pocket.status.as_str())),
        }));
    }

    // Validate URL format
    if !req.endpoint_url.starts_with("https://") {
        return Ok(Json(GateRegisterResponse {
            success: false,
            endpoint_id: None,
            pocket_id,
            pocket_address: String::new(),
            error: Some("Endpoint URL must start with https://".to_string()),
        }));
    }

    // Validate price
    if req.price_usdc <= 0.0 {
        return Ok(Json(GateRegisterResponse {
            success: false,
            endpoint_id: None,
            pocket_id,
            pocket_address: String::new(),
            error: Some("Price must be greater than 0".to_string()),
        }));
    }

    // Validate category
    let valid_categories = ["ai_ml", "search", "maps", "data", "compute", "productivity"];
    if !valid_categories.contains(&req.category.as_str()) {
        return Ok(Json(GateRegisterResponse {
            success: false,
            endpoint_id: None,
            pocket_id,
            pocket_address: String::new(),
            error: Some(format!("Invalid category. Must be one of: {}", valid_categories.join(", "))),
        }));
    }

    // Check if endpoint already registered
    if state.db.is_endpoint_registered(&req.endpoint_url)? {
        return Ok(Json(GateRegisterResponse {
            success: false,
            endpoint_id: None,
            pocket_id,
            pocket_address: String::new(),
            error: Some("Endpoint URL already registered".to_string()),
        }));
    }

    let now = chrono::Utc::now().timestamp();
    let endpoint_id = format!("gate_{}", &generate_pocket_id()[7..]);

    let gate_endpoint = GateEndpoint {
        id: endpoint_id.clone(),
        pocket_id: pocket_id.clone(),
        pocket_address: pocket.stealth_pubkey.clone(),
        owner_meta_hash: owner_meta_hash.clone(),
        endpoint_url: req.endpoint_url.clone(),
        method: req.method.clone().unwrap_or_else(|| "POST".to_string()),
        description: req.description,
        price_usdc: req.price_usdc,
        category: req.category,
        status: "active".to_string(),
        created_at: now,
    };

    state.db.create_gate_endpoint(&gate_endpoint)?;

    info!("KausaGate: endpoint {} registered to pocket {}", req.endpoint_url, pocket_id);

    // Log to transaction_log
    let _ = state.db.insert_transaction_log(
        &format!("gate_{}", chrono::Utc::now().timestamp_millis()),
        &owner_meta_hash, "gate_register", "completed",
        None, None,
        Some(&format!("Endpoint registered: {}", req.endpoint_url)),
        None,
        None,
    );

    // Generate Pay.sh YAML spec for this endpoint
    save_gate_spec(&gate_endpoint);

    Ok(Json(GateRegisterResponse {
        success: true,
        endpoint_id: Some(endpoint_id),
        pocket_id,
        pocket_address: pocket.stealth_pubkey,
        error: None,
    }))
}

/// List endpoints registered to a pocket
async fn gate_list_by_pocket(
    State(state): State<Arc<AppState>>,
    Path(pocket_id): Path<String>,
    Query(query): Query<ListPocketsQuery>,
) -> std::result::Result<Json<GateListResponse>, AppError> {
    let owner_meta_hash = hash_meta_address(&query.meta_address);

    let endpoints = state.db.list_gate_endpoints_by_pocket(&pocket_id, &owner_meta_hash)?;

    let endpoint_infos: Vec<GateEndpointInfo> = endpoints.iter().map(|ep| GateEndpointInfo {
        id: ep.id.clone(),
        endpoint_url: ep.endpoint_url.clone(),
        method: ep.method.clone(),
        description: ep.description.clone(),
        price_usdc: ep.price_usdc,
        category: ep.category.clone(),
        status: ep.status.clone(),
        created_at: ep.created_at,
    }).collect();

    let count = endpoint_infos.len();

    Ok(Json(GateListResponse {
        success: true,
        pocket_id,
        endpoints: endpoint_infos,
        count,
    }))
}

/// List all gate endpoints (admin)
async fn gate_list_all(
    State(state): State<Arc<AppState>>,
) -> std::result::Result<Json<GateListAllResponse>, AppError> {
    let endpoints = state.db.list_all_gate_endpoints()?;

    let endpoint_infos: Vec<GateEndpointInfoFull> = endpoints.iter().map(|ep| GateEndpointInfoFull {
        id: ep.id.clone(),
        pocket_id: ep.pocket_id.clone(),
        pocket_address: ep.pocket_address.clone(),
        endpoint_url: ep.endpoint_url.clone(),
        description: ep.description.clone(),
        price_usdc: ep.price_usdc,
        category: ep.category.clone(),
        status: ep.status.clone(),
        created_at: ep.created_at,
    }).collect();

    let count = endpoint_infos.len();

    Ok(Json(GateListAllResponse {
        success: true,
        endpoints: endpoint_infos,
        count,
    }))
}


/// Get Pay.sh YAML spec for a gate endpoint
async fn gate_get_yaml(
    State(state): State<Arc<AppState>>,
    Path(endpoint_id): Path<String>,
) -> axum::response::Response {
    // Find endpoint in database
    let endpoint = match state.db.list_all_gate_endpoints() {
        Ok(endpoints) => endpoints.into_iter().find(|ep| ep.id == endpoint_id),
        Err(e) => {
            error!("KausaGate: database error: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
                "error": "Internal server error"
            }))).into_response();
        }
    };

    let endpoint = match endpoint {
        Some(ep) => ep,
        None => {
            return (StatusCode::NOT_FOUND, Json(serde_json::json!({
                "error": "Endpoint not found"
            }))).into_response();
        }
    };

    let yaml_content = generate_gate_spec(&endpoint);
    let filename = format!("{}.yml", endpoint.id);

    axum::response::Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "text/yaml")
        .header("Content-Disposition", format!("attachment; filename=\"{}\"", filename))
        .body(axum::body::Body::from(yaml_content))
        .unwrap_or_else(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Error").into_response())
}

/// Delete a gate endpoint
async fn gate_delete(
    State(state): State<Arc<AppState>>,
    Path(pocket_id): Path<String>,
    Json(req): Json<GateDeleteRequest>,
) -> std::result::Result<Json<GateDeleteResponse>, AppError> {
    let owner_meta_hash = hash_meta_address(&req.meta_address);

    // Verify pocket ownership
    let _pocket = state.db.get_pocket_for_owner(&pocket_id, &owner_meta_hash)?
        .ok_or(MazeError::PocketNotFound(pocket_id.clone()))?;

    // Find endpoint_id before deleting (for spec file cleanup)
    let endpoint_id = state.db.list_gate_endpoints_by_pocket(&pocket_id, &owner_meta_hash)?
        .iter()
        .find(|ep| ep.endpoint_url == req.endpoint_url)
        .map(|ep| ep.id.clone());

    let deleted = state.db.delete_gate_endpoint(&req.endpoint_url, &owner_meta_hash)?;

    if deleted {
        info!("KausaGate: endpoint {} deleted from pocket {}", req.endpoint_url, pocket_id);

        // Delete Pay.sh YAML spec file
        if let Some(ref eid) = endpoint_id {
            delete_gate_spec(eid);
        }

        Ok(Json(GateDeleteResponse {
            success: true,
            message: format!("Endpoint {} removed", req.endpoint_url),
        }))
    } else {
        Ok(Json(GateDeleteResponse {
            success: false,
            message: "Endpoint not found or access denied".to_string(),
        }))
    }
}


// ============ PROOF OF PRIVACY ============

#[derive(Debug, Serialize, Deserialize, Clone)]
struct ProofOfPrivacy {
    proof_id: String,
    route_id: String,
    route_type: String,  // "funding", "sweep", "p2p"
    generated_at: i64,
    // Maze metrics (from maze_graph_json)
    hop_count: u8,
    total_nodes: usize,
    total_levels: u8,
    total_transactions: u16,
    delay_pattern: String,
    merge_strategy: String,
    // Privacy indicators
    privacy_grade: String,  // A, B, C, D
    amount_range: String,   // e.g. "0.1-0.5 SOL"
    // Hashed identifiers (no raw addresses)
    maze_hash: String,      // SHA-256 of maze_graph_json
    entry_hash: String,     // SHA-256 of entry node address
    exit_hash: String,      // SHA-256 of exit/destination address
    // Timing
    route_created_at: i64,
    route_completed_at: Option<i64>,
    // Status
    route_status: String,
    tx_signature: Option<String>,
    // Proof signature (HMAC-SHA256)
    signature: String,
}

fn calculate_privacy_grade(hop_count: u8, delay_pattern: &str, merge_strategy: &str) -> String {
    let delay_score = match delay_pattern {
        "fibonacci" | "exponential" => 3,
        "random" | "linear" => 2,
        _ => 0,
    };
    let merge_score = match merge_strategy {
        "fibonacci" => 3,
        "late" | "middle" => 2,
        "early" => 1,
        _ => 1,
    };
    let hop_score = if hop_count >= 9 { 4 } else if hop_count >= 7 { 3 } else if hop_count >= 6 { 2 } else { 1 };
    let total = hop_score + delay_score + merge_score;
    if total >= 9 { "A".to_string() }
    else if total >= 7 { "B".to_string() }
    else if total >= 4 { "C".to_string() }
    else { "D".to_string() }
}

fn calculate_amount_range(lamports: u64) -> String {
    let sol = lamports as f64 / 1_000_000_000.0;
    if sol < 0.01 { "< 0.01 SOL".to_string() }
    else if sol < 0.1 { "0.01-0.1 SOL".to_string() }
    else if sol < 0.5 { "0.1-0.5 SOL".to_string() }
    else if sol < 1.0 { "0.5-1 SOL".to_string() }
    else if sol < 5.0 { "1-5 SOL".to_string() }
    else if sol < 10.0 { "5-10 SOL".to_string() }
    else { "10+ SOL".to_string() }
}

fn hash_string(input: &str) -> String {
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    hex::encode(hasher.finalize())
}

fn sign_proof(proof: &ProofOfPrivacy, master_key: &str) -> String {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    type HmacSha256 = Hmac<Sha256>;

    let payload = format!(
        "{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{:?}:{}:{:?}",
        proof.proof_id, proof.route_id, proof.route_type,
        proof.hop_count, proof.total_nodes, proof.total_levels, proof.total_transactions,
        proof.delay_pattern, proof.merge_strategy,
        proof.privacy_grade, proof.amount_range, proof.maze_hash,
        proof.entry_hash, proof.exit_hash,
        proof.route_created_at, proof.route_status, proof.route_completed_at,
        proof.generated_at, proof.tx_signature
    );
    let mut mac = HmacSha256::new_from_slice(master_key.as_bytes())
        .expect("HMAC key");
    mac.update(payload.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

fn generate_proof(
    route_id: &str,
    route_type: &str,
    maze_json: &str,
    amount_lamports: u64,
    status: &str,
    created_at: i64,
    completed_at: Option<i64>,
    tx_signature: Option<&str>,
    destination: Option<&str>,
    master_key: &str,
) -> Option<ProofOfPrivacy> {
    let maze: MazeGraph = serde_json::from_str(maze_json).ok()?;

    let hop_count = maze.parameters.hop_count;
    let delay_pattern = format!("{:?}", maze.parameters.delay_pattern).to_lowercase();
    let merge_strategy = format!("{:?}", maze.parameters.merge_strategy).to_lowercase();

    let privacy_grade = calculate_privacy_grade(hop_count, &delay_pattern, &merge_strategy);
    let amount_range = calculate_amount_range(amount_lamports);
    let maze_hash = hash_string(maze_json);

    // Entry = first node address
    let entry_hash = maze.nodes.first()
        .map(|n| hash_string(&n.address))
        .unwrap_or_default();

    // Exit = destination or last node
    let exit_addr = destination.unwrap_or_else(|| {
        maze.nodes.last().map(|n| n.address.as_str()).unwrap_or("")
    });
    let exit_hash = hash_string(exit_addr);

    let now = chrono::Utc::now().timestamp();
    let proof_id = format!("proof_{}_{}", route_type, &route_id[route_id.find('_').map(|i| i+1).unwrap_or(0)..]);

    let mut proof = ProofOfPrivacy {
        proof_id,
        route_id: route_id.to_string(),
        route_type: route_type.to_string(),
        generated_at: now,
        hop_count,
        total_nodes: maze.nodes.len(),
        total_levels: maze.total_levels,
        total_transactions: maze.total_transactions,
        delay_pattern,
        merge_strategy,
        privacy_grade,
        amount_range,
        maze_hash,
        entry_hash,
        exit_hash,
        route_created_at: created_at,
        route_completed_at: completed_at,
        route_status: status.to_string(),
        tx_signature: tx_signature.map(|s| s.to_string()),
        signature: String::new(),
    };

    proof.signature = sign_proof(&proof, master_key);
    Some(proof)
}

// ============ PROOF OF PRIVACY ENDPOINTS ============

#[derive(Debug, Serialize)]
struct ProofResponse {
    success: bool,
    proof: Option<ProofOfPrivacy>,
    error: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ProofQuery {
    meta_address: String,
}

/// Get Proof of Privacy for a route
async fn get_proof_handler(
    State(state): State<Arc<AppState>>,
    Path((pocket_id, route_id)): Path<(String, String)>,
    Query(query): Query<ProofQuery>,
) -> std::result::Result<Json<ProofResponse>, AppError> {
    let owner_meta_hash = hash_meta_address(&query.meta_address);

    // Verify pocket ownership
    let _pocket = state.db.get_pocket_for_owner(&pocket_id, &owner_meta_hash)?
        .ok_or(MazeError::PocketNotFound(pocket_id.clone()))?;

    // Determine route type and fetch data
    let proof = if route_id.starts_with("fund_") {
        // Funding route
        let req = state.db.get_funding_request(&route_id)?
            .ok_or(MazeError::RequestNotFound(route_id.clone()))?;
        if req.owner_meta_hash != owner_meta_hash {
            return Err(MazeError::PocketNotFound("Access denied".into()).into());
        }
        let maze_json = state.db.get_maze_graph(&route_id)?;
        generate_proof(
            &route_id, "funding", &maze_json,
            req.amount_lamports, &req.status, req.created_at, req.completed_at,
            req.tx_signature.as_deref(), req.destination_address.as_deref(),
            &state.config.master_key,
        )
    } else if route_id.starts_with("sweep_") {
        // Sweep route
        let sweep_req = state.db.get_sweep_request(&route_id)?
            .ok_or(MazeError::RequestNotFound(route_id.clone()))?;
        let maze_json = state.db.get_sweep_maze_graph(&route_id)?;
        let sweep_tx_sig = state.db.get_sweep_final_tx_signature(&route_id)?;
        generate_proof(
            &route_id, "sweep", &maze_json,
            sweep_req.3, &sweep_req.5, chrono::Utc::now().timestamp(), None,
            sweep_tx_sig.as_deref(), Some(&sweep_req.2),
            &state.config.master_key,
        )
    } else if route_id.starts_with("p2p_") {
        // P2P route
        let transfer = state.db.get_p2p_transfer(&route_id)?
            .ok_or(MazeError::RequestNotFound(route_id.clone()))?;
        if transfer.sender_meta_hash != owner_meta_hash {
            return Err(MazeError::PocketNotFound("Access denied".into()).into());
        }
        let maze_json = state.db.get_p2p_maze_graph(&route_id)?;
        generate_proof(
            &route_id, "p2p", &maze_json,
            transfer.amount_lamports, &transfer.status, transfer.created_at, transfer.completed_at,
            transfer.tx_signature.as_deref(), Some(&transfer.receiver_pocket_id),
            &state.config.master_key,
        )
    } else if route_id.starts_with("link_") {
        // KausaLink route
        let link = state.db.get_send_link(&route_id)?
            .ok_or(MazeError::RequestNotFound(route_id.clone()))?;
        if link.owner_meta_hash != owner_meta_hash {
            return Err(MazeError::PocketNotFound("Access denied".into()).into());
        }
        let maze_json = link.funding_maze_json
            .ok_or(MazeError::DatabaseError("No maze data for send link".into()))?;
        generate_proof(
            &route_id, "send_link", &maze_json,
            link.amount_lamports, &link.status, link.created_at, link.claimed_at,
            link.refund_tx_signature.as_deref(), Some(&link.escrow_address),
            &state.config.master_key,
        )
    } else {
        None
    };

    match proof {
        Some(p) => Ok(Json(ProofResponse { success: true, proof: Some(p), error: None })),
        None => Ok(Json(ProofResponse { success: false, proof: None, error: Some("Could not generate proof".into()) })),
    }
}

/// Download Proof of Privacy as JSON file
async fn download_proof_handler(
    State(state): State<Arc<AppState>>,
    Path((pocket_id, route_id)): Path<(String, String)>,
    Query(query): Query<ProofQuery>,
) -> axum::response::Response {
    let owner_meta_hash = hash_meta_address(&query.meta_address);

    let _pocket = match state.db.get_pocket_for_owner(&pocket_id, &owner_meta_hash) {
        Ok(Some(p)) => p,
        _ => return (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "Pocket not found"}))).into_response(),
    };

    // Generate proof (same logic as get_proof_handler)
    let proof = if route_id.starts_with("fund_") {
        let req = match state.db.get_funding_request(&route_id) {
            Ok(Some(r)) if r.owner_meta_hash == owner_meta_hash => r,
            _ => return (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "Route not found"}))).into_response(),
        };
        let maze_json = match state.db.get_maze_graph(&route_id) {
            Ok(j) => j,
            _ => return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": "Maze data unavailable"}))).into_response(),
        };
        generate_proof(&route_id, "funding", &maze_json, req.amount_lamports, &req.status, req.created_at, req.completed_at, req.tx_signature.as_deref(), req.destination_address.as_deref(), &state.config.master_key)
    } else if route_id.starts_with("sweep_") {
        let sweep_req = match state.db.get_sweep_request(&route_id) {
            Ok(Some(r)) => r,
            _ => return (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "Route not found"}))).into_response(),
        };
        let maze_json = match state.db.get_sweep_maze_graph(&route_id) {
            Ok(j) => j,
            _ => return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": "Maze data unavailable"}))).into_response(),
        };
        let sweep_tx_sig = state.db.get_sweep_final_tx_signature(&route_id).ok().flatten();
        generate_proof(&route_id, "sweep", &maze_json, sweep_req.3, &sweep_req.5, chrono::Utc::now().timestamp(), None, sweep_tx_sig.as_deref(), Some(&sweep_req.2), &state.config.master_key)
    } else if route_id.starts_with("p2p_") {
        let transfer = match state.db.get_p2p_transfer(&route_id) {
            Ok(Some(t)) if t.sender_meta_hash == owner_meta_hash => t,
            _ => return (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "Route not found"}))).into_response(),
        };
        let maze_json = match state.db.get_p2p_maze_graph(&route_id) {
            Ok(j) => j,
            _ => return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": "Maze data unavailable"}))).into_response(),
        };
        generate_proof(&route_id, "p2p", &maze_json, transfer.amount_lamports, &transfer.status, transfer.created_at, transfer.completed_at, transfer.tx_signature.as_deref(), Some(&transfer.receiver_pocket_id), &state.config.master_key)
    } else if route_id.starts_with("link_") {
        let link = match state.db.get_send_link(&route_id) {
            Ok(Some(l)) if l.owner_meta_hash == owner_meta_hash => l,
            _ => return (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "Route not found"}))).into_response(),
        };
        let maze_json = match link.funding_maze_json {
            Some(j) => j,
            None => return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": "Maze data unavailable"}))).into_response(),
        };
        generate_proof(&route_id, "send_link", &maze_json, link.amount_lamports, &link.status, link.created_at, link.claimed_at, link.refund_tx_signature.as_deref(), Some(&link.escrow_address), &state.config.master_key)
    } else {
        None
    };

    match proof {
        Some(p) => {
            let json_str = serde_json::to_string_pretty(&p).unwrap_or_default();
            let filename = format!("{}.json", p.proof_id);
            axum::response::Response::builder()
                .status(StatusCode::OK)
                .header("Content-Type", "application/json")
                .header("Content-Disposition", format!("attachment; filename=\"{}\"", filename))
                .body(axum::body::Body::from(json_str))
                .unwrap_or_else(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Error").into_response())
        }
        None => (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "Could not generate proof"}))).into_response(),
    }
}

// ============ TRANSACTION HISTORY ENDPOINT ============

#[derive(Debug, Deserialize)]
struct HistoryQuery {
    meta_address: String,
    tx_type: Option<String>,
    limit: Option<u32>,
}

#[derive(Debug, Serialize)]
struct HistoryEntry {
    id: String,
    tx_type: String,
    status: String,
    amount_lamports: Option<i64>,
    amount_display: Option<String>,
    tx_signature: Option<String>,
    description: Option<String>,
    created_at: i64,
    completed_at: Option<i64>,
    has_proof: bool,
}

#[derive(Debug, Serialize)]
struct HistoryResponse {
    success: bool,
    history: Vec<HistoryEntry>,
    count: usize,
}

async fn get_history_handler(
    State(state): State<Arc<AppState>>,
    Query(query): Query<HistoryQuery>,
) -> std::result::Result<Json<HistoryResponse>, AppError> {
    let owner_meta_hash = hash_meta_address(&query.meta_address);
    let limit = query.limit.unwrap_or(50).min(100);
    let tx_type_filter = query.tx_type.as_deref();

    let entries = state.db.get_transaction_history(&owner_meta_hash, tx_type_filter, limit)?;

    let history: Vec<HistoryEntry> = entries.into_iter().map(|(id, tx_type, status, amount, display, sig, desc, created, completed, has_proof)| {
        HistoryEntry {
            id,
            tx_type,
            status,
            amount_lamports: amount,
            amount_display: display,
            tx_signature: sig,
            description: desc,
            created_at: created,
            completed_at: completed,
            has_proof,
        }
    }).collect();

    let count = history.len();

    Ok(Json(HistoryResponse {
        success: true,
        history,
        count,
    }))
}

// ============ PROOF VERIFY ============

#[derive(Debug, Deserialize)]
struct VerifyProofRequest {
    proof: ProofOfPrivacy,
}

#[derive(Debug, Serialize)]
struct VerifyProofResponse {
    valid: bool,
    proof_id: String,
    route_type: String,
    privacy_grade: String,
    message: String,
}

async fn verify_proof_handler(
    State(state): State<Arc<AppState>>,
    Json(req): Json<VerifyProofRequest>,
) -> Json<VerifyProofResponse> {
    let proof = req.proof;
    let expected_sig = sign_proof(&proof, &state.config.master_key);
    let valid = expected_sig == proof.signature;

    Json(VerifyProofResponse {
        valid,
        proof_id: proof.proof_id.clone(),
        route_type: proof.route_type.clone(),
        privacy_grade: proof.privacy_grade.clone(),
        message: if valid {
            "Proof is valid and was issued by KausaLayer".to_string()
        } else {
            "Invalid proof - signature does not match".to_string()
        },
    })
}

// ============ KAUSA AI CHAT ============

#[derive(Debug, Deserialize)]
struct KausaChatRequest {
    messages: Vec<KausaChatMessage>,
    message: String,
    context: Option<KausaChatContext>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
struct KausaChatMessage {
    role: String,
    content: String,
}

#[derive(Debug, Deserialize)]
struct KausaChatContext {
    page: Option<String>,
    connected: Option<bool>,
    pocket_count: Option<u32>,
    active_operation: Option<String>,
    has_saved_wallets: Option<bool>,
}

#[derive(Debug, Serialize)]
struct KausaChatResponse {
    success: bool,
    reply: Option<String>,
    error: Option<String>,
}

async fn kausa_chat_handler(
    State(state): State<Arc<AppState>>,
    Json(req): Json<KausaChatRequest>,
) -> Json<KausaChatResponse> {
    // Check if Kausa is configured
    if state.openrouter_api_key.is_empty() || state.kausa_prompt.is_empty() {
        return Json(KausaChatResponse {
            success: false,
            reply: None,
            error: Some("Kausa AI is not configured".to_string()),
        });
    }

    // Build context string from user state
    let context_str = if let Some(ref ctx) = req.context {
        format!(
            "\n\nUser context: page={}, connected={}, pocket_count={}, active_operation={}, has_saved_wallets={}",
            ctx.page.as_deref().unwrap_or("unknown"),
            ctx.connected.unwrap_or(false),
            ctx.pocket_count.unwrap_or(0),
            ctx.active_operation.as_deref().unwrap_or("null"),
            ctx.has_saved_wallets.unwrap_or(false),
        )
    } else {
        String::new()
    };

    // Build messages array for OpenRouter
    let system_prompt = format!("{}{}", state.kausa_prompt, context_str);

    let mut messages = Vec::new();
    messages.push(serde_json::json!({
        "role": "system",
        "content": system_prompt,
    }));

    // Add conversation history
    for msg in &req.messages {
        messages.push(serde_json::json!({
            "role": msg.role,
            "content": msg.content,
        }));
    }

    // Add current message
    messages.push(serde_json::json!({
        "role": "user",
        "content": req.message,
    }));

    // Call OpenRouter API
    let body = serde_json::json!({
        "model": "anthropic/claude-sonnet-4",
        "messages": messages,
        "max_tokens": 1024,
        "temperature": 0.7,
    });

    let response = match state.http_client
        .post("https://openrouter.ai/api/v1/chat/completions")
        .header("Authorization", format!("Bearer {}", state.openrouter_api_key))
        .header("Content-Type", "application/json")
        .header("HTTP-Referer", "https://kausalayer.com")
        .header("X-Title", "KausaLayer")
        .json(&body)
        .send()
        .await
    {
        Ok(resp) => resp,
        Err(e) => {
            error!("Kausa chat: OpenRouter request failed: {}", e);
            return Json(KausaChatResponse {
                success: false,
                reply: None,
                error: Some("Failed to reach AI service".to_string()),
            });
        }
    };

    let status = response.status();
    let response_text = match response.text().await {
        Ok(t) => t,
        Err(e) => {
            error!("Kausa chat: failed to read response: {}", e);
            return Json(KausaChatResponse {
                success: false,
                reply: None,
                error: Some("Failed to read AI response".to_string()),
            });
        }
    };

    if !status.is_success() {
        error!("Kausa chat: OpenRouter returned {}: {}", status, &response_text[..200.min(response_text.len())]);
        return Json(KausaChatResponse {
            success: false,
            reply: None,
            error: Some(format!("AI service error ({})", status)),
        });
    }

    // Parse OpenRouter response
    let parsed: serde_json::Value = match serde_json::from_str(&response_text) {
        Ok(v) => v,
        Err(e) => {
            error!("Kausa chat: failed to parse response: {}", e);
            return Json(KausaChatResponse {
                success: false,
                reply: None,
                error: Some("Failed to parse AI response".to_string()),
            });
        }
    };

    // Extract reply text
    let reply = parsed["choices"][0]["message"]["content"]
        .as_str()
        .unwrap_or("")
        .to_string();

    if reply.is_empty() {
        return Json(KausaChatResponse {
            success: false,
            reply: None,
            error: Some("AI returned empty response".to_string()),
        });
    }

    Json(KausaChatResponse {
        success: true,
        reply: Some(reply),
        error: None,
    })
}

// ============ X ACCOUNT LINK HANDLERS ============

#[derive(Debug, Deserialize)]
struct LinkXAccountRequest {
    meta_address: String,
    x_user_id: String,
    x_username: Option<String>,
}

#[derive(Debug, Serialize)]
struct LinkXAccountResponse {
    success: bool,
    x_user_id: String,
    x_username: Option<String>,
    error: Option<String>,
}

#[derive(Debug, Serialize)]
struct XLinkStatusResponse {
    success: bool,
    linked: bool,
    x_user_id: Option<String>,
    x_username: Option<String>,
}

#[derive(Debug, Deserialize)]
struct XLinkStatusQuery {
    meta_address: String,
}

#[derive(Debug, Deserialize)]
struct UnlinkXAccountRequest {
    meta_address: String,
}

#[derive(Debug, Serialize)]
struct UnlinkXAccountResponse {
    success: bool,
    message: String,
}

/// Link X account to KausaLayer identity
async fn link_x_account_handler(
    State(state): State<Arc<AppState>>,
    Json(req): Json<LinkXAccountRequest>,
) -> std::result::Result<Json<LinkXAccountResponse>, AppError> {
    let owner_meta_hash = hash_meta_address(&req.meta_address);

    // Check if this X user is already linked to another account
    if let Some(existing) = state.db.get_x_link(&req.x_user_id)? {
        if existing.owner_meta_hash != req.meta_address && existing.owner_meta_hash != owner_meta_hash {
            return Ok(Json(LinkXAccountResponse {
                success: false,
                x_user_id: req.x_user_id,
                x_username: req.x_username,
                error: Some("This X account is already linked to another wallet".into()),
            }));
        }
    }

    let now = chrono::Utc::now().timestamp();
    let link = XAccountLink {
        x_user_id: req.x_user_id.clone(),
        owner_meta_hash: req.meta_address.clone(),
        x_username: req.x_username.clone(),
        linked_at: now,
        status: "active".to_string(),
    };

    state.db.link_x_account(&link)?;

    info!("X account {} linked", req.x_user_id);

    Ok(Json(LinkXAccountResponse {
        success: true,
        x_user_id: req.x_user_id,
        x_username: req.x_username,
        error: None,
    }))
}

/// Check X link status for current user
async fn x_link_status_handler(
    State(state): State<Arc<AppState>>,
    Query(query): Query<XLinkStatusQuery>,
) -> std::result::Result<Json<XLinkStatusResponse>, AppError> {
    // Search by raw meta_address (stored as-is in x_account_links)
    let owner_meta_hash = hash_meta_address(&query.meta_address);

    // Try hashed first, then raw (for bot-inserted records)
    let link = state.db.get_x_link_by_owner(&owner_meta_hash)?
        .or(state.db.get_x_link_by_owner(&query.meta_address)?);

    match link {
        Some(link) => Ok(Json(XLinkStatusResponse {
            success: true,
            linked: true,
            x_user_id: Some(link.x_user_id),
            x_username: link.x_username,
        })),
        None => Ok(Json(XLinkStatusResponse {
            success: true,
            linked: false,
            x_user_id: None,
            x_username: None,
        })),
    }
}

/// Unlink X account
async fn unlink_x_account_handler(
    State(state): State<Arc<AppState>>,
    Json(req): Json<UnlinkXAccountRequest>,
) -> std::result::Result<Json<UnlinkXAccountResponse>, AppError> {
    let owner_meta_hash = hash_meta_address(&req.meta_address);

    // Try hashed first, then raw (for bot-inserted records)
    let link = state.db.get_x_link_by_owner(&owner_meta_hash)?
        .or(state.db.get_x_link_by_owner(&req.meta_address)?);

    match link {
        Some(l) => {
            state.db.unlink_x_account(&l.x_user_id)?;
            info!("X account {} unlinked", l.x_user_id);
            Ok(Json(UnlinkXAccountResponse {
                success: true,
                message: "X account unlinked".to_string(),
            }))
        }
        None => Ok(Json(UnlinkXAccountResponse {
            success: false,
            message: "No X account linked".to_string(),
        })),
    }
}



// ============ X OAUTH 2.0 TOKEN EXCHANGE ============

#[derive(Debug, Deserialize)]
struct XOAuthTokenRequest {
    code: String,
    code_verifier: String,
    meta_address: String,
}

#[derive(Debug, Serialize)]
struct XOAuthTokenResponse {
    success: bool,
    x_user_id: Option<String>,
    x_username: Option<String>,
    error: Option<String>,
}

/// Exchange X OAuth 2.0 authorization code for user info and link account
async fn x_oauth_token_handler(
    State(state): State<Arc<AppState>>,
    Json(req): Json<XOAuthTokenRequest>,
) -> std::result::Result<Json<XOAuthTokenResponse>, AppError> {
    let client_id = std::env::var("X_OAUTH2_CLIENT_ID").unwrap_or_default();
    let client_secret = std::env::var("X_OAUTH2_CLIENT_SECRET").unwrap_or_default();
    let callback_url = std::env::var("X_OAUTH2_CALLBACK_URL")
        .unwrap_or_else(|_| "https://kausalayer.com/callback".to_string());

    if client_id.is_empty() || client_secret.is_empty() {
        return Ok(Json(XOAuthTokenResponse {
            success: false, x_user_id: None, x_username: None,
            error: Some("X OAuth not configured".into()),
        }));
    }

    info!("X OAuth token exchange request");

    // Exchange code for access token
    let token_resp = match state.http_client
        .post("https://api.x.com/2/oauth2/token")
        .basic_auth(&client_id, Some(&client_secret))
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", &req.code),
            ("redirect_uri", &callback_url),
            ("code_verifier", &req.code_verifier),
        ])
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            error!("X OAuth token request failed: {}", e);
            return Ok(Json(XOAuthTokenResponse {
                success: false, x_user_id: None, x_username: None,
                error: Some("Failed to contact X API".into()),
            }));
        }
    };

    let token_status = token_resp.status();
    let token_body: serde_json::Value = match token_resp.json().await {
        Ok(v) => v,
        Err(e) => {
            error!("X OAuth token parse failed: {}", e);
            return Ok(Json(XOAuthTokenResponse {
                success: false, x_user_id: None, x_username: None,
                error: Some("Failed to parse X token response".into()),
            }));
        }
    };

    if !token_status.is_success() {
        let err_desc = token_body["error_description"].as_str()
            .or(token_body["error"].as_str())
            .unwrap_or("Unknown error");
        error!("X OAuth token error {}: {}", token_status, err_desc);
        return Ok(Json(XOAuthTokenResponse {
            success: false, x_user_id: None, x_username: None,
            error: Some(format!("X auth failed: {}", err_desc)),
        }));
    }

    let access_token = match token_body["access_token"].as_str() {
        Some(t) => t.to_string(),
        None => return Ok(Json(XOAuthTokenResponse {
            success: false, x_user_id: None, x_username: None,
            error: Some("No access token in response".into()),
        })),
    };

    // Get user info
    let user_body: serde_json::Value = match state.http_client
        .get("https://api.x.com/2/users/me")
        .bearer_auth(&access_token)
        .send()
        .await
    {
        Ok(r) => match r.json().await {
            Ok(v) => v,
            Err(e) => {
                error!("X OAuth user parse failed: {}", e);
                return Ok(Json(XOAuthTokenResponse {
                    success: false, x_user_id: None, x_username: None,
                    error: Some("Failed to parse X user info".into()),
                }));
            }
        },
        Err(e) => {
            error!("X OAuth user info failed: {}", e);
            return Ok(Json(XOAuthTokenResponse {
                success: false, x_user_id: None, x_username: None,
                error: Some("Failed to get X user info".into()),
            }));
        }
    };

    let x_user_id = match user_body["data"]["id"].as_str() {
        Some(id) => id.to_string(),
        None => return Ok(Json(XOAuthTokenResponse {
            success: false, x_user_id: None, x_username: None,
            error: Some("Could not get X user ID".into()),
        })),
    };
    let x_username = user_body["data"]["username"].as_str().map(|s| s.to_string());

    // Link X account
    if let Some(existing) = state.db.get_x_link(&x_user_id)? {
        let owner_meta_hash = hash_meta_address(&req.meta_address);
        if existing.owner_meta_hash != req.meta_address && existing.owner_meta_hash != owner_meta_hash {
            return Ok(Json(XOAuthTokenResponse {
                success: false, x_user_id: Some(x_user_id), x_username,
                error: Some("This X account is already linked to another wallet".into()),
            }));
        }
    }

    let now = chrono::Utc::now().timestamp();
    let link = XAccountLink {
        x_user_id: x_user_id.clone(),
        owner_meta_hash: req.meta_address.clone(),
        x_username: x_username.clone(),
        linked_at: now,
        status: "active".to_string(),
    };
    state.db.link_x_account(&link)?;

    info!("X account {} (@{}) linked via OAuth", x_user_id, x_username.as_deref().unwrap_or("unknown"));

    Ok(Json(XOAuthTokenResponse {
        success: true,
        x_user_id: Some(x_user_id),
        x_username,
        error: None,
    }))
}


// ============ X OAUTH 2.0 SERVER-SIDE FLOW ============

fn base64_url_encode(data: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data)
}

#[derive(Debug, Deserialize)]
struct XOAuthAuthorizeQuery {
    meta_address: String,
}

/// Server-side: generate PKCE, store state, redirect user to X
async fn x_oauth_authorize_handler(
    Query(query): Query<XOAuthAuthorizeQuery>,
) -> axum::response::Response {
    let client_id = std::env::var("X_OAUTH2_CLIENT_ID").unwrap_or_default();
    let callback_url = std::env::var("X_OAUTH2_CALLBACK_URL")
        .unwrap_or_else(|_| "https://mazepocket.kausalayer.com/x/oauth/callback".to_string());

    if client_id.is_empty() {
        return axum::response::Redirect::temporary("https://kausalayer.com/callback?error=not_configured").into_response();
    }

    // Generate PKCE
    let verifier_bytes: [u8; 32] = rand::random();
    let code_verifier = base64_url_encode(&verifier_bytes);

    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(code_verifier.as_bytes());
    let code_challenge = base64_url_encode(&hasher.finalize());

    // Generate state
    let state_bytes: [u8; 16] = rand::random();
    let state = hex::encode(state_bytes);

    // Store verifier + meta_address in temp file
    let store_path = format!("/tmp/x_oauth_{}.json", state);
    let store_data = serde_json::json!({
        "code_verifier": code_verifier,
        "meta_address": query.meta_address,
        "created_at": chrono::Utc::now().timestamp()
    });
    let _ = std::fs::write(&store_path, store_data.to_string());

    let authorize_url = format!(
        "https://x.com/i/oauth2/authorize?response_type=code&client_id={}&redirect_uri={}&scope={}&state={}&code_challenge={}&code_challenge_method=S256",
        urlencoding::encode(&client_id),
        urlencoding::encode(&callback_url),
        urlencoding::encode("users.read tweet.read tweet.write offline.access"),
        urlencoding::encode(&state),
        urlencoding::encode(&code_challenge),
    );

    info!("X OAuth server-side authorize redirect, state={}", state);
    axum::response::Redirect::temporary(&authorize_url).into_response()
}

#[derive(Debug, Deserialize)]
struct XOAuthCallbackQuery {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
}

/// Server-side: X redirects here, exchange code for token, link account, redirect to frontend
async fn x_oauth_callback_handler(
    State(state): State<Arc<AppState>>,
    Query(query): Query<XOAuthCallbackQuery>,
) -> axum::response::Response {
    if let Some(ref err) = query.error {
        let r = format!("https://kausalayer.com/callback?error={}", urlencoding::encode(err));
        return axum::response::Redirect::temporary(&r).into_response();
    }

    let code = match &query.code {
        Some(c) => c.clone(),
        None => return axum::response::Redirect::temporary("https://kausalayer.com/callback?error=no_code").into_response(),
    };
    let state_param = match &query.state {
        Some(s) => s.clone(),
        None => return axum::response::Redirect::temporary("https://kausalayer.com/callback?error=no_state").into_response(),
    };

    // Load stored PKCE data
    let store_path = format!("/tmp/x_oauth_{}.json", state_param);
    let store_data = match std::fs::read_to_string(&store_path) {
        Ok(d) => d,
        Err(_) => return axum::response::Redirect::temporary("https://kausalayer.com/callback?error=invalid_state").into_response(),
    };
    let _ = std::fs::remove_file(&store_path);

    let stored: serde_json::Value = match serde_json::from_str(&store_data) {
        Ok(v) => v,
        Err(_) => return axum::response::Redirect::temporary("https://kausalayer.com/callback?error=corrupt_state").into_response(),
    };

    let code_verifier = stored["code_verifier"].as_str().unwrap_or_default().to_string();
    let meta_address = stored["meta_address"].as_str().unwrap_or_default().to_string();

    if code_verifier.is_empty() || meta_address.is_empty() {
        return axum::response::Redirect::temporary("https://kausalayer.com/callback?error=missing_data").into_response();
    }

    let client_id = std::env::var("X_OAUTH2_CLIENT_ID").unwrap_or_default();
    let client_secret = std::env::var("X_OAUTH2_CLIENT_SECRET").unwrap_or_default();
    let callback_url = std::env::var("X_OAUTH2_CALLBACK_URL")
        .unwrap_or_else(|_| "https://mazepocket.kausalayer.com/x/oauth/callback".to_string());

    // Exchange code for token
    let token_resp = match state.http_client
        .post("https://api.x.com/2/oauth2/token")
        .basic_auth(&client_id, Some(&client_secret))
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("redirect_uri", &callback_url),
            ("code_verifier", &code_verifier),
        ])
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            error!("X OAuth callback token request failed: {}", e);
            return axum::response::Redirect::temporary("https://kausalayer.com/callback?error=token_failed").into_response();
        }
    };

    let token_body: serde_json::Value = match token_resp.json().await {
        Ok(v) => v,
        Err(_) => return axum::response::Redirect::temporary("https://kausalayer.com/callback?error=token_parse_failed").into_response(),
    };

    let access_token = match token_body["access_token"].as_str() {
        Some(t) => t.to_string(),
        None => {
            let err = token_body["error_description"].as_str()
                .or(token_body["error"].as_str())
                .unwrap_or("unknown");
            error!("X OAuth no access_token: {}", err);
            let r = format!("https://kausalayer.com/callback?error={}", urlencoding::encode(err));
            return axum::response::Redirect::temporary(&r).into_response();
        }
    };

    // Get user info
    let user_body: serde_json::Value = match state.http_client
        .get("https://api.x.com/2/users/me")
        .bearer_auth(&access_token)
        .send()
        .await
    {
        Ok(r) => match r.json().await {
            Ok(v) => v,
            Err(_) => return axum::response::Redirect::temporary("https://kausalayer.com/callback?error=user_parse_failed").into_response(),
        },
        Err(_) => return axum::response::Redirect::temporary("https://kausalayer.com/callback?error=user_fetch_failed").into_response(),
    };

    let x_user_id = match user_body["data"]["id"].as_str() {
        Some(id) => id.to_string(),
        None => return axum::response::Redirect::temporary("https://kausalayer.com/callback?error=no_user_id").into_response(),
    };
    let x_username = user_body["data"]["username"].as_str().map(|s| s.to_string());

    // Check existing link
    if let Some(existing) = state.db.get_x_link(&x_user_id).unwrap_or(None) {
        let owner_meta_hash = hash_meta_address(&meta_address);
        if existing.owner_meta_hash != meta_address && existing.owner_meta_hash != owner_meta_hash {
            return axum::response::Redirect::temporary("https://kausalayer.com/callback?error=already_linked_other").into_response();
        }
    }

    // Link account
    let now = chrono::Utc::now().timestamp();
    let link = XAccountLink {
        x_user_id: x_user_id.clone(),
        owner_meta_hash: meta_address,
        x_username: x_username.clone(),
        linked_at: now,
        status: "active".to_string(),
    };

    if let Err(e) = state.db.link_x_account(&link) {
        error!("X OAuth link failed: {}", e);
        return axum::response::Redirect::temporary("https://kausalayer.com/callback?error=link_failed").into_response();
    }

    let uname = x_username.as_deref().unwrap_or(&x_user_id);
    info!("X account {} (@{}) linked via server-side OAuth", x_user_id, uname);

    let r = format!(
        "https://kausalayer.com/callback?success=true&x_username={}&x_user_id={}",
        urlencoding::encode(uname),
        urlencoding::encode(&x_user_id),
    );
    axum::response::Redirect::temporary(&r).into_response()
}


// ============ X OAUTH 1.0a SERVER-SIDE FLOW ============

#[derive(Debug, Deserialize)]
struct XOAuth1AuthorizeQuery {
    meta_address: String,
}

/// Step 1: Get request token from X, store it, redirect user to X authorize
async fn x_oauth1_authorize_handler(
    State(state): State<Arc<AppState>>,
    Query(query): Query<XOAuth1AuthorizeQuery>,
) -> axum::response::Response {
    let consumer_key = std::env::var("X_APP_KEY").unwrap_or_default();
    let consumer_secret = std::env::var("X_APP_SECRET").unwrap_or_default();
    let callback_url = std::env::var("X_OAUTH1_CALLBACK_URL")
        .unwrap_or_else(|_| "https://mazepocket.kausalayer.com/x/oauth1/callback".to_string());

    if consumer_key.is_empty() || consumer_secret.is_empty() {
        return axum::response::Redirect::temporary("https://kausalayer.com/callback?error=oauth1_not_configured").into_response();
    }

    // Build OAuth 1.0a request_token request
    let nonce_bytes: [u8; 16] = rand::random();
    let nonce = hex::encode(nonce_bytes);
    let timestamp = chrono::Utc::now().timestamp().to_string();

    // Parameters for signature
    let mut params = vec![
        ("oauth_callback", callback_url.as_str()),
        ("oauth_consumer_key", consumer_key.as_str()),
        ("oauth_nonce", nonce.as_str()),
        ("oauth_signature_method", "HMAC-SHA1"),
        ("oauth_timestamp", timestamp.as_str()),
        ("oauth_version", "1.0"),
    ];
    params.sort_by_key(|p| p.0);

    let param_string: String = params.iter()
        .map(|(k, v)| format!("{}={}", urlencoding::encode(k), urlencoding::encode(v)))
        .collect::<Vec<_>>()
        .join("&");

    let base_string = format!(
        "POST&{}&{}",
        urlencoding::encode("https://api.x.com/oauth/request_token"),
        urlencoding::encode(&param_string)
    );

    let signing_key = format!("{}&", urlencoding::encode(&consumer_secret));

    // HMAC-SHA1
    use hmac::{Hmac, Mac};
    use sha1::Sha1;
    type HmacSha1 = Hmac<Sha1>;
    let mut mac = HmacSha1::new_from_slice(signing_key.as_bytes()).unwrap();
    mac.update(base_string.as_bytes());
    let signature = base64_url_encode_standard(&mac.finalize().into_bytes());

    let auth_header = format!(
        r#"OAuth oauth_callback="{}", oauth_consumer_key="{}", oauth_nonce="{}", oauth_signature="{}", oauth_signature_method="HMAC-SHA1", oauth_timestamp="{}", oauth_version="1.0""#,
        urlencoding::encode(&callback_url),
        urlencoding::encode(&consumer_key),
        urlencoding::encode(&nonce),
        urlencoding::encode(&signature),
        urlencoding::encode(&timestamp),
    );

    let resp = match state.http_client
        .post("https://api.x.com/oauth/request_token")
        .header("Authorization", &auth_header)
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            error!("OAuth 1.0a request_token failed: {}", e);
            return axum::response::Redirect::temporary("https://kausalayer.com/callback?error=request_token_failed").into_response();
        }
    };

    let body = match resp.text().await {
        Ok(t) => t,
        Err(_) => return axum::response::Redirect::temporary("https://kausalayer.com/callback?error=request_token_parse").into_response(),
    };

    // Parse response: oauth_token=xxx&oauth_token_secret=xxx&oauth_callback_confirmed=true
    let parsed: std::collections::HashMap<String, String> = body.split('&')
        .filter_map(|pair| {
            let mut parts = pair.splitn(2, '=');
            Some((parts.next()?.to_string(), parts.next()?.to_string()))
        })
        .collect();

    let oauth_token = match parsed.get("oauth_token") {
        Some(t) => t.clone(),
        None => {
            error!("OAuth 1.0a no oauth_token in response: {}", body);
            return axum::response::Redirect::temporary("https://kausalayer.com/callback?error=no_request_token").into_response();
        }
    };
    let oauth_token_secret = parsed.get("oauth_token_secret").cloned().unwrap_or_default();

    // Store token_secret + meta_address
    let store_path = format!("/tmp/x_oauth1_{}.json", oauth_token);
    let store_data = serde_json::json!({
        "oauth_token_secret": oauth_token_secret,
        "meta_address": query.meta_address,
        "created_at": chrono::Utc::now().timestamp()
    });
    let _ = std::fs::write(&store_path, store_data.to_string());

    let authorize_url = format!("https://api.x.com/oauth/authorize?oauth_token={}", urlencoding::encode(&oauth_token));
    info!("OAuth 1.0a redirect to X authorize, token={}", &oauth_token[..10.min(oauth_token.len())]);

    axum::response::Redirect::temporary(&authorize_url).into_response()
}

fn base64_url_encode_standard(data: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(data)
}

#[derive(Debug, Deserialize)]
struct XOAuth1CallbackQuery {
    oauth_token: Option<String>,
    oauth_verifier: Option<String>,
    denied: Option<String>,
}

/// Step 2: X redirects here with oauth_token + oauth_verifier
async fn x_oauth1_callback_handler(
    State(state): State<Arc<AppState>>,
    Query(query): Query<XOAuth1CallbackQuery>,
) -> axum::response::Response {
    // User denied
    if query.denied.is_some() {
        return axum::response::Redirect::temporary("https://kausalayer.com/callback?error=denied").into_response();
    }

    let oauth_token = match &query.oauth_token {
        Some(t) => t.clone(),
        None => return axum::response::Redirect::temporary("https://kausalayer.com/callback?error=no_token").into_response(),
    };
    let oauth_verifier = match &query.oauth_verifier {
        Some(v) => v.clone(),
        None => return axum::response::Redirect::temporary("https://kausalayer.com/callback?error=no_verifier").into_response(),
    };

    // Load stored data
    let store_path = format!("/tmp/x_oauth1_{}.json", oauth_token);
    let store_data = match std::fs::read_to_string(&store_path) {
        Ok(d) => d,
        Err(_) => return axum::response::Redirect::temporary("https://kausalayer.com/callback?error=invalid_token").into_response(),
    };
    let _ = std::fs::remove_file(&store_path);

    let stored: serde_json::Value = match serde_json::from_str(&store_data) {
        Ok(v) => v,
        Err(_) => return axum::response::Redirect::temporary("https://kausalayer.com/callback?error=corrupt_data").into_response(),
    };

    let oauth_token_secret = stored["oauth_token_secret"].as_str().unwrap_or_default().to_string();
    let meta_address = stored["meta_address"].as_str().unwrap_or_default().to_string();

    if meta_address.is_empty() {
        return axum::response::Redirect::temporary("https://kausalayer.com/callback?error=no_meta").into_response();
    }

    let consumer_key = std::env::var("X_APP_KEY").unwrap_or_default();
    let consumer_secret = std::env::var("X_APP_SECRET").unwrap_or_default();

    // Exchange for access token
    let nonce_bytes: [u8; 16] = rand::random();
    let nonce = hex::encode(nonce_bytes);
    let timestamp = chrono::Utc::now().timestamp().to_string();

    let mut params = vec![
        ("oauth_consumer_key", consumer_key.as_str()),
        ("oauth_nonce", nonce.as_str()),
        ("oauth_signature_method", "HMAC-SHA1"),
        ("oauth_timestamp", timestamp.as_str()),
        ("oauth_token", oauth_token.as_str()),
        ("oauth_verifier", oauth_verifier.as_str()),
        ("oauth_version", "1.0"),
    ];
    params.sort_by_key(|p| p.0);

    let param_string: String = params.iter()
        .map(|(k, v)| format!("{}={}", urlencoding::encode(k), urlencoding::encode(v)))
        .collect::<Vec<_>>()
        .join("&");

    let base_string = format!(
        "POST&{}&{}",
        urlencoding::encode("https://api.x.com/oauth/access_token"),
        urlencoding::encode(&param_string)
    );

    let signing_key = format!("{}&{}", urlencoding::encode(&consumer_secret), urlencoding::encode(&oauth_token_secret));

    use hmac::{Hmac, Mac};
    use sha1::Sha1;
    type HmacSha1 = Hmac<Sha1>;
    let mut mac = HmacSha1::new_from_slice(signing_key.as_bytes()).unwrap();
    mac.update(base_string.as_bytes());
    let signature = base64_url_encode_standard(&mac.finalize().into_bytes());

    let auth_header = format!(
        r#"OAuth oauth_consumer_key="{}", oauth_nonce="{}", oauth_signature="{}", oauth_signature_method="HMAC-SHA1", oauth_timestamp="{}", oauth_token="{}", oauth_verifier="{}", oauth_version="1.0""#,
        urlencoding::encode(&consumer_key),
        urlencoding::encode(&nonce),
        urlencoding::encode(&signature),
        urlencoding::encode(&timestamp),
        urlencoding::encode(&oauth_token),
        urlencoding::encode(&oauth_verifier),
    );

    let resp = match state.http_client
        .post("https://api.x.com/oauth/access_token")
        .header("Authorization", &auth_header)
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            error!("OAuth 1.0a access_token failed: {}", e);
            return axum::response::Redirect::temporary("https://kausalayer.com/callback?error=access_token_failed").into_response();
        }
    };

    let body = match resp.text().await {
        Ok(t) => t,
        Err(_) => return axum::response::Redirect::temporary("https://kausalayer.com/callback?error=access_token_parse").into_response(),
    };

    let parsed: std::collections::HashMap<String, String> = body.split('&')
        .filter_map(|pair| {
            let mut parts = pair.splitn(2, '=');
            Some((parts.next()?.to_string(), parts.next()?.to_string()))
        })
        .collect();

    let x_user_id = match parsed.get("user_id") {
        Some(id) => id.clone(),
        None => {
            error!("OAuth 1.0a no user_id: {}", body);
            return axum::response::Redirect::temporary("https://kausalayer.com/callback?error=no_user_id").into_response();
        }
    };
    let x_username = parsed.get("screen_name").cloned();

    // Check existing link
    if let Some(existing) = state.db.get_x_link(&x_user_id).unwrap_or(None) {
        let owner_meta_hash = hash_meta_address(&meta_address);
        if existing.owner_meta_hash != meta_address && existing.owner_meta_hash != owner_meta_hash {
            return axum::response::Redirect::temporary("https://kausalayer.com/callback?error=already_linked_other").into_response();
        }
    }

    // Link account
    let now = chrono::Utc::now().timestamp();
    let link = XAccountLink {
        x_user_id: x_user_id.clone(),
        owner_meta_hash: meta_address,
        x_username: x_username.clone(),
        linked_at: now,
        status: "active".to_string(),
    };

    if let Err(e) = state.db.link_x_account(&link) {
        error!("OAuth 1.0a link failed: {}", e);
        return axum::response::Redirect::temporary("https://kausalayer.com/callback?error=link_failed").into_response();
    }

    let uname = x_username.as_deref().unwrap_or(&x_user_id);
    info!("X account {} (@{}) linked via OAuth 1.0a", x_user_id, uname);

    let r = format!(
        "https://kausalayer.com/callback?success=true&x_username={}&x_user_id={}",
        urlencoding::encode(uname),
        urlencoding::encode(&x_user_id),
    );
    axum::response::Redirect::temporary(&r).into_response()
}

// ============ PERPS POSITION MONITOR ============

async fn perps_position_monitor(state: Arc<AppState>) {
    info!("Starting perps position monitor task");

    loop {
        tokio::time::sleep(tokio::time::Duration::from_secs(30)).await;

        // Get all open positions from DB
        let positions = match state.db.get_all_open_perps_positions() {
            Ok(p) => p,
            Err(e) => {
                error!("Perps monitor: failed to get positions: {}", e);
                continue;
            }
        };

        if positions.is_empty() {
            continue;
        }

        // Group by pocket stealth_pubkey to minimize API calls
        let mut pocket_wallets: std::collections::HashMap<String, Vec<(String, String, String, f64, f64)>> = std::collections::HashMap::new();
        for (id, pocket_id, _owner, market, side, entry_price, liq_price, _pos_pubkey, _status) in &positions {
            // Get pocket stealth_pubkey
            if let Ok(Some(pocket)) = state.db.get_pocket(pocket_id) {
                pocket_wallets.entry(pocket.stealth_pubkey.clone())
                    .or_default()
                    .push((id.clone(), market.clone(), side.clone(), *entry_price, *liq_price));
            }
        }

        // For each unique wallet, fetch live positions from Jupiter
        for (wallet_address, db_positions) in &pocket_wallets {
            let live_result = match perps::get_positions(wallet_address).await {
                Ok(r) => r,
                Err(e) => {
                    warn!("Perps monitor: failed to fetch positions for {}: {}", &wallet_address[..20.min(wallet_address.len())], e);
                    continue;
                }
            };

            if !live_result.success {
                continue;
            }

            let live_positions = live_result.positions.unwrap_or_default();

            for (db_id, db_market, db_side, _db_entry, db_liq) in db_positions {
                // Find matching live position by market mint and side
                let live_match = live_positions.iter().find(|lp| {
                    lp.side.to_lowercase() == db_side.to_lowercase()
                });

                match live_match {
                    Some(live_pos) => {
                        // Update entry/liq prices in DB if they were 0 (initial)
                        if db_liq.abs() < 0.01 {
                            let _ = state.db.update_perps_position_prices(
                                db_id, live_pos.entry_price, live_pos.liquidation_price,
                            );
                        }

                        // Check liquidation proximity
                        let mark = live_pos.mark_price;
                        let liq = live_pos.liquidation_price;
                        if liq > 0.0 && mark > 0.0 {
                            let distance_pct = if db_side.to_lowercase() == "long" {
                                ((mark - liq) / mark) * 100.0
                            } else {
                                ((liq - mark) / mark) * 100.0
                            };

                            if distance_pct < 5.0 {
                                error!("LIQUIDATION CRITICAL: {} {} position {}, mark=${:.2}, liq=${:.2}, distance={:.1}%",
                                    db_side, db_market, db_id, mark, liq, distance_pct);
                            } else if distance_pct < 10.0 {
                                warn!("Liquidation warning: {} {} position {}, mark=${:.2}, liq=${:.2}, distance={:.1}%",
                                    db_side, db_market, db_id, mark, liq, distance_pct);
                            }
                        }
                    }
                    None => {
                        // Position not found on-chain — might have been liquidated or closed externally
                        warn!("Perps monitor: DB position {} ({} {}) not found on-chain, marking closed",
                            db_id, db_side, db_market);
                        let _ = state.db.update_perps_position_status(db_id, "closed_external", Some("Position not found on-chain"));
                    }
                }
            }
        }
    }
}

// ============ PERPS HANDLERS ============

#[derive(Debug, Deserialize)]
struct PerpsOpenPositionRequest {
    meta_address: String,
    asset: String,
    side: String,
    collateral_usdc: f64,
    leverage: f64,
}

#[derive(Debug, Serialize)]
struct PerpsOpenPositionResponse {
    success: bool,
    position_id: Option<String>,
    signature: Option<String>,
    position_pubkey: Option<String>,
    side: Option<String>,
    asset: Option<String>,
    collateral_usdc: Option<f64>,
    leverage: Option<f64>,
    size_usd: Option<f64>,
    error: Option<String>,
}

/// Open a perpetual position from a pocket
async fn perps_open_handler(
    State(state): State<Arc<AppState>>,
    Path(pocket_id): Path<String>,
    Json(req): Json<PerpsOpenPositionRequest>,
) -> std::result::Result<Json<PerpsOpenPositionResponse>, AppError> {
    let owner_meta_hash = hash_meta_address(&req.meta_address);

    let pocket = state.db.get_pocket_for_owner(&pocket_id, &owner_meta_hash)?
        .ok_or(MazeError::PocketNotFound(pocket_id.clone()))?;

    if pocket.status != PocketStatus::Active {
        return Ok(Json(PerpsOpenPositionResponse {
            success: false, position_id: None, signature: None, position_pubkey: None,
            side: None, asset: None, collateral_usdc: None, leverage: None, size_usd: None,
            error: Some(format!("Pocket status is {}, must be active", pocket.status.as_str())),
        }));
    }

    // Validate inputs
    let asset_upper = req.asset.to_uppercase();
    if !["SOL", "ETH", "BTC"].contains(&asset_upper.as_str()) {
        return Ok(Json(PerpsOpenPositionResponse {
            success: false, position_id: None, signature: None, position_pubkey: None,
            side: None, asset: None, collateral_usdc: None, leverage: None, size_usd: None,
            error: Some("Asset must be SOL, ETH, or BTC".to_string()),
        }));
    }

    let side = if req.side.to_lowercase() == "long" { "Long" } else { "Short" };

    if req.leverage < 1.1 || req.leverage > 100.0 {
        return Ok(Json(PerpsOpenPositionResponse {
            success: false, position_id: None, signature: None, position_pubkey: None,
            side: None, asset: None, collateral_usdc: None, leverage: None, size_usd: None,
            error: Some("Leverage must be between 1.1 and 100".to_string()),
        }));
    }

    if req.collateral_usdc < 10.0 {
        return Ok(Json(PerpsOpenPositionResponse {
            success: false, position_id: None, signature: None, position_pubkey: None,
            side: None, asset: None, collateral_usdc: None, leverage: None, size_usd: None,
            error: Some("Minimum collateral is 10 USDC".to_string()),
        }));
    }

    // Safety: max leverage cap for MVP
    if req.leverage > 20.0 {
        return Ok(Json(PerpsOpenPositionResponse {
            success: false, position_id: None, signature: None, position_pubkey: None,
            side: None, asset: None, collateral_usdc: None, leverage: None, size_usd: None,
            error: Some("Maximum leverage is 20x for safety. Higher leverage coming soon.".to_string()),
        }));
    }

    // Safety: max 3 open positions per pocket
    let existing_positions = state.db.get_perps_positions_by_pocket(&pocket_id)?;
    if existing_positions.len() >= 3 {
        return Ok(Json(PerpsOpenPositionResponse {
            success: false, position_id: None, signature: None, position_pubkey: None,
            side: None, asset: None, collateral_usdc: None, leverage: None, size_usd: None,
            error: Some("Maximum 3 open positions per pocket. Close a position first.".to_string()),
        }));
    }

    // Get pocket private key
    let keypair_bytes = state.db.decrypt(&pocket.keypair_encrypted)?;
    let _pocket_keypair = Keypair::from_bytes(&keypair_bytes)
        .map_err(|e| MazeError::KeypairError(e.to_string()))?;
    let private_key = bs58::encode(&keypair_bytes).into_string();

    info!("Perps open: {} {} {}x, {} USDC from pocket {}", side, asset_upper, req.leverage, req.collateral_usdc, pocket_id);

    // Call sidecar
    let result = perps::open_position(
        &private_key, &state.config.rpc_url,
        &asset_upper, side, req.collateral_usdc, req.leverage, None,
    ).await.map_err(|e| AppError(e))?;

    if !result.success {
        return Ok(Json(PerpsOpenPositionResponse {
            success: false, position_id: None, signature: None, position_pubkey: None,
            side: None, asset: None, collateral_usdc: None, leverage: None, size_usd: None,
            error: result.error,
        }));
    }

    // Store in DB
    let position_id = format!("perps_{}", &generate_pocket_id()[7..]);
    let size_usd = result.size_usd.unwrap_or(req.collateral_usdc * req.leverage);
    let _ = state.db.create_perps_position(
        &position_id, &pocket_id, &owner_meta_hash,
        &asset_upper, side, req.leverage, req.collateral_usdc,
        size_usd, 0.0, 0.0,
        result.position_pubkey.as_deref().unwrap_or(""),
        result.signature.as_deref(),
    );

    // Log transaction
    let _ = state.db.insert_transaction_log(
        &format!("perps_{}", chrono::Utc::now().timestamp_millis()),
        &owner_meta_hash, "perps_open", "completed",
        None,
        Some(&format!("{} USDC", req.collateral_usdc)),
        Some(&format!("Open {} {} {}x", side, asset_upper, req.leverage)),
        result.signature.as_deref(),
        None,
    );

    info!("Perps position opened: {} {} from pocket {}", side, asset_upper, pocket_id);

    Ok(Json(PerpsOpenPositionResponse {
        success: true,
        position_id: Some(position_id),
        signature: result.signature,
        position_pubkey: result.position_pubkey,
        side: Some(side.to_string()),
        asset: Some(asset_upper),
        collateral_usdc: Some(req.collateral_usdc),
        leverage: Some(req.leverage),
        size_usd: Some(size_usd),
        error: None,
    }))
}

#[derive(Debug, Deserialize)]
struct PerpsClosePositionRequest {
    meta_address: String,
    asset: String,
    side: String,
}

#[derive(Debug, Serialize)]
struct PerpsClosePositionResponse {
    success: bool,
    signature: Option<String>,
    position_pubkey: Option<String>,
    asset: Option<String>,
    side: Option<String>,
    error: Option<String>,
}

/// Close a perpetual position
async fn perps_close_handler(
    State(state): State<Arc<AppState>>,
    Path(pocket_id): Path<String>,
    Json(req): Json<PerpsClosePositionRequest>,
) -> std::result::Result<Json<PerpsClosePositionResponse>, AppError> {
    let owner_meta_hash = hash_meta_address(&req.meta_address);

    let pocket = state.db.get_pocket_for_owner(&pocket_id, &owner_meta_hash)?
        .ok_or(MazeError::PocketNotFound(pocket_id.clone()))?;

    if pocket.status != PocketStatus::Active {
        return Ok(Json(PerpsClosePositionResponse {
            success: false, signature: None, position_pubkey: None,
            asset: None, side: None,
            error: Some(format!("Pocket status is {}, must be active", pocket.status.as_str())),
        }));
    }

    let asset_upper = req.asset.to_uppercase();
    let side = if req.side.to_lowercase() == "long" { "Long" } else { "Short" };

    let keypair_bytes = state.db.decrypt(&pocket.keypair_encrypted)?;
    let private_key = bs58::encode(&keypair_bytes).into_string();

    info!("Perps close: {} {} from pocket {}", side, asset_upper, pocket_id);

    let result = perps::close_position(
        &private_key, &state.config.rpc_url,
        &asset_upper, side, None,
    ).await.map_err(|e| AppError(e))?;

    if !result.success {
        return Ok(Json(PerpsClosePositionResponse {
            success: false, signature: None, position_pubkey: None,
            asset: None, side: None, error: result.error,
        }));
    }

    // Update DB - find and close position
    if let Ok(Some(pos)) = state.db.find_perps_position(&pocket_id, &asset_upper, side) {
        let _ = state.db.close_perps_position(&pos.0, None, result.signature.as_deref());
    }

    // Log transaction
    let _ = state.db.insert_transaction_log(
        &format!("perps_{}", chrono::Utc::now().timestamp_millis()),
        &owner_meta_hash, "perps_close", "completed",
        None, None,
        Some(&format!("Close {} {}", side, asset_upper)),
        result.signature.as_deref(),
        None,
    );

    info!("Perps position closed: {} {} from pocket {}", side, asset_upper, pocket_id);

    Ok(Json(PerpsClosePositionResponse {
        success: true,
        signature: result.signature,
        position_pubkey: result.position_pubkey,
        asset: Some(asset_upper),
        side: Some(side.to_string()),
        error: None,
    }))
}

#[derive(Debug, Deserialize)]
struct PerpsPositionsQuery {
    meta_address: String,
}

#[derive(Debug, Serialize)]
struct PerpsPositionsApiResponse {
    success: bool,
    positions: Vec<serde_json::Value>,
    count: usize,
    error: Option<String>,
}

/// Get perps positions for a pocket (live from Jupiter API)
async fn perps_positions_handler(
    State(state): State<Arc<AppState>>,
    Path(pocket_id): Path<String>,
    Query(query): Query<PerpsPositionsQuery>,
) -> std::result::Result<Json<PerpsPositionsApiResponse>, AppError> {
    let owner_meta_hash = hash_meta_address(&query.meta_address);

    let pocket = state.db.get_pocket_for_owner(&pocket_id, &owner_meta_hash)?
        .ok_or(MazeError::PocketNotFound(pocket_id.clone()))?;

    let result = perps::get_positions(&pocket.stealth_pubkey).await
        .map_err(|e| AppError(e))?;

    if !result.success {
        return Ok(Json(PerpsPositionsApiResponse {
            success: false, positions: vec![], count: 0, error: result.error,
        }));
    }

    let positions: Vec<serde_json::Value> = result.positions.unwrap_or_default().iter().map(|p| {
        serde_json::json!({
            "position_pubkey": p.position_pubkey,
            "side": p.side,
            "asset_mint": p.asset_mint,
            "collateral_usd": p.collateral_usd,
            "size_usd": p.size_usd,
            "entry_price": p.entry_price,
            "mark_price": p.mark_price,
            "liquidation_price": p.liquidation_price,
            "leverage": p.leverage,
            "pnl_usd": p.pnl_usd,
            "pnl_pct": p.pnl_pct,
            "borrow_fees_usd": p.borrow_fees_usd,
            "close_fees_usd": p.close_fees_usd,
        })
    }).collect();

    let count = positions.len();

    Ok(Json(PerpsPositionsApiResponse {
        success: true,
        positions,
        count,
        error: None,
    }))
}

#[derive(Debug, Deserialize)]
struct PerpsMarketQuery {
    asset: String,
}

/// Get perps market data
async fn perps_market_handler(
    Query(query): Query<PerpsMarketQuery>,
) -> std::result::Result<Json<serde_json::Value>, AppError> {
    let result = perps::get_market(&query.asset).await
        .map_err(|e| AppError(e))?;

    Ok(Json(serde_json::json!({
        "success": result.success,
        "data": {
            "asset": result.asset,
            "price": result.price,
            "price_change_24h": result.price_change_24h,
            "high_24h": result.high_24h,
            "low_24h": result.low_24h,
            "volume_24h": result.volume_24h,
            "open_fee_pct": result.open_fee_pct,
            "long_borrow_rate_pct": result.long_borrow_rate_pct,
            "short_borrow_rate_pct": result.short_borrow_rate_pct,
            "long_utilization_pct": result.long_utilization_pct,
            "short_utilization_pct": result.short_utilization_pct,
            "long_available_liquidity": result.long_available_liquidity,
            "short_available_liquidity": result.short_available_liquidity,
        },
        "error": result.error,
    })))
}

#[derive(Debug, Deserialize)]
struct PerpsEstimateRequest {
    meta_address: String,
    asset: String,
    side: String,
    collateral_usdc: f64,
    leverage: f64,
}

/// Estimate perps position before opening
async fn perps_estimate_handler(
    State(state): State<Arc<AppState>>,
    Path(pocket_id): Path<String>,
    Json(req): Json<PerpsEstimateRequest>,
) -> std::result::Result<Json<serde_json::Value>, AppError> {
    let owner_meta_hash = hash_meta_address(&req.meta_address);

    let pocket = state.db.get_pocket_for_owner(&pocket_id, &owner_meta_hash)?
        .ok_or(MazeError::PocketNotFound(pocket_id.clone()))?;

    let result = perps::estimate_position(
        &pocket.stealth_pubkey, &req.asset, &req.side,
        req.collateral_usdc, req.leverage, None,
    ).await.map_err(|e| AppError(e))?;

    Ok(Json(serde_json::json!({
        "success": result.success,
        "data": {
            "entry_price": result.entry_price,
            "leverage": result.leverage,
            "liquidation_price": result.liquidation_price,
            "open_fee_usd": result.open_fee_usd,
            "price_impact_fee_usd": result.price_impact_fee_usd,
            "borrow_fee_usd": result.borrow_fee_usd,
            "position_size_usd": result.position_size_usd,
            "collateral_usd": result.collateral_usd,
        },
        "error": result.error,
    })))
}

// ============ PERPS EXTENDED HANDLERS ============

#[derive(Debug, Deserialize)]
struct PerpsSetTpslRequest {
    meta_address: String,
    position_pubkey: String,
    tp_price: Option<f64>,
    sl_price: Option<f64>,
}

async fn perps_set_tpsl_handler(
    State(state): State<Arc<AppState>>,
    Path(pocket_id): Path<String>,
    Json(req): Json<PerpsSetTpslRequest>,
) -> std::result::Result<Json<serde_json::Value>, AppError> {
    let owner_meta_hash = hash_meta_address(&req.meta_address);
    let pocket = state.db.get_pocket_for_owner(&pocket_id, &owner_meta_hash)?
        .ok_or(MazeError::PocketNotFound(pocket_id.clone()))?;

    let keypair_bytes = state.db.decrypt(&pocket.keypair_encrypted)?;
    let private_key = bs58::encode(&keypair_bytes).into_string();

    let result = perps::set_tpsl(&private_key, &state.config.rpc_url, &req.position_pubkey, req.tp_price, req.sl_price)
        .await.map_err(|e| AppError(e))?;
    Ok(Json(result))
}

#[derive(Debug, Deserialize)]
struct PerpsCancelTpslRequest {
    meta_address: String,
    position_request_pubkey: String,
}

async fn perps_cancel_tpsl_handler(
    State(state): State<Arc<AppState>>,
    Path(pocket_id): Path<String>,
    Json(req): Json<PerpsCancelTpslRequest>,
) -> std::result::Result<Json<serde_json::Value>, AppError> {
    let owner_meta_hash = hash_meta_address(&req.meta_address);
    let pocket = state.db.get_pocket_for_owner(&pocket_id, &owner_meta_hash)?
        .ok_or(MazeError::PocketNotFound(pocket_id.clone()))?;

    let keypair_bytes = state.db.decrypt(&pocket.keypair_encrypted)?;
    let private_key = bs58::encode(&keypair_bytes).into_string();

    let result = perps::cancel_tpsl(&private_key, &state.config.rpc_url, &req.position_request_pubkey)
        .await.map_err(|e| AppError(e))?;
    Ok(Json(result))
}

#[derive(Debug, Deserialize)]
struct PerpsLimitOrderRequest {
    meta_address: String,
    asset: String,
    side: String,
    collateral_usdc: f64,
    leverage: f64,
    trigger_price: f64,
}

async fn perps_limit_order_handler(
    State(state): State<Arc<AppState>>,
    Path(pocket_id): Path<String>,
    Json(req): Json<PerpsLimitOrderRequest>,
) -> std::result::Result<Json<serde_json::Value>, AppError> {
    let owner_meta_hash = hash_meta_address(&req.meta_address);
    let pocket = state.db.get_pocket_for_owner(&pocket_id, &owner_meta_hash)?
        .ok_or(MazeError::PocketNotFound(pocket_id.clone()))?;

    let keypair_bytes = state.db.decrypt(&pocket.keypair_encrypted)?;
    let private_key = bs58::encode(&keypair_bytes).into_string();

    let result = perps::limit_order(
        &private_key, &state.config.rpc_url,
        &req.asset.to_uppercase(), &req.side, req.collateral_usdc, req.leverage, req.trigger_price,
    ).await.map_err(|e| AppError(e))?;
    Ok(Json(result))
}

#[derive(Debug, Deserialize)]
struct PerpsPartialCloseRequest {
    meta_address: String,
    position_pubkey: String,
    size_usd_delta: Option<f64>,
    collateral_usd_delta: Option<f64>,
}

async fn perps_partial_close_handler(
    State(state): State<Arc<AppState>>,
    Path(pocket_id): Path<String>,
    Json(req): Json<PerpsPartialCloseRequest>,
) -> std::result::Result<Json<serde_json::Value>, AppError> {
    let owner_meta_hash = hash_meta_address(&req.meta_address);
    let pocket = state.db.get_pocket_for_owner(&pocket_id, &owner_meta_hash)?
        .ok_or(MazeError::PocketNotFound(pocket_id.clone()))?;

    let keypair_bytes = state.db.decrypt(&pocket.keypair_encrypted)?;
    let private_key = bs58::encode(&keypair_bytes).into_string();

    let result = perps::partial_close(
        &private_key, &state.config.rpc_url,
        &req.position_pubkey, req.size_usd_delta, req.collateral_usd_delta,
    ).await.map_err(|e| AppError(e))?;
    Ok(Json(result))
}

async fn perps_close_all_handler(
    State(state): State<Arc<AppState>>,
    Path(pocket_id): Path<String>,
    Json(req): Json<serde_json::Value>,
) -> std::result::Result<Json<serde_json::Value>, AppError> {
    let meta_address = req.get("meta_address").and_then(|v| v.as_str()).unwrap_or("");
    let owner_meta_hash = hash_meta_address(meta_address);
    let pocket = state.db.get_pocket_for_owner(&pocket_id, &owner_meta_hash)?
        .ok_or(MazeError::PocketNotFound(pocket_id.clone()))?;

    let keypair_bytes = state.db.decrypt(&pocket.keypair_encrypted)?;
    let private_key = bs58::encode(&keypair_bytes).into_string();

    let result = perps::close_all(&private_key, &state.config.rpc_url)
        .await.map_err(|e| AppError(e))?;
    Ok(Json(result))
}

#[derive(Debug, Deserialize)]
struct PerpsTradeHistoryQuery {
    meta_address: String,
    asset: Option<String>,
    side: Option<String>,
}

async fn perps_trade_history_handler(
    State(state): State<Arc<AppState>>,
    Path(pocket_id): Path<String>,
    Query(query): Query<PerpsTradeHistoryQuery>,
) -> std::result::Result<Json<serde_json::Value>, AppError> {
    let owner_meta_hash = hash_meta_address(&query.meta_address);
    let pocket = state.db.get_pocket_for_owner(&pocket_id, &owner_meta_hash)?
        .ok_or(MazeError::PocketNotFound(pocket_id.clone()))?;

    let result = perps::trade_history(
        &pocket.stealth_pubkey,
        query.asset.as_deref(),
        query.side.as_deref(),
    ).await.map_err(|e| AppError(e))?;
    Ok(Json(result))
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

    // Load Kausa AI prompt
    let kausa_prompt = std::fs::read_to_string("kausa-prompt.txt")
        .unwrap_or_else(|e| {
            warn!("Failed to load kausa-prompt.txt: {}, using empty prompt", e);
            String::new()
        });
    info!("Kausa AI prompt loaded ({} bytes)", kausa_prompt.len());

    // Load OpenRouter API key
    let openrouter_api_key = std::env::var("OPENROUTER_API_KEY")
        .unwrap_or_default();
    if openrouter_api_key.is_empty() {
        warn!("OPENROUTER_API_KEY not set, Kausa chat endpoint will be disabled");
    }

    // Create app state
    let http_client = reqwest::Client::new();
    let state = Arc::new(AppState { db, rpc, config: config.clone(), pool_lock: Arc::new(tokio::sync::Semaphore::new(1)), http_client, kausa_prompt, openrouter_api_key });

    // Start deposit monitor
    let monitor_state = state.clone();
    tokio::spawn(async move {
        deposit_monitor(monitor_state).await;
    });
    info!("Deposit monitor started");

    // Start perps position monitor
    let perps_monitor_state = state.clone();
    tokio::spawn(async move {
        perps_position_monitor(perps_monitor_state).await;
    });
    info!("Perps position monitor started");

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
        .route("/pocket/:pocket_id/send", post(send_to_pocket))
        .route("/pocket/:pocket_id/spawn", post(spawn_pocket))
        .route("/p2p/:transfer_id/status", get(get_p2p_status))
        .route("/p2p/:transfer_id/recover", post(recover_p2p_transfer))
        .route("/wallet", post(add_wallet))
        .route("/wallet/:slot", axum::routing::delete(delete_wallet))
        .route("/contact", post(add_contact))
        .route("/contacts", get(list_contacts))
        .route("/contact/:alias", axum::routing::delete(delete_contact))
        .route("/mcp/register", post(mcp_register))
        .route("/mcp/validate-key", post(mcp_validate_key))
        .route("/tier-config", get(tier_config))
        .route("/route-history", get(get_route_history))
        .route("/usage-stats", get(get_usage_stats))
        .route("/airdrop/verify", get(airdrop_verify))
        .route("/pocket/:pocket_id/transactions", get(get_pocket_transactions))
        .route("/admin/partners", get(list_partners_handler))
        .route("/admin/partners", post(add_partner_handler))
        .route("/admin/partners/:id", axum::routing::delete(delete_partner_handler))
        .route("/pocket/:pocket_id/token-balances", get(token_balances_handler))
        .route("/pocket/:pocket_id/swap/quote", get(swap_quote_handler))
        .route("/pocket/:pocket_id/swap", post(swap_execute_handler))
        .route("/tokens", get(token_list_handler))
        .route("/token/resolve", get(token_resolve_handler))
        .route("/pocket/:pocket_id/printr/create", post(printr_create_handler))
        .route("/printr/deployment", get(printr_deployment_handler))
        .route("/printr/token", get(printr_token_info_handler))
        .route("/pocket/:pocket_id/conduit/discover", post(conduit_discover_handler))
        .route("/pocket/:pocket_id/conduit/call", post(conduit_call_handler))
        .route("/pocket/:pocket_id/usepod/register", post(usepod_register_handler))
        .route("/pocket/:pocket_id/usepod/fund", post(usepod_fund_handler))
        .route("/preferences/maze", post(get_maze_preferences_handler))
        .route("/preferences/maze/save", post(save_maze_preferences_handler))
        .route("/pocket/:pocket_id/pay", post(kausa_pay_handler))
        .route("/pocket/:pocket_id/gate/register", post(gate_register))
        .route("/pocket/:pocket_id/gate/endpoints", get(gate_list_by_pocket))
        .route("/pocket/:pocket_id/gate/endpoint", axum::routing::delete(gate_delete))
        .route("/gate/endpoints", get(gate_list_all))
        .route("/gate/yaml/:endpoint_id", get(gate_get_yaml))
        .route("/pocket/:pocket_id/proof/:route_id", get(get_proof_handler))
        .route("/pocket/:pocket_id/proof/:route_id/download", get(download_proof_handler))
        .route("/history", get(get_history_handler))
        .route("/proof/verify", post(verify_proof_handler))
        .route("/send-link/create", post(create_send_link))
        .route("/send-link/:id", get(get_send_link_info))
        .route("/send-link/:id/claim", post(claim_send_link))
        .route("/send-links", get(list_send_links))
        .route("/x/link", post(link_x_account_handler))
        .route("/x/link-status", get(x_link_status_handler))
        .route("/x/unlink", post(unlink_x_account_handler))
        .route("/x/oauth/token", post(x_oauth_token_handler))
        .route("/x/oauth/authorize", get(x_oauth_authorize_handler))
        .route("/x/oauth/callback", get(x_oauth_callback_handler))
        .route("/x/oauth1/authorize", get(x_oauth1_authorize_handler))
        .route("/x/oauth1/callback", get(x_oauth1_callback_handler))
        .route("/api/chat", post(kausa_chat_handler))
        .route("/pocket/:pocket_id/evm-info", get(evm_info_handler))
        .route("/pocket/:pocket_id/evm-export", post(evm_export_handler))
        .route("/pocket/:pocket_id/cross-swap", post(cross_swap_handler))
        .route("/pocket/:pocket_id/cross-swap-sell", post(cross_swap_sell_handler))
        .route("/pocket/:pocket_id/cross-swap-status", get(cross_swap_status_handler))
        .route("/resolve-token/:address", get(resolve_token_handler))
        .route("/pocket/:pocket_id/perps/open", post(perps_open_handler))
        .route("/pocket/:pocket_id/perps/close", post(perps_close_handler))
        .route("/pocket/:pocket_id/perps/positions", get(perps_positions_handler))
        .route("/pocket/:pocket_id/perps/estimate", post(perps_estimate_handler))
        .route("/perps/market", get(perps_market_handler))
        .route("/pocket/:pocket_id/perps/tpsl", post(perps_set_tpsl_handler))
        .route("/pocket/:pocket_id/perps/tpsl/cancel", post(perps_cancel_tpsl_handler))
        .route("/pocket/:pocket_id/perps/limit-order", post(perps_limit_order_handler))
        .route("/pocket/:pocket_id/perps/partial-close", post(perps_partial_close_handler))
        .route("/pocket/:pocket_id/perps/close-all", post(perps_close_all_handler))
        .route("/pocket/:pocket_id/perps/trades", get(perps_trade_history_handler))
        .route("/pocket/:pocket_id/genesis/deposit", post(genesis_deposit_handler))
        .route("/pocket/:pocket_id/genesis/claim", post(genesis_claim_handler))
        .route("/pocket/:pocket_id/genesis/buy", post(genesis_buy_handler))
        .route("/pocket/:pocket_id/genesis/activate", post(genesis_activate_handler))
        .route("/pocket/:pocket_id/genesis/sell", post(genesis_sell_handler))
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

// ============ AIRDROP VERIFICATION ============

#[derive(Debug, Deserialize)]
struct AirdropVerifyQuery {
    meta_address: String,
    start_time: Option<i64>,
    end_time: Option<i64>,
}

#[derive(Debug, Serialize)]
struct AirdropVerifyResponse {
    success: bool,
    pockets_created: i64,
    routes_completed: i64,
    funding_volume_lamports: u64,
    funding_volume_sol: f64,
    sweeps_completed: i64,
    unique_destinations: i64,
    p2p_completed: i64,
    p2p_volume_lamports: u64,
    p2p_volume_sol: f64,
    total_volume_sol: f64,
    first_activity: Option<i64>,
    last_activity: Option<i64>,
    points: AirdropPoints,
    tier: String,
}

#[derive(Debug, Serialize)]
struct AirdropPoints {
    pocket_creation: i64,
    maze_routes: i64,
    sweeps: i64,
    p2p_transfers: i64,
    volume_bonus: i64,
    multi_route_bonus: i64,
    total: i64,
    multiplier: f64,
    final_total: i64,
}

async fn airdrop_verify(
    State(state): State<Arc<AppState>>,
    Query(query): Query<AirdropVerifyQuery>,
) -> std::result::Result<Json<AirdropVerifyResponse>, AppError> {
    let owner_meta_hash = hash_meta_address(&query.meta_address);

    // Default: all time if no range specified
    let start_time = query.start_time.unwrap_or(0);
    let end_time = query.end_time.unwrap_or(i64::MAX);

    let stats = state.db.get_airdrop_stats(&owner_meta_hash, start_time, end_time)?;

    // Calculate points (no cap - reward all activity)
    let pocket_points = stats.pockets_created * 100;
    let route_points = stats.routes_completed * 150;
    let sweep_points = stats.sweeps_completed * 100;
    let p2p_points = stats.p2p_completed * 75;

    // Volume bonus: 100 pts per 0.5 SOL routed (no cap)
    let total_volume_lamports = stats.funding_volume_lamports + stats.p2p_volume_lamports;
    let volume_bonus = ((total_volume_lamports as f64 / 500_000_000.0) as i64) * 100;

    // Multi-route bonus: 200 pts if 3+ distinct routes
    let multi_route_bonus = if stats.routes_completed >= 3 { 200 } else { 0 };

    let total_points = pocket_points + route_points + sweep_points + p2p_points + volume_bonus + multi_route_bonus;

    // Determine tier based on activity thresholds
    let tier = if stats.routes_completed >= 100 && stats.sweeps_completed >= 100 && stats.p2p_completed >= 100 {
        "Pioneer"
    } else if stats.routes_completed >= 50 && stats.sweeps_completed >= 50 && stats.p2p_completed >= 50 {
        "Explorer"
    } else if stats.routes_completed >= 25 && stats.sweeps_completed >= 25 && stats.p2p_completed >= 25 {
        "Navigator"
    } else {
        "Observer"
    };

    // Tier multiplier
    let multiplier: f64 = match tier {
        "Pioneer" => 3.0,
        "Explorer" => 2.0,
        "Navigator" => 1.5,
        _ => 1.0,
    };
    let final_total = (total_points as f64 * multiplier) as i64;

    let total_volume_sol = lamports_to_sol(total_volume_lamports);

    Ok(Json(AirdropVerifyResponse {
        success: true,
        pockets_created: stats.pockets_created,
        routes_completed: stats.routes_completed,
        funding_volume_lamports: stats.funding_volume_lamports,
        funding_volume_sol: lamports_to_sol(stats.funding_volume_lamports),
        sweeps_completed: stats.sweeps_completed,
        unique_destinations: stats.unique_destinations,
        p2p_completed: stats.p2p_completed,
        p2p_volume_lamports: stats.p2p_volume_lamports,
        p2p_volume_sol: lamports_to_sol(stats.p2p_volume_lamports),
        total_volume_sol,
        first_activity: stats.first_activity,
        last_activity: stats.last_activity,
        points: AirdropPoints {
            pocket_creation: pocket_points,
            maze_routes: route_points,
            sweeps: sweep_points,
            p2p_transfers: p2p_points,
            volume_bonus,
            multi_route_bonus,
            total: total_points,
            multiplier,
            final_total,
        },
        tier: tier.to_string(),
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
    meta_address: Option<String>,
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
    
    // Store in database - use meta_address from frontend if provided, otherwise hash wallet address
    let raw_meta = req.meta_address.as_deref().filter(|m| !m.is_empty());
    let owner_meta_hash = match raw_meta {
        Some(meta) => hash_meta_address(meta),
        None => hash_meta_address(&req.wallet_address),
    };
    state.db.store_mcp_api_key(&api_key_hash, &req.wallet_address, &owner_meta_hash, raw_meta)?;
    
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
    meta_address: Option<String>,
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
    match state.db.validate_mcp_api_key_full(&api_key_hash) {
        Ok(Some((wallet_address, raw_meta))) => Json(McpValidateKeyResponse {
            valid: true,
            wallet_address: Some(wallet_address),
            meta_address: raw_meta,
        }),
        _ => Json(McpValidateKeyResponse {
            valid: false,
            wallet_address: None,
            meta_address: None,
        }),
    }
}

// ============ CONTACT BOOK ============

#[derive(Debug, Deserialize)]
struct AddContactRequest {
    meta_address: String,
    alias: String,
    pocket_id: String,
    label: Option<String>,
}

#[derive(Debug, Serialize)]
struct AddContactResponse {
    success: bool,
    alias: String,
    pocket_id: String,
}

#[derive(Debug, Deserialize)]
struct ListContactsQuery {
    meta_address: String,
}

#[derive(Debug, Serialize)]
struct ContactInfo {
    alias: String,
    pocket_id: String,
    label: Option<String>,
    created_at: i64,
}

#[derive(Debug, Serialize)]
struct ListContactsResponse {
    success: bool,
    contacts: Vec<ContactInfo>,
    count: usize,
}

#[derive(Debug, Deserialize)]
struct DeleteContactQuery {
    meta_address: String,
}

#[derive(Debug, Serialize)]
struct DeleteContactResponse {
    success: bool,
    deleted: bool,
}

async fn add_contact(
    State(state): State<Arc<AppState>>,
    Json(req): Json<AddContactRequest>,
) -> std::result::Result<Json<AddContactResponse>, AppError> {
    let owner_meta_hash = hash_meta_address(&req.meta_address);

    // Validate alias format (must start with @)
    let alias = if req.alias.starts_with('@') {
        req.alias.clone()
    } else {
        format!("@{}", req.alias)
    };

    // Validate pocket_id format
    if !req.pocket_id.starts_with("pocket_") {
        return Err(MazeError::InvalidParameters("Invalid pocket ID format".into()).into());
    }

    let now = chrono::Utc::now().timestamp();
    let contact = Contact {
        owner_meta_hash,
        alias: alias.clone(),
        pocket_id: req.pocket_id.clone(),
        label: req.label,
        created_at: now,
    };

    state.db.add_contact(&contact)?;

    info!("Contact {} added: {}", alias, req.pocket_id);

    Ok(Json(AddContactResponse {
        success: true,
        alias,
        pocket_id: req.pocket_id,
    }))
}

async fn list_contacts(
    State(state): State<Arc<AppState>>,
    Query(query): Query<ListContactsQuery>,
) -> std::result::Result<Json<ListContactsResponse>, AppError> {
    let owner_meta_hash = hash_meta_address(&query.meta_address);
    let contacts = state.db.list_contacts(&owner_meta_hash)?;

    let contact_infos: Vec<ContactInfo> = contacts.iter().map(|c| ContactInfo {
        alias: c.alias.clone(),
        pocket_id: c.pocket_id.clone(),
        label: c.label.clone(),
        created_at: c.created_at,
    }).collect();

    let count = contact_infos.len();

    Ok(Json(ListContactsResponse {
        success: true,
        contacts: contact_infos,
        count,
    }))
}

async fn delete_contact(
    State(state): State<Arc<AppState>>,
    Path(alias): Path<String>,
    Query(query): Query<DeleteContactQuery>,
) -> std::result::Result<Json<DeleteContactResponse>, AppError> {
    let owner_meta_hash = hash_meta_address(&query.meta_address);

    // Normalize alias
    let alias = if alias.starts_with('@') {
        alias
    } else {
        format!("@{}", alias)
    };

    let deleted = state.db.delete_contact(&owner_meta_hash, &alias)?;

    Ok(Json(DeleteContactResponse {
        success: true,
        deleted,
    }))
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


// ============ CROSS-CHAIN EVM TYPES ============

#[derive(Debug, Deserialize)]
struct EvmInfoQuery {
    meta_address: String,
}

#[derive(Debug, Serialize)]
struct EvmInfoResponse {
    success: bool,
    evm_address: Option<String>,
    chains: Vec<serde_json::Value>,
    error: Option<String>,
}

#[derive(Debug, Deserialize)]
struct EvmExportRequest {
    meta_address: String,
}

#[derive(Debug, Serialize)]
struct EvmExportResponse {
    success: bool,
    evm_address: Option<String>,
    evm_private_key: Option<String>,
    error: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CrossSwapRequest {
    meta_address: String,
    target_token: String,
    amount_sol: f64,
    target_chain: Option<String>,
    target_decimals: Option<u8>,
}

#[derive(Debug, Serialize)]
struct CrossSwapResponse {
    success: bool,
    order_id: Option<String>,
    estimated_output: Option<serde_json::Value>,
    tx_signature: Option<String>,
    error: Option<String>,
}

// ============ CROSS-CHAIN EVM HANDLERS ============

/// Get EVM wallet info for a pocket (lazy-generates if needed)
async fn evm_info_handler(
    State(state): State<Arc<AppState>>,
    Path(pocket_id): Path<String>,
    Query(query): Query<EvmInfoQuery>,
) -> std::result::Result<Json<EvmInfoResponse>, AppError> {
    let owner_meta_hash = hash_meta_address(&query.meta_address);

    let pocket = state.db.get_pocket_for_owner(&pocket_id, &owner_meta_hash)?
        .ok_or(MazeError::PocketNotFound(pocket_id.clone()))?;

    // Lazy generate EVM keypair if not exists
    let evm_address = if let Some(addr) = pocket.evm_address.clone() {
        addr
    } else {
        // Generate new EVM keypair
        let evm_kp = evm::generate_keypair().await
            .map_err(|e| AppError(e))?;

        // Encrypt EVM private key with same encryption as Solana keypairs
        let evm_encrypted = state.db.encrypt(evm_kp.private_key.as_bytes())?;

        // Store in database
        state.db.update_pocket_evm(&pocket_id, &owner_meta_hash, &evm_kp.address, &evm_encrypted)?;

        info!("Generated EVM wallet {} for pocket {}", evm_kp.address, pocket_id);
        evm_kp.address
    };

    // Get token list from cross-swap history for this EVM address
    let swap_tokens = state.db.get_cross_swap_tokens(&evm_address).unwrap_or_default();
    info!("EVM info for {}: {} tokens from swap history", evm_address, swap_tokens.len());

    // Get EVM balance across all chains (Base + BSC)
    match evm::get_balance_all_chains(&evm_address, swap_tokens).await {
        Ok(chain_balances) => {
            let chains: Vec<serde_json::Value> = chain_balances.iter()
                .map(|c| {
                    let tokens: Vec<serde_json::Value> = c.tokens.iter()
                        .map(|t| serde_json::json!({
                            "address": t.address,
                            "symbol": t.symbol,
                            "balance": t.balance,
                            "decimals": t.decimals,
                            "balance_raw": t.balance_raw,
                            "logo_uri": t.logo_uri,
                        }))
                        .collect();
                    serde_json::json!({
                        "chain": c.chain,
                        "chain_id": c.chain_id,
                        "native_symbol": c.native_symbol,
                        "native_balance": c.native_balance,
                        "tokens": tokens,
                    })
                })
                .collect();

            Ok(Json(EvmInfoResponse {
                success: true,
                evm_address: Some(evm_address),
                chains,
                error: None,
            }))
        }
        Err(e) => {
            // Return address even if balance check fails
            Ok(Json(EvmInfoResponse {
                success: true,
                evm_address: Some(evm_address),
                chains: vec![],
                error: Some(format!("Balance check failed: {}", e)),
            }))
        }
    }
}

/// Export EVM private key for a pocket
async fn evm_export_handler(
    State(state): State<Arc<AppState>>,
    Path(pocket_id): Path<String>,
    Json(req): Json<EvmExportRequest>,
) -> std::result::Result<Json<EvmExportResponse>, AppError> {
    let owner_meta_hash = hash_meta_address(&req.meta_address);

    let pocket = state.db.get_pocket_for_owner(&pocket_id, &owner_meta_hash)?
        .ok_or(MazeError::PocketNotFound(pocket_id.clone()))?;

    match (pocket.evm_address, pocket.evm_keypair_encrypted) {
        (Some(addr), Some(encrypted)) => {
            let decrypted = state.db.decrypt(&encrypted)?;
            let private_key = String::from_utf8(decrypted)
                .map_err(|e| MazeError::DecryptionError(format!("Invalid UTF-8: {}", e)))?;

            Ok(Json(EvmExportResponse {
                success: true,
                evm_address: Some(addr),
                evm_private_key: Some(private_key),
                error: None,
            }))
        }
        _ => {
            Ok(Json(EvmExportResponse {
                success: false,
                evm_address: None,
                evm_private_key: None,
                error: Some("No EVM wallet generated for this pocket. Call evm-info first.".to_string()),
            }))
        }
    }
}

/// Execute cross-chain swap (Solana SOL -> Base token via deBridge)
async fn cross_swap_handler(
    State(state): State<Arc<AppState>>,
    Path(pocket_id): Path<String>,
    Json(req): Json<CrossSwapRequest>,
) -> std::result::Result<Json<CrossSwapResponse>, AppError> {
    let owner_meta_hash = hash_meta_address(&req.meta_address);

    let pocket = state.db.get_pocket_for_owner(&pocket_id, &owner_meta_hash)?
        .ok_or(MazeError::PocketNotFound(pocket_id.clone()))?;

    if pocket.status != PocketStatus::Active {
        return Ok(Json(CrossSwapResponse {
            success: false,
            order_id: None,
            estimated_output: None,
            tx_signature: None,
            error: Some(format!("Pocket status is {}, must be active", pocket.status.as_str())),
        }));
    }

    // Validate minimum amount
    if req.amount_sol < 0.05 {
        return Ok(Json(CrossSwapResponse {
            success: false,
            order_id: None,
            estimated_output: None,
            tx_signature: None,
            error: Some("Minimum 0.05 SOL for cross-chain swap".to_string()),
        }));
    }

    // Validate target token is EVM address
    if !req.target_token.starts_with("0x") || req.target_token.len() != 42 {
        return Ok(Json(CrossSwapResponse {
            success: false,
            order_id: None,
            estimated_output: None,
            tx_signature: None,
            error: Some("Invalid EVM token address. Must start with 0x and be 42 characters.".to_string()),
        }));
    }

    // Auto-resolve token chain + decimals from CA
    let resolved = evm::resolve_evm_token(&req.target_token).await.ok();
    let target_chain_id: u32 = resolved.as_ref()
        .map(|r| r.token.chain_id)
        .or_else(|| req.target_chain.as_ref().and_then(|c| match c.as_str() {
            "bsc" => Some(56),
            _ => Some(8453),
        }))
        .unwrap_or(8453);
    let target_decimals: u8 = resolved.as_ref()
        .map(|r| r.token.decimals)
        .or(req.target_decimals)
        .unwrap_or(18);
    let target_chain_name = if target_chain_id == 56 { "BSC" } else { "Base" };
    info!("Cross-swap: resolved target {} -> chain {} ({}), decimals {}", 
        req.target_token, target_chain_id, target_chain_name, target_decimals);

    // Get pocket balance
    let keypair_bytes = state.db.decrypt(&pocket.keypair_encrypted)?;
    let pocket_keypair = Keypair::from_bytes(&keypair_bytes)
        .map_err(|e| MazeError::KeypairError(e.to_string()))?;

    let balance = state.rpc.get_balance(&pocket_keypair.pubkey())
        .map_err(|e| MazeError::RpcError(e.to_string()))?;

    let amount_lamports = sol_to_lamports(req.amount_sol);
    let buffer = 10_000; // reserve for tx fee
    if balance < amount_lamports + buffer {
        return Ok(Json(CrossSwapResponse {
            success: false,
            order_id: None,
            estimated_output: None,
            tx_signature: None,
            error: Some(format!("Insufficient balance. Have {} SOL, need {} SOL + fees",
                lamports_to_sol(balance), req.amount_sol)),
        }));
    }

    // Lazy generate EVM wallet if needed
    let evm_address = if let Some(addr) = pocket.evm_address.clone() {
        addr
    } else {
        let evm_kp = evm::generate_keypair().await.map_err(|e| AppError(e))?;
        let evm_encrypted = state.db.encrypt(evm_kp.private_key.as_bytes())?;
        state.db.update_pocket_evm(&pocket_id, &owner_meta_hash, &evm_kp.address, &evm_encrypted)?;
        info!("Generated EVM wallet {} for pocket {} (cross-swap)", evm_kp.address, pocket_id);
        evm_kp.address
    };

    // Step 1: Swap SOL -> USDC via Jupiter (with retry on timeout)
    let usdc_mint = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
    info!("Cross-swap step 1: Jupiter swap {} lamports SOL -> USDC for pocket {}", amount_lamports, pocket_id);

    let mut usdc_amount: u64 = 0;
    let mut last_jup_error: Option<String> = None;
    for jup_attempt in 1..=3u8 {
        let swap_result = swap::execute_swap(
            &state.http_client,
            &state.rpc,
            &pocket_keypair,
            &tokens::SOL_MINT.to_string(),
            usdc_mint,
            amount_lamports,
            Some(100), // 1% slippage for SOL->USDC
        ).await;

        match swap_result {
            Ok(ref sr) if sr.success => {
                let out = sr.out_amount.parse::<u64>().unwrap_or(0);
                info!("Cross-swap step 1 done (attempt {}): got {} USDC raw units", jup_attempt, out);
                usdc_amount = out;
                last_jup_error = None;
                break;
            }
            Ok(ref sr) => {
                let err = format!("Jupiter swap SOL->USDC failed: {}", sr.error.as_deref().unwrap_or("unknown"));
                if err.contains("timeout") && jup_attempt < 3 {
                    warn!("Cross-swap step 1 attempt {}/3 timeout, retrying...", jup_attempt);
                    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
                    last_jup_error = Some(err);
                    continue;
                }
                last_jup_error = Some(err);
                break;
            }
            Err(e) => {
                let err = format!("Jupiter swap SOL->USDC error: {}", e);
                if err.contains("timeout") && jup_attempt < 3 {
                    warn!("Cross-swap step 1 attempt {}/3 timeout, retrying...", jup_attempt);
                    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
                    last_jup_error = Some(err);
                    continue;
                }
                last_jup_error = Some(err);
                break;
            }
        }
    }

    if let Some(err) = last_jup_error {
        return Ok(Json(CrossSwapResponse {
            success: false,
            order_id: None,
            estimated_output: None,
            tx_signature: None,
            error: Some(err),
        }));
    }

    if usdc_amount == 0 {
        return Ok(Json(CrossSwapResponse {
            success: false,
            order_id: None,
            estimated_output: None,
            tx_signature: None,
            error: Some("Jupiter swap returned 0 USDC".to_string()),
        }));
    }

    // Get actual USDC balance in pocket (Jupiter out_amount may differ slightly from actual balance)
    let usdc_pubkey = solana_sdk::pubkey::Pubkey::from_str(usdc_mint)
        .map_err(|e| MazeError::RpcError(format!("Invalid USDC mint: {}", e)))?;
    let usdc_ata = spl_associated_token_account::get_associated_token_address(
        &pocket_keypair.pubkey(),
        &usdc_pubkey,
    );
    let actual_usdc = match state.rpc.get_token_account_balance(&usdc_ata) {
        Ok(bal) => bal.amount.parse::<u64>().unwrap_or(usdc_amount),
        Err(_) => usdc_amount,
    };

    // Step 2: Bridge USDC (Solana) -> ETH (Base) via deBridge (always bridge to ETH for gas)
    let eth_base = "0x0000000000000000000000000000000000000000";
    let pocket_key_b58 = bs58::encode(&keypair_bytes).into_string();
    info!("Cross-swap step 2: deBridge bridge {} USDC (actual: {}) -> {} on {} for pocket {}", usdc_amount, actual_usdc, if target_chain_id == 56 { "BNB" } else { "ETH" }, target_chain_name, pocket_id);

    let exec_result = evm::debridge_execute(
        eth_base,
        actual_usdc,
        &evm_address,
        &pocket.stealth_pubkey,
        &pocket_key_b58,
        &state.config.rpc_url,
        Some(0.5), // affiliate fee 0.5%
        Some("Cu6mYBnL6T4J8tsaCC3XPU68Z7VwLZaXSTzp8v5v9aZA"), // Jupiter referral key
        None, // deBridge referral code (optional)
        Some(target_chain_id), // dst_chain_id from token resolver
    ).await;

    let bridge_result = match exec_result {
        Ok(result) => result,
        Err(e) => {
            warn!("Cross-chain swap bridge failed for pocket {}: {}", pocket_id, e);
            return Ok(Json(CrossSwapResponse {
                success: false,
                order_id: None,
                estimated_output: None,
                tx_signature: None,
                error: Some(format!("Bridge USDC->ETH failed: {}", e)),
            }));
        }
    };

    let bridge_tx = bridge_result.tx_signature.clone().unwrap_or_default();
    info!("Cross-swap step 2 done: bridge TX {}", bridge_tx);

    // Step 3: If target token is not ETH/BNB, swap ETH/BNB -> target token via 1inch
    let eth_native_addr = "0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE";
    let is_target_eth = req.target_token.to_lowercase() == eth_native_addr.to_lowercase()
        || req.target_token == eth_base;

    if !is_target_eth {
        // Wait for bridge to be fulfilled (solver ~4-10 seconds)
        info!("Cross-swap step 3: waiting for bridge fulfillment before swap...");
        tokio::time::sleep(tokio::time::Duration::from_secs(15)).await;

        // Get ETH balance on Base
        let evm_bal = evm::get_balance(&evm_address, None, Some(target_chain_id)).await
            .map_err(|e| AppError(e))?;
        let eth_wei: u128 = evm_bal.eth_balance_wei.parse().unwrap_or(0);
        // Dynamic gas reserve: BSC gas is more expensive than Base
        let gas_reserve: u128 = if target_chain_id == 56 { 15_000_000_000_000_000 } else { 1_500_000_000_000_000 }; // 0.015 BNB or 0.0015 ETH
        let swap_amount = if eth_wei > gas_reserve { eth_wei - gas_reserve } else { 0 };

        if swap_amount == 0 {
            return Ok(Json(CrossSwapResponse {
                success: true,
                order_id: bridge_result.order_id,
                estimated_output: bridge_result.estimation,
                tx_signature: bridge_result.tx_signature,
                error: Some("Bridge succeeded but no ETH available for swap to target token. ETH is in your Base wallet.".to_string()),
            }));
        }

        info!("Cross-swap step 3: 1inch swap {} wei ETH -> {} on {}", swap_amount, req.target_token, target_chain_name);

        // Decrypt EVM private key for 1inch swap
        let evm_pk_bytes = state.db.decrypt(&pocket.evm_keypair_encrypted.clone().unwrap_or_default())?;
        let evm_private_key = String::from_utf8(evm_pk_bytes)
            .map_err(|e| MazeError::DecryptionError(format!("Invalid UTF-8: {}", e)))?;

        let swap_result = evm::evm_swap(
            &evm_private_key,
            eth_native_addr,
            &req.target_token,
            &swap_amount.to_string(),
            18, // ETH decimals
            target_decimals,
            Some(100), // 1% slippage
            Some(target_chain_id), // chain_id from token resolver
        ).await;

        match swap_result {
            Ok(sr) => {
                info!("Cross-swap step 3 done: 1inch TX {}", sr.tx_hash);
            }
            Err(e) => {
                warn!("Cross-swap step 3 1inch swap failed: {}. ETH/BNB is in EVM wallet.", e);
                return Ok(Json(CrossSwapResponse {
                    success: true,
                    order_id: bridge_result.order_id,
                    estimated_output: bridge_result.estimation,
                    tx_signature: bridge_result.tx_signature,
                    error: Some(format!("Bridge succeeded but swap ETH->target failed: {}. ETH is in your Base wallet.", e)),
                }));
            }
        }
    }

    // Log transaction
    let _ = state.db.insert_transaction_log(
        &format!("xswap_{}", &bridge_tx[..16.min(bridge_tx.len())]),
        &owner_meta_hash,
        "cross_swap",
        "completed",
        Some(amount_lamports as i64),
        Some(&format!("{} SOL -> {} ({})", req.amount_sol, &req.target_token[..10.min(req.target_token.len())], target_chain_name)),
        Some(&format!("Cross-chain swap to {} token {}", target_chain_name, req.target_token)),
        Some(&bridge_tx),
        Some(&serde_json::json!({
            "order_id": bridge_result.order_id,
            "target_token": req.target_token,
            "evm_address": evm_address,
            "target_chain": req.target_chain.unwrap_or_else(|| "base".to_string()),
        }).to_string()),
    );

    Ok(Json(CrossSwapResponse {
        success: true,
        order_id: bridge_result.order_id,
        estimated_output: bridge_result.estimation,
        tx_signature: bridge_result.tx_signature,
        error: None,
    }))
}


// ============ CROSS-CHAIN SELL + STATUS ============

#[derive(Debug, Deserialize)]
struct CrossSwapSellRequest {
    meta_address: String,
    input_token: String,
    amount_raw: String,
    src_decimals: Option<u8>,
    chain: Option<String>,
}

#[derive(Debug, Serialize)]
struct CrossSwapSellResponse {
    success: bool,
    order_id: Option<String>,
    estimated_sol: Option<serde_json::Value>,
    tx_hash: Option<String>,
    error: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CrossSwapStatusQuery {
    meta_address: String,
    order_id: Option<String>,
    tx_hash: Option<String>,
}

#[derive(Debug, Serialize)]
struct CrossSwapStatusResponse {
    success: bool,
    status: Option<String>,
    data: Option<serde_json::Value>,
    error: Option<String>,
}

/// Execute reverse cross-chain swap (Base token -> SOL via deBridge)
async fn cross_swap_sell_handler(
    State(state): State<Arc<AppState>>,
    Path(pocket_id): Path<String>,
    Json(req): Json<CrossSwapSellRequest>,
) -> std::result::Result<Json<CrossSwapSellResponse>, AppError> {
    let owner_meta_hash = hash_meta_address(&req.meta_address);

    let pocket = state.db.get_pocket_for_owner(&pocket_id, &owner_meta_hash)?
        .ok_or(MazeError::PocketNotFound(pocket_id.clone()))?;

    if pocket.status != PocketStatus::Active {
        return Ok(Json(CrossSwapSellResponse {
            success: false,
            order_id: None,
            estimated_sol: None,
            tx_hash: None,
            error: Some(format!("Pocket status is {}, must be active", pocket.status.as_str())),
        }));
    }

    // Validate input token is EVM address
    if !req.input_token.starts_with("0x") || req.input_token.len() != 42 {
        return Ok(Json(CrossSwapSellResponse {
            success: false,
            order_id: None,
            estimated_sol: None,
            tx_hash: None,
            error: Some("Invalid EVM token address. Must start with 0x and be 42 characters.".to_string()),
        }));
    }

    // Check EVM wallet exists
    let (evm_address, evm_encrypted) = match (pocket.evm_address.clone(), pocket.evm_keypair_encrypted.clone()) {
        (Some(addr), Some(enc)) => (addr, enc),
        _ => {
            return Ok(Json(CrossSwapSellResponse {
                success: false,
                order_id: None,
                estimated_sol: None,
                tx_hash: None,
                error: Some("No EVM wallet for this pocket. Buy tokens first via cross-swap.".to_string()),
            }));
        }
    };

    // Decrypt EVM private key
    let evm_pk_bytes = state.db.decrypt(&evm_encrypted)?;
    let evm_private_key = String::from_utf8(evm_pk_bytes)
        .map_err(|e| MazeError::DecryptionError(format!("Invalid UTF-8: {}", e)))?;

    // Auto-resolve token chain + decimals from CA
    // For native tokens (0x000...0), resolver can't detect chain — use req.chain field
    let is_native_addr = req.input_token == "0x0000000000000000000000000000000000000000"
        || req.input_token.to_lowercase() == "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
    let resolved_sell = if is_native_addr { None } else { evm::resolve_evm_token(&req.input_token).await.ok() };
    let sell_chain_id: u32 = resolved_sell.as_ref()
        .map(|r| r.token.chain_id)
        .or_else(|| req.chain.as_ref().and_then(|c| match c.as_str() {
            "bsc" | "BSC" => Some(56),
            "base" | "Base" => Some(8453),
            _ => c.parse::<u32>().ok(),
        }))
        .unwrap_or(8453);
    let sell_decimals: u8 = resolved_sell.as_ref()
        .map(|r| r.token.decimals)
        .or(req.src_decimals)
        .unwrap_or(18);
    let sell_chain_name = if sell_chain_id == 56 { "BSC" } else { "Base" };
    info!("Cross-sell: resolved input {} -> chain {} ({}), decimals {}",
        req.input_token, sell_chain_id, sell_chain_name, sell_decimals);

    let eth_native = "0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE";
    let is_eth_input = req.input_token.to_lowercase() == eth_native.to_lowercase()
        || req.input_token == "0x0000000000000000000000000000000000000000";

    // Step 1: If input is not ETH/BNB, swap token -> ETH/BNB via 1inch
    let _eth_amount_for_bridge: Option<u128> = if !is_eth_input {
        info!("Cross-sell step 1: 1inch swap {} {} -> ETH/BNB on {} for pocket {}", req.amount_raw, req.input_token, sell_chain_name, pocket_id);

        let src_decimals: u8 = sell_decimals;
        let swap_result = evm::evm_swap(
            &evm_private_key,
            &req.input_token,
            eth_native,
            &req.amount_raw,
            src_decimals,
            18,
            Some(100), // 1% slippage
            Some(sell_chain_id), // chain_id from token resolver
        ).await;

        match swap_result {
            Ok(ref sr) => {
                info!("Cross-sell step 1 done: 1inch TX {}", sr.tx_hash);
                // Wait for balance to settle after 1inch swap
                tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;
                None // will use full ETH balance
            }
            Err(e) => {
                return Ok(Json(CrossSwapSellResponse {
                    success: false,
                    order_id: None,
                    estimated_sol: None,
                    tx_hash: None,
                    error: Some(format!("1inch swap failed: {}", e)),
                }));
            }
        }
    } else {
        None // already ETH, use amount_raw directly
    };

    // Step 2: Get ETH balance to bridge (leave small amount for future gas)
    let evm_balance = evm::get_balance(&evm_address, None, Some(sell_chain_id)).await
        .map_err(|e| AppError(e))?;
    let eth_wei: u128 = evm_balance.eth_balance_wei.parse().unwrap_or(0);
    // Dynamic gas reserve: BSC gas is more expensive than Base
    let gas_reserve: u128 = if sell_chain_id == 56 { 15_000_000_000_000_000 } else { 1_500_000_000_000_000 }; // 0.015 BNB or 0.0015 ETH
    let bridge_amount = if eth_wei > gas_reserve { eth_wei - gas_reserve } else { 0 };

    if bridge_amount == 0 {
        return Ok(Json(CrossSwapSellResponse {
            success: false,
            order_id: None,
            estimated_sol: None,
            tx_hash: None,
            error: Some("Insufficient ETH balance for bridge after swap".to_string()),
        }));
    }

    // Step 3: Bridge ETH (Base) -> SOL (Solana) via deBridge
    let eth_zero = "0x0000000000000000000000000000000000000000";
    info!("Cross-sell step 2: deBridge bridge {} wei ETH -> SOL for pocket {}", bridge_amount, pocket_id);
    let quote = evm::debridge_quote_reverse(
        eth_zero,
        &bridge_amount.to_string(),
        &pocket.stealth_pubkey,
        &evm_address,
        Some(0.5),
        Some("0x8E61077Af8BF9564210ecb52D3a27FC17591AF9c"),
        None,
        Some(sell_chain_id), // src_chain_id from token resolver
    ).await.map_err(|e| AppError(e))?;

    let (tx_to, tx_data, tx_value) = match &quote.tx {
        Some(tx) => {
            let to = tx.get("to").and_then(|v| v.as_str()).unwrap_or("");
            let data = tx.get("data").and_then(|v| v.as_str()).unwrap_or("");
            let value = tx.get("value").and_then(|v| v.as_str()).unwrap_or("0");
            (to.to_string(), data.to_string(), value.to_string())
        }
        None => {
            return Ok(Json(CrossSwapSellResponse {
                success: false,
                order_id: quote.order_id,
                estimated_sol: quote.estimation.clone(),
                tx_hash: None,
                error: Some("deBridge did not return transaction data".to_string()),
            }));
        }
    };

    // ETH native doesn't need approve, just send bridge TX
    let evm_result = evm::evm_approve_and_send(
        &evm_private_key,
        None, // no approve needed for native ETH
        None,
        None,
        &tx_to,
        &tx_data,
        &tx_value,
        Some(sell_chain_id), // chain_id from token resolver
    ).await.map_err(|e| AppError(e))?;

    info!("Cross-chain sell submitted: {} (pocket {} -> SOL from Base token {})",
        evm_result.tx_hash, pocket_id, req.input_token);

    // Log transaction
    let _ = state.db.insert_transaction_log(
        &format!("xsell_{}", &evm_result.tx_hash[..16.min(evm_result.tx_hash.len())]),
        &owner_meta_hash,
        "cross_swap_sell",
        "pending",
        None,
        Some(&format!("{} {} (Base) -> SOL", req.amount_raw, &req.input_token[..10.min(req.input_token.len())])),
        Some(&format!("Cross-chain sell Base token {} -> SOL", req.input_token)),
        Some(&evm_result.tx_hash),
        Some(&serde_json::json!({
            "order_id": quote.order_id,
            "input_token": req.input_token,
            "evm_address": evm_address,
            "amount_raw": req.amount_raw,
        }).to_string()),
    );

    // Background task: auto-unwrap WSOL -> native SOL after solver fulfills
    let unwrap_keypair = state.db.decrypt(&pocket.keypair_encrypted).unwrap_or_default();
    let unwrap_rpc_url = state.config.rpc_url.clone();
    let unwrap_pocket_id = pocket_id.clone();
    tokio::spawn(async move {
        let wsol_mint = solana_sdk::pubkey::Pubkey::from_str("So11111111111111111111111111111111111111112").unwrap();
        if let Ok(kp) = Keypair::from_bytes(&unwrap_keypair) {
            let wsol_ata = spl_associated_token_account::get_associated_token_address(&kp.pubkey(), &wsol_mint);
            let unwrap_rpc = solana_client::rpc_client::RpcClient::new(unwrap_rpc_url);
            for attempt in 1..=2 {
                tokio::time::sleep(tokio::time::Duration::from_secs(30)).await;
                if let Ok(bal) = unwrap_rpc.get_token_account_balance(&wsol_ata) {
                    let amount: u64 = bal.amount.parse().unwrap_or(0);
                    if amount > 0 {
                        if let Ok(close_ix) = spl_token::instruction::close_account(
                            &spl_token::id(), &wsol_ata, &kp.pubkey(), &kp.pubkey(), &[],
                        ) {
                            if let Ok(bh) = unwrap_rpc.get_latest_blockhash() {
                                let tx = solana_sdk::transaction::Transaction::new_signed_with_payer(
                                    &[close_ix], Some(&kp.pubkey()), &[&kp], bh,
                                );
                                match unwrap_rpc.send_and_confirm_transaction(&tx) {
                                    Ok(sig) => { info!("Auto-unwrap WSOL attempt {}: {} (pocket {})", attempt, sig, unwrap_pocket_id); break; }
                                    Err(e) => { warn!("Auto-unwrap WSOL attempt {} failed: {} (pocket {})", attempt, e, unwrap_pocket_id); }
                                }
                            }
                        }
                    }
                }
            }
        }
    });

    Ok(Json(CrossSwapSellResponse {
        success: true,
        order_id: quote.order_id,
        estimated_sol: quote.estimation,
        tx_hash: Some(evm_result.tx_hash),
        error: None,
    }))
}

/// Check cross-chain swap order status
async fn cross_swap_status_handler(
    State(state): State<Arc<AppState>>,
    Path(pocket_id): Path<String>,
    Query(query): Query<CrossSwapStatusQuery>,
) -> std::result::Result<Json<CrossSwapStatusResponse>, AppError> {
    let owner_meta_hash = hash_meta_address(&query.meta_address);

    // Verify pocket ownership
    let _pocket = state.db.get_pocket_for_owner(&pocket_id, &owner_meta_hash)?
        .ok_or(MazeError::PocketNotFound(pocket_id.clone()))?;

    let status_result = evm::debridge_order_status(
        query.order_id.as_deref(),
        query.tx_hash.as_deref(),
    ).await.map_err(|e| AppError(e))?;

    Ok(Json(CrossSwapStatusResponse {
        success: true,
        status: status_result.status,
        data: Some(status_result.data),
        error: None,
    }))
}


// ============ TOKEN RESOLVER ============

#[derive(Debug, Serialize)]
struct ResolveTokenResponse {
    success: bool,
    chain_id: Option<u32>,
    chain_name: Option<String>,
    address: Option<String>,
    symbol: Option<String>,
    name: Option<String>,
    decimals: Option<u8>,
    all_chains: Option<Vec<serde_json::Value>>,
    error: Option<String>,
}

/// Resolve token metadata + chain from contract address
async fn resolve_token_handler(
    State(state): State<Arc<AppState>>,
    Path(address): Path<String>,
) -> std::result::Result<Json<ResolveTokenResponse>, AppError> {
    let address = address.trim().to_string();

    // If it's a Solana address (not 0x prefix), resolve via DexScreener
    if !address.starts_with("0x") {
        // Try curated list first
        if let Some(token) = tokens::resolve_token(&address) {
            return Ok(Json(ResolveTokenResponse {
                success: true,
                chain_id: Some(0), // 0 = Solana (not EVM)
                chain_name: Some("solana".to_string()),
                address: Some(token.mint),
                symbol: Some(token.symbol),
                name: Some(token.name),
                decimals: Some(token.decimals),
                all_chains: None,
                error: None,
            }));
        }

        // Try DexScreener
        match swap::resolve_token_dexscreener(&state.http_client, &address).await {
            Some(token) => {
                return Ok(Json(ResolveTokenResponse {
                    success: true,
                    chain_id: Some(0),
                    chain_name: Some("solana".to_string()),
                    address: Some(token.mint),
                    symbol: Some(token.symbol),
                    name: Some(token.name),
                    decimals: Some(token.decimals),
                    all_chains: None,
                    error: None,
                }));
            }
            None => {
                return Ok(Json(ResolveTokenResponse {
                    success: false,
                    chain_id: None,
                    chain_name: None,
                    address: None,
                    symbol: None,
                    name: None,
                    decimals: None,
                    all_chains: None,
                    error: Some("Token not found on Solana".to_string()),
                }));
            }
        }
    }

    // EVM address — resolve via sidecar (checks Base + BSC)
    match evm::resolve_evm_token(&address).await {
        Ok(resolved) => {
            let all_chains: Vec<serde_json::Value> = resolved.all_chains.iter().map(|c| {
                serde_json::json!({
                    "chain_id": c.chain_id,
                    "chain_name": c.chain_name,
                    "address": c.address,
                    "symbol": c.symbol,
                    "name": c.name,
                    "decimals": c.decimals,
                })
            }).collect();

            Ok(Json(ResolveTokenResponse {
                success: true,
                chain_id: Some(resolved.token.chain_id),
                chain_name: Some(resolved.token.chain_name),
                address: Some(resolved.token.address),
                symbol: Some(resolved.token.symbol),
                name: Some(resolved.token.name),
                decimals: Some(resolved.token.decimals),
                all_chains: Some(all_chains),
                error: None,
            }))
        }
        Err(e) => {
            Ok(Json(ResolveTokenResponse {
                success: false,
                chain_id: None,
                chain_name: None,
                address: None,
                symbol: None,
                name: None,
                decimals: None,
                all_chains: None,
                error: Some(format!("{}", e)),
            }))
        }
    }
}


// ============ GENESIS HANDLERS ============

#[derive(Debug, Deserialize)]
struct GenesisDepositApiRequest {
    meta_address: String,
    genesis_account: String,
    mint_address: String,
    amount_lamports: Option<u64>,
}

#[derive(Debug, Serialize)]
struct GenesisDepositApiResponse {
    success: bool,
    tx_signature: Option<String>,
    depositor: Option<String>,
    amount_deposited: Option<u64>,
    launch_pool_bucket: Option<String>,
    error: Option<String>,
}

async fn genesis_deposit_handler(
    State(state): State<Arc<AppState>>,
    Path(pocket_id): Path<String>,
    Json(req): Json<GenesisDepositApiRequest>,
) -> std::result::Result<Json<GenesisDepositApiResponse>, AppError> {
    let owner_meta_hash = hash_meta_address(&req.meta_address);

    // Verify pocket ownership
    let pocket = state.db.get_pocket_for_owner(&pocket_id, &owner_meta_hash)?
        .ok_or(MazeError::PocketNotFound(pocket_id.clone()))?;

    if pocket.status != PocketStatus::Active {
        return Ok(Json(GenesisDepositApiResponse {
            success: false,
            tx_signature: None,
            depositor: None,
            amount_deposited: None,
            launch_pool_bucket: None,
            error: Some(format!("Pocket status is {}, must be active", pocket.status.as_str())),
        }));
    }

    // Decrypt keypair
    let keypair_bytes = state.db.decrypt(&pocket.keypair_encrypted)?;
    let pocket_keypair = Keypair::from_bytes(&keypair_bytes)
        .map_err(|e| MazeError::KeypairError(e.to_string()))?;

    // Check balance
    let balance = state.rpc.get_balance(&pocket_keypair.pubkey())
        .map_err(|e| MazeError::RpcError(e.to_string()))?;

    let deposit_amount = req.amount_lamports.unwrap_or(balance.saturating_sub(5_000_000));

    if balance < deposit_amount + 5_000_000 {
        return Ok(Json(GenesisDepositApiResponse {
            success: false,
            tx_signature: None,
            depositor: None,
            amount_deposited: None,
            launch_pool_bucket: None,
            error: Some(format!(
                "Insufficient balance. Need {} + fees, have {} SOL",
                lamports_to_sol(deposit_amount),
                lamports_to_sol(balance)
            )),
        }));
    }

    let genesis_req = genesis::GenesisDepositRequest {
        genesis_account: req.genesis_account,
        mint_address: req.mint_address,
        amount_lamports: deposit_amount,
    };

    let rpc_url = state.config.rpc_url.clone();
    let result = genesis::execute_genesis_deposit(&pocket_keypair, &rpc_url, &genesis_req).await?;

    Ok(Json(GenesisDepositApiResponse {
        success: result.success,
        tx_signature: result.tx_signature,
        depositor: result.depositor,
        amount_deposited: result.amount_deposited,
        launch_pool_bucket: result.launch_pool_bucket,
        error: result.error,
    }))
}

#[derive(Debug, Deserialize)]
struct GenesisClaimApiRequest {
    meta_address: String,
    genesis_account: String,
    mint_address: String,
}

#[derive(Debug, Serialize)]
struct GenesisClaimApiResponse {
    success: bool,
    tx_signature: Option<String>,
    claimed_by: Option<String>,
    token_mint: Option<String>,
    error: Option<String>,
}

async fn genesis_claim_handler(
    State(state): State<Arc<AppState>>,
    Path(pocket_id): Path<String>,
    Json(req): Json<GenesisClaimApiRequest>,
) -> std::result::Result<Json<GenesisClaimApiResponse>, AppError> {
    let owner_meta_hash = hash_meta_address(&req.meta_address);

    let pocket = state.db.get_pocket_for_owner(&pocket_id, &owner_meta_hash)?
        .ok_or(MazeError::PocketNotFound(pocket_id.clone()))?;

    let keypair_bytes = state.db.decrypt(&pocket.keypair_encrypted)?;
    let pocket_keypair = Keypair::from_bytes(&keypair_bytes)
        .map_err(|e| MazeError::KeypairError(e.to_string()))?;

    let genesis_req = genesis::GenesisClaimRequest {
        genesis_account: req.genesis_account,
        mint_address: req.mint_address,
    };

    let rpc_url = state.config.rpc_url.clone();
    let result = genesis::execute_genesis_claim(&pocket_keypair, &rpc_url, &genesis_req).await?;

    Ok(Json(GenesisClaimApiResponse {
        success: result.success,
        tx_signature: result.tx_signature,
        claimed_by: result.claimed_by,
        token_mint: result.token_mint,
        error: result.error,
    }))
}


// ============ GENESIS BONDING CURVE HANDLER ============

#[derive(Debug, Deserialize)]
struct GenesisBuyApiRequest {
    meta_address: String,
    genesis_account: String,
    mint_address: String,
    amount_lamports: Option<u64>,
    min_amount_out: Option<u64>,
}

#[derive(Debug, Serialize)]
struct GenesisBuyApiResponse {
    success: bool,
    tx_signature: Option<String>,
    buyer: Option<String>,
    amount_spent: Option<u64>,
    bonding_curve_bucket: Option<String>,
    error: Option<String>,
}

async fn genesis_buy_handler(
    State(state): State<Arc<AppState>>,
    Path(pocket_id): Path<String>,
    Json(req): Json<GenesisBuyApiRequest>,
) -> std::result::Result<Json<GenesisBuyApiResponse>, AppError> {
    let owner_meta_hash = hash_meta_address(&req.meta_address);

    let pocket = state.db.get_pocket_for_owner(&pocket_id, &owner_meta_hash)?
        .ok_or(MazeError::PocketNotFound(pocket_id.clone()))?;

    if pocket.status != PocketStatus::Active {
        return Ok(Json(GenesisBuyApiResponse {
            success: false,
            tx_signature: None,
            buyer: None,
            amount_spent: None,
            bonding_curve_bucket: None,
            error: Some(format!("Pocket status is {}, must be active", pocket.status.as_str())),
        }));
    }

    let keypair_bytes = state.db.decrypt(&pocket.keypair_encrypted)?;
    let pocket_keypair = Keypair::from_bytes(&keypair_bytes)
        .map_err(|e| MazeError::KeypairError(e.to_string()))?;

    let balance = state.rpc.get_balance(&pocket_keypair.pubkey())
        .map_err(|e| MazeError::RpcError(e.to_string()))?;

    let buy_amount = req.amount_lamports.unwrap_or(balance.saturating_sub(5_000_000));

    if balance < buy_amount + 5_000_000 {
        return Ok(Json(GenesisBuyApiResponse {
            success: false,
            tx_signature: None,
            buyer: None,
            amount_spent: None,
            bonding_curve_bucket: None,
            error: Some(format!(
                "Insufficient balance. Need {} + fees, have {} SOL",
                lamports_to_sol(buy_amount),
                lamports_to_sol(balance)
            )),
        }));
    }

    let genesis_req = genesis::GenesisBuyRequest {
        genesis_account: req.genesis_account,
        mint_address: req.mint_address,
        amount_lamports: buy_amount,
        min_amount_out: req.min_amount_out,
    };

    let rpc_url = state.config.rpc_url.clone();
    let result = genesis::execute_genesis_buy(&pocket_keypair, &rpc_url, &genesis_req).await?;

    Ok(Json(GenesisBuyApiResponse {
        success: result.success,
        tx_signature: result.tx_signature,
        buyer: result.buyer,
        amount_spent: result.amount_spent,
        bonding_curve_bucket: result.bonding_curve_bucket,
        error: result.error,
    }))
}


#[derive(Debug, Deserialize)]
struct GenesisSellApiRequest {
    meta_address: String,
    genesis_account: String,
    mint_address: String,
    amount_tokens: u64,
    min_amount_out: Option<u64>,
}

#[derive(Debug, Serialize)]
struct GenesisSellApiResponse {
    success: bool,
    tx_signature: Option<String>,
    seller: Option<String>,
    amount_sold: Option<u64>,
    sol_received: Option<u64>,
    bonding_curve_bucket: Option<String>,
    error: Option<String>,
}

async fn genesis_sell_handler(
    State(state): State<Arc<AppState>>,
    Path(pocket_id): Path<String>,
    Json(req): Json<GenesisSellApiRequest>,
) -> std::result::Result<Json<GenesisSellApiResponse>, AppError> {
    let owner_meta_hash = hash_meta_address(&req.meta_address);

    let pocket = state.db.get_pocket_for_owner(&pocket_id, &owner_meta_hash)?
        .ok_or(MazeError::PocketNotFound(pocket_id.clone()))?;

    if pocket.status != PocketStatus::Active {
        return Ok(Json(GenesisSellApiResponse {
            success: false,
            tx_signature: None,
            seller: None,
            amount_sold: None,
            sol_received: None,
            bonding_curve_bucket: None,
            error: Some(format!("Pocket status is {}, must be active", pocket.status.as_str())),
        }));
    }

    let keypair_bytes = state.db.decrypt(&pocket.keypair_encrypted)?;
    let pocket_keypair = Keypair::from_bytes(&keypair_bytes)
        .map_err(|e| MazeError::KeypairError(e.to_string()))?;

    let genesis_req = genesis::GenesisSellRequest {
        genesis_account: req.genesis_account,
        mint_address: req.mint_address,
        amount_tokens: req.amount_tokens,
        min_amount_out: req.min_amount_out,
    };

    let rpc_url = state.config.rpc_url.clone();
    let result = genesis::execute_genesis_sell(&pocket_keypair, &rpc_url, &genesis_req).await?;

    Ok(Json(GenesisSellApiResponse {
        success: result.success,
        tx_signature: result.tx_signature,
        seller: result.seller,
        amount_sold: result.amount_sold,
        sol_received: result.sol_received,
        bonding_curve_bucket: result.bonding_curve_bucket,
        error: result.error,
    }))
}


#[derive(Debug, Deserialize)]
struct GenesisActivateApiRequest {
    meta_address: String,
    genesis_account: String,
    mint_address: String,
}

#[derive(Debug, Serialize)]
struct GenesisActivateApiResponse {
    success: bool,
    wallet: Option<String>,
    wsol_ata: Option<String>,
    base_token_ata: Option<String>,
    error: Option<String>,
}

async fn genesis_activate_handler(
    State(state): State<Arc<AppState>>,
    Path(pocket_id): Path<String>,
    Json(req): Json<GenesisActivateApiRequest>,
) -> std::result::Result<Json<GenesisActivateApiResponse>, AppError> {
    let owner_meta_hash = hash_meta_address(&req.meta_address);

    let pocket = state.db.get_pocket_for_owner(&pocket_id, &owner_meta_hash)?
        .ok_or(MazeError::PocketNotFound(pocket_id.clone()))?;

    let keypair_bytes = state.db.decrypt(&pocket.keypair_encrypted)?;
    let pocket_keypair = Keypair::from_bytes(&keypair_bytes)
        .map_err(|e| MazeError::KeypairError(e.to_string()))?;

    let activate_req = genesis::GenesisActivateRequest {
        genesis_account: req.genesis_account,
        mint_address: req.mint_address,
    };

    let result = genesis::execute_genesis_activate(&pocket_keypair, &state.config.rpc_url, &activate_req).await
        .map_err(|e| MazeError::RpcError(format!("{}", e)))?;

    Ok(Json(GenesisActivateApiResponse {
        success: result.success,
        wallet: result.wallet,
        wsol_ata: result.wsol_ata,
        base_token_ata: result.base_token_ata,
        error: result.error,
    }))
}
