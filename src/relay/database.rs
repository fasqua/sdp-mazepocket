//! Database layer for SDP Maze Pocket
//!
//! Uses SQLite with Argon2id + AES-256-GCM encryption for keypair storage

use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use aes_gcm::aead::{Aead, KeyInit};
use argon2::{Argon2, password_hash::SaltString, PasswordHasher};
use sha2::{Sha256, Digest};
use zeroize::Zeroize;

use crate::config::{
    POCKET_DB_PATH, ARGON2_MEMORY_COST, ARGON2_TIME_COST, ARGON2_PARALLELISM
};
use crate::error::{MazeError, Result};

/// Pocket status enum
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum PocketStatus {
    Active,
    Sweeping,
    Swept,
    Deleted,
}

impl PocketStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Sweeping => "sweeping",
            Self::Swept => "swept",
            Self::Deleted => "deleted",
        }
    }

    pub fn from_str(s: &str) -> Self {
        match s {
            "active" => Self::Active,
            "sweeping" => Self::Sweeping,
            "swept" => Self::Swept,
            "deleted" => Self::Deleted,
            _ => Self::Active,
        }
    }
}

/// A Maze Pocket record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MazePocket {
    pub id: String,
    pub owner_meta_hash: String,
    pub stealth_pubkey: String,
    pub keypair_encrypted: Vec<u8>,
    pub funding_maze_id: Option<String>,
    pub funding_amount_lamports: u64,
    pub created_at: i64,
    pub last_sweep_at: Option<i64>,
    pub status: PocketStatus,
}

/// Funding request for creating a pocket
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FundingRequest {
    pub id: String,
    pub pocket_id: String,
    pub owner_meta_hash: String,
    pub deposit_address: String,
    pub deposit_keypair_encrypted: Vec<u8>,
    pub amount_lamports: u64,
    pub fee_lamports: u64,
    pub maze_config_json: Option<String>,
    pub status: String,
    pub created_at: i64,
    pub expires_at: i64,
    pub completed_at: Option<i64>,
    pub error_message: Option<String>,
    pub destination_address: Option<String>,
    pub tx_signature: Option<String>,
}

/// Protocol statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolStats {
    pub total_nodes_alltime: i64,
    pub total_hops_alltime: i64,
    pub nodes_24h: i64,
}
/// Database wrapper with Argon2id + AES-256-GCM encryption
pub struct PocketDatabase {
    conn: Arc<Mutex<Connection>>,
    encryption_key: [u8; 32],
}

impl PocketDatabase {
    /// Create new database connection with Argon2id key derivation
    pub fn new(db_path: Option<&str>, master_key: &str) -> Result<Self> {
        let path = db_path.unwrap_or(POCKET_DB_PATH);
        let conn = Connection::open(path)
            .map_err(|e| MazeError::DatabaseError(e.to_string()))?;

        // Derive encryption key using Argon2id (memory-hard, resistant to GPU/ASIC attacks)
        let encryption_key = Self::derive_key_argon2id(master_key)?;

        let db = Self {
            conn: Arc::new(Mutex::new(conn)),
            encryption_key,
        };

        db.init_tables()?;
        Ok(db)
    }

    /// Derive encryption key using Argon2id
    fn derive_key_argon2id(master_key: &str) -> Result<[u8; 32]> {
        // Use a fixed salt derived from the master key itself
        // This ensures deterministic key derivation while still being secure
        let mut hasher = Sha256::new();
        hasher.update(b"sdp-mazepocket-salt-v1:");
        hasher.update(master_key.as_bytes());
        let salt_bytes = hasher.finalize();
        
        // Configure Argon2id with strong parameters
        let argon2 = Argon2::new(
            argon2::Algorithm::Argon2id,
            argon2::Version::V0x13,
            argon2::Params::new(
                ARGON2_MEMORY_COST,
                ARGON2_TIME_COST,
                ARGON2_PARALLELISM,
                Some(32),
            ).map_err(|e| MazeError::CryptoError(e.to_string()))?,
        );

        // Derive the key
        let mut key = [0u8; 32];
        argon2.hash_password_into(
            master_key.as_bytes(),
            &salt_bytes[..16], // Use first 16 bytes as salt
            &mut key,
        ).map_err(|e| MazeError::CryptoError(e.to_string()))?;

        Ok(key)
    }

    /// Initialize database tables
    fn init_tables(&self) -> Result<()> {
        let conn = self.conn.lock().unwrap();

        // Maze Pockets table
        conn.execute(
            r#"CREATE TABLE IF NOT EXISTS maze_pockets (
                id TEXT PRIMARY KEY,
                owner_meta_hash TEXT NOT NULL,
                stealth_pubkey TEXT NOT NULL,
                keypair_encrypted BLOB NOT NULL,
                funding_maze_id TEXT,
                funding_amount_lamports INTEGER NOT NULL,
                created_at INTEGER NOT NULL,
                last_sweep_at INTEGER,
                status TEXT DEFAULT 'active'
            )"#,
            [],
        )?;

        // Funding requests table (for tracking maze routing to pocket)
        conn.execute(
            r#"CREATE TABLE IF NOT EXISTS funding_requests (
                id TEXT PRIMARY KEY,
                pocket_id TEXT NOT NULL,
                owner_meta_hash TEXT NOT NULL,
                deposit_address TEXT NOT NULL,
                deposit_keypair_encrypted BLOB NOT NULL,
                amount_lamports INTEGER NOT NULL,
                fee_lamports INTEGER NOT NULL,
                maze_config_json TEXT,
                maze_graph_json TEXT,
                status TEXT DEFAULT 'pending',
                created_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                completed_at INTEGER,
                error_message TEXT,
                destination_address TEXT,
                FOREIGN KEY (pocket_id) REFERENCES maze_pockets(id)
            )"#,
            [],
        )?;

        // Maze nodes table (for tracking routing progress)
        conn.execute(
            r#"CREATE TABLE IF NOT EXISTS maze_nodes (
                request_id TEXT NOT NULL,
                node_index INTEGER NOT NULL,
                level INTEGER NOT NULL,
                address TEXT NOT NULL,
                keypair_encrypted BLOB NOT NULL,
                inputs TEXT NOT NULL,
                outputs TEXT NOT NULL,
                amount_in INTEGER NOT NULL,
                amount_out INTEGER NOT NULL,
                status TEXT DEFAULT 'pending',
                tx_signature TEXT,
                PRIMARY KEY (request_id, node_index),
                FOREIGN KEY (request_id) REFERENCES funding_requests(id)
            )"#,
            [],
        )?;

        // Sweep requests table
        conn.execute(
            r#"CREATE TABLE IF NOT EXISTS sweep_requests (
                id TEXT PRIMARY KEY,
                pocket_id TEXT NOT NULL,
                destination_address TEXT NOT NULL,
                amount_lamports INTEGER,
                maze_graph_json TEXT,
                status TEXT DEFAULT 'pending',
                created_at INTEGER NOT NULL,
                completed_at INTEGER,
                tx_signature TEXT,
                error_message TEXT,
                destination_address TEXT,
                FOREIGN KEY (pocket_id) REFERENCES maze_pockets(id)
            )"#,
            [],
        )?;

        // Sweep maze nodes table (for tracking sweep routing progress)
        conn.execute(
            r#"CREATE TABLE IF NOT EXISTS sweep_maze_nodes (
                sweep_id TEXT NOT NULL,
                node_index INTEGER NOT NULL,
                level INTEGER NOT NULL,
                address TEXT NOT NULL,
                keypair_encrypted BLOB NOT NULL,
                inputs TEXT NOT NULL,
                outputs TEXT NOT NULL,
                amount_in INTEGER NOT NULL,
                amount_out INTEGER NOT NULL,
                status TEXT DEFAULT 'pending',
                tx_signature TEXT,
                PRIMARY KEY (sweep_id, node_index),
                FOREIGN KEY (sweep_id) REFERENCES sweep_requests(id)
            )"#,
            [],
        )?;

        // MCP API Keys table
        conn.execute(
            r#"CREATE TABLE IF NOT EXISTS mcp_api_keys (
                api_key_hash TEXT PRIMARY KEY,
                wallet_address TEXT NOT NULL,
                owner_meta_hash TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                last_used_at INTEGER
            )"#,
            [],
        )?;

        // Destination wallets table (saved withdrawal addresses)
        conn.execute(
            r#"CREATE TABLE IF NOT EXISTS destination_wallets (
                owner_meta_hash TEXT NOT NULL,
                slot INTEGER NOT NULL,
                wallet_address TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                PRIMARY KEY (owner_meta_hash, slot)
            )"#,
            [],
        )?;

        // Indexes
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_pockets_owner ON maze_pockets(owner_meta_hash)",
            [],
        )?;
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_pockets_status ON maze_pockets(status)",
            [],
        )?;
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_funding_status ON funding_requests(status)",
            [],
        )?;

        Ok(())
    }

    /// Encrypt data using AES-256-GCM
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let key = Key::<Aes256Gcm>::from_slice(&self.encryption_key);
        let cipher = Aes256Gcm::new(key);

        let nonce_bytes: [u8; 12] = rand::random();
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher.encrypt(nonce, plaintext)
            .map_err(|e| MazeError::EncryptionError(e.to_string()))?;

        // Prepend nonce to ciphertext
        let mut result = Vec::with_capacity(12 + ciphertext.len());
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&ciphertext);

        Ok(result)
    }

    /// Decrypt data using AES-256-GCM
    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        if ciphertext.len() < 12 {
            return Err(MazeError::DecryptionError("Ciphertext too short".into()));
        }

        let key = Key::<Aes256Gcm>::from_slice(&self.encryption_key);
        let cipher = Aes256Gcm::new(key);

        let nonce = Nonce::from_slice(&ciphertext[..12]);
        let encrypted = &ciphertext[12..];

        cipher.decrypt(nonce, encrypted)
            .map_err(|e| MazeError::DecryptionError(e.to_string()))
    }

    // ============ POCKET OPERATIONS ============

    /// Create a new pocket
    pub fn create_pocket(&self, pocket: &MazePocket) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            r#"INSERT INTO maze_pockets 
               (id, owner_meta_hash, stealth_pubkey, keypair_encrypted, 
                funding_maze_id, funding_amount_lamports, created_at, status)
               VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)"#,
            params![
                pocket.id,
                pocket.owner_meta_hash,
                pocket.stealth_pubkey,
                pocket.keypair_encrypted,
                pocket.funding_maze_id,
                pocket.funding_amount_lamports,
                pocket.created_at,
                pocket.status.as_str(),
            ],
        )?;
        Ok(())
    }

    /// Get pocket by ID
    pub fn get_pocket(&self, pocket_id: &str) -> Result<Option<MazePocket>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            r#"SELECT id, owner_meta_hash, stealth_pubkey, keypair_encrypted,
                      funding_maze_id, funding_amount_lamports, created_at,
                      last_sweep_at, status
               FROM maze_pockets WHERE id = ?1"#
        )?;

        let result = stmt.query_row(params![pocket_id], |row| {
            Ok(MazePocket {
                id: row.get(0)?,
                owner_meta_hash: row.get(1)?,
                stealth_pubkey: row.get(2)?,
                keypair_encrypted: row.get(3)?,
                funding_maze_id: row.get(4)?,
                funding_amount_lamports: row.get(5)?,
                created_at: row.get(6)?,
                last_sweep_at: row.get(7)?,
                status: PocketStatus::from_str(&row.get::<_, String>(8)?),
            })
        });

        match result {
            Ok(pocket) => Ok(Some(pocket)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(MazeError::DatabaseError(e.to_string())),
        }
    }

    /// Get pocket by ID and verify ownership
    pub fn get_pocket_for_owner(&self, pocket_id: &str, owner_meta_hash: &str) -> Result<Option<MazePocket>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            r#"SELECT id, owner_meta_hash, stealth_pubkey, keypair_encrypted,
                      funding_maze_id, funding_amount_lamports, created_at,
                      last_sweep_at, status
               FROM maze_pockets 
               WHERE id = ?1 AND owner_meta_hash = ?2"#
        )?;

        let result = stmt.query_row(params![pocket_id, owner_meta_hash], |row| {
            Ok(MazePocket {
                id: row.get(0)?,
                owner_meta_hash: row.get(1)?,
                stealth_pubkey: row.get(2)?,
                keypair_encrypted: row.get(3)?,
                funding_maze_id: row.get(4)?,
                funding_amount_lamports: row.get(5)?,
                created_at: row.get(6)?,
                last_sweep_at: row.get(7)?,
                status: PocketStatus::from_str(&row.get::<_, String>(8)?),
            })
        });

        match result {
            Ok(pocket) => Ok(Some(pocket)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(MazeError::DatabaseError(e.to_string())),
        }
    }

    /// List all pockets for an owner
    pub fn list_pockets(&self, owner_meta_hash: &str) -> Result<Vec<MazePocket>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            r#"SELECT id, owner_meta_hash, stealth_pubkey, keypair_encrypted,
                      funding_maze_id, funding_amount_lamports, created_at,
                      last_sweep_at, status
               FROM maze_pockets 
               WHERE owner_meta_hash = ?1 AND status != 'deleted' AND id NOT LIKE 'route_%'
               ORDER BY created_at DESC"#
        )?;

        let pockets = stmt.query_map(params![owner_meta_hash], |row| {
            Ok(MazePocket {
                id: row.get(0)?,
                owner_meta_hash: row.get(1)?,
                stealth_pubkey: row.get(2)?,
                keypair_encrypted: row.get(3)?,
                funding_maze_id: row.get(4)?,
                funding_amount_lamports: row.get(5)?,
                created_at: row.get(6)?,
                last_sweep_at: row.get(7)?,
                status: PocketStatus::from_str(&row.get::<_, String>(8)?),
            })
        })?;

        let mut result = Vec::new();
        for pocket in pockets {
            result.push(pocket.map_err(|e| MazeError::DatabaseError(e.to_string()))?);
        }
        Ok(result)
    }

    /// Update pocket status
    pub fn update_pocket_status(&self, pocket_id: &str, status: PocketStatus) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE maze_pockets SET status = ?1 WHERE id = ?2",
            params![status.as_str(), pocket_id],
        )?;
        Ok(())
    }

    /// Update pocket after sweep
    pub fn mark_pocket_swept(&self, pocket_id: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        let now = chrono::Utc::now().timestamp();
        conn.execute(
            "UPDATE maze_pockets SET status = 'swept', last_sweep_at = ?1 WHERE id = ?2",
            params![now, pocket_id],
        )?;
        Ok(())
    }

    /// Delete pocket (soft delete)
    pub fn delete_pocket(&self, pocket_id: &str, owner_meta_hash: &str) -> Result<bool> {
        let conn = self.conn.lock().unwrap();
        let rows = conn.execute(
            "UPDATE maze_pockets SET status = 'deleted' WHERE id = ?1 AND owner_meta_hash = ?2",
            params![pocket_id, owner_meta_hash],
        )?;
        Ok(rows > 0)
    }

    // ============ FUNDING REQUEST OPERATIONS ============

    /// Create a funding request
    pub fn create_funding_request(&self, request: &FundingRequest, maze_json: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            r#"INSERT INTO funding_requests 
               (id, pocket_id, owner_meta_hash, deposit_address, deposit_keypair_encrypted,
                amount_lamports, fee_lamports, maze_config_json, maze_graph_json,
                status, created_at, expires_at, destination_address)
               VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)"#,
            params![
                request.id,
                request.pocket_id,
                request.owner_meta_hash,
                request.deposit_address,
                request.deposit_keypair_encrypted,
                request.amount_lamports,
                request.fee_lamports,
                request.maze_config_json,
                maze_json,
                request.status,
                request.created_at,
                request.expires_at,
                request.destination_address,
            ],
        )?;
        Ok(())
    }

    /// Get funding request by deposit address
    pub fn get_funding_request_by_deposit(&self, deposit_address: &str) -> Result<Option<FundingRequest>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            r#"SELECT id, pocket_id, owner_meta_hash, deposit_address, deposit_keypair_encrypted,
                      amount_lamports, fee_lamports, maze_config_json, status,
                      created_at, expires_at, completed_at, error_message, destination_address, tx_signature
               FROM funding_requests WHERE deposit_address = ?1"#
        )?;

        let result = stmt.query_row(params![deposit_address], |row| {
            Ok(FundingRequest {
                id: row.get(0)?,
                pocket_id: row.get(1)?,
                owner_meta_hash: row.get(2)?,
                deposit_address: row.get(3)?,
                deposit_keypair_encrypted: row.get(4)?,
                amount_lamports: row.get(5)?,
                fee_lamports: row.get(6)?,
                maze_config_json: row.get(7)?,
                status: row.get(8)?,
                created_at: row.get(9)?,
                expires_at: row.get(10)?,
                completed_at: row.get(11)?,
                error_message: row.get(12)?,
                destination_address: row.get(13)?,
                tx_signature: row.get(14)?,
            })
        });

        match result {
            Ok(req) => Ok(Some(req)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(MazeError::DatabaseError(e.to_string())),
        }
    }

    /// Update funding request status
    pub fn update_funding_status(&self, request_id: &str, status: &str, error: Option<&str>) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        if status == "completed" {
            let now = chrono::Utc::now().timestamp();
            conn.execute(
                "UPDATE funding_requests SET status = ?1, completed_at = ?2 WHERE id = ?3",
                params![status, now, request_id],
            )?;
        } else {
            conn.execute(
                "UPDATE funding_requests SET status = ?1, error_message = ?2 WHERE id = ?3",
                params![status, error, request_id],
            )?;
        }
        Ok(())
    }

    /// Update funding request as completed with tx_signature
    pub fn update_funding_completed(&self, request_id: &str, tx_signature: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        let now = chrono::Utc::now().timestamp();
        conn.execute(
            "UPDATE funding_requests SET status = 'completed', completed_at = ?1, tx_signature = ?2 WHERE id = ?3",
            params![now, tx_signature, request_id],
        )?;
        Ok(())
    }

    /// Get pending funding requests (for deposit monitoring)
    pub fn get_pending_funding_requests(&self) -> Result<Vec<(String, String, i64)>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            r#"SELECT id, deposit_address, amount_lamports 
               FROM funding_requests 
               WHERE status = 'pending' AND expires_at > ?1"#
        )?;

        let now = chrono::Utc::now().timestamp();
        let rows = stmt.query_map(params![now], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?))
        })?;

        let mut result = Vec::new();
        for row in rows {
            result.push(row.map_err(|e| MazeError::DatabaseError(e.to_string()))?);
        }
        Ok(result)

    }
    // ============ MAZE NODE OPERATIONS ============

    /// Store a maze node
    pub fn store_maze_node(&self, request_id: &str, node: &crate::relay::maze::MazeNode) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        let inputs_json = serde_json::to_string(&node.inputs).unwrap_or_default();
        let outputs_json = serde_json::to_string(&node.outputs).unwrap_or_default();

        conn.execute(
            r#"INSERT OR REPLACE INTO maze_nodes 
               (request_id, node_index, level, address, keypair_encrypted,
                inputs, outputs, amount_in, amount_out, status)
               VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)"#,
            params![
                request_id,
                node.index,
                node.level,
                node.address,
                node.keypair_encrypted,
                inputs_json,
                outputs_json,
                node.amount_in,
                node.amount_out,
                node.status,
            ],
        )?;
        Ok(())
    }

    /// Get node status
    pub fn get_node_status(&self, request_id: &str, node_index: u16) -> Result<Option<String>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT status FROM maze_nodes WHERE request_id = ?1 AND node_index = ?2"
        )?;

        let result = stmt.query_row(params![request_id, node_index], |row| {
            row.get::<_, String>(0)
        });

        match result {
            Ok(status) => Ok(Some(status)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(MazeError::DatabaseError(e.to_string())),
        }
    }

    /// Update node status
    pub fn update_node_status(&self, request_id: &str, node_index: u16, status: &str, tx_sig: Option<&str>) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE maze_nodes SET status = ?1, tx_signature = ?2 WHERE request_id = ?3 AND node_index = ?4",
            params![status, tx_sig, request_id, node_index],
        )?;
        Ok(())
    }

    /// Get maze graph JSON
    pub fn get_maze_graph(&self, request_id: &str) -> Result<String> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT maze_graph_json FROM funding_requests WHERE id = ?1"
        )?;

        stmt.query_row(params![request_id], |row| row.get::<_, String>(0))
            .map_err(|e| MazeError::DatabaseError(e.to_string()))
    }

    /// Get funding request by ID
    pub fn get_funding_request(&self, request_id: &str) -> Result<Option<FundingRequest>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            r#"SELECT id, pocket_id, owner_meta_hash, deposit_address, deposit_keypair_encrypted,
                      amount_lamports, fee_lamports, maze_config_json, status,
                      created_at, expires_at, completed_at, error_message, destination_address, tx_signature
               FROM funding_requests WHERE id = ?1"#
        )?;

        let result = stmt.query_row(params![request_id], |row| {
            Ok(FundingRequest {
                id: row.get(0)?,
                pocket_id: row.get(1)?,
                owner_meta_hash: row.get(2)?,
                deposit_address: row.get(3)?,
                deposit_keypair_encrypted: row.get(4)?,
                amount_lamports: row.get(5)?,
                fee_lamports: row.get(6)?,
                maze_config_json: row.get(7)?,
                status: row.get(8)?,
                created_at: row.get(9)?,
                expires_at: row.get(10)?,
                completed_at: row.get(11)?,
                error_message: row.get(12)?,
                destination_address: row.get(13)?,
                tx_signature: row.get(14)?,
            })
        });

        match result {
            Ok(req) => Ok(Some(req)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(MazeError::DatabaseError(e.to_string())),
        }
    }

    /// Update pocket with funding maze ID
    pub fn update_pocket_funding_maze(&self, pocket_id: &str, maze_id: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE maze_pockets SET funding_maze_id = ?1 WHERE id = ?2",
            params![maze_id, pocket_id],
        )?;
        Ok(())
    }

    // ============ SWEEP REQUEST OPERATIONS ============

    /// Create a sweep request
    pub fn create_sweep_request(
        &self,
        id: &str,
        pocket_id: &str,
        destination: &str,
        amount: u64,
        maze_json: &str,
    ) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        let now = chrono::Utc::now().timestamp();
        conn.execute(
            r#"INSERT INTO sweep_requests
               (id, pocket_id, destination_address, amount_lamports, maze_graph_json, status, created_at)
               VALUES (?1, ?2, ?3, ?4, ?5, 'pending', ?6)"#,
            params![id, pocket_id, destination, amount, maze_json, now],
        )?;
        Ok(())
    }

    /// Get sweep request by ID
    pub fn get_sweep_request(&self, sweep_id: &str) -> Result<Option<(String, String, String, u64, String, String)>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            r#"SELECT id, pocket_id, destination_address, amount_lamports, maze_graph_json, status
               FROM sweep_requests WHERE id = ?1"#
        )?;

        let result = stmt.query_row(params![sweep_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)? as u64,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
            ))
        });

        match result {
            Ok(req) => Ok(Some(req)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(MazeError::DatabaseError(e.to_string())),
        }
    }

    /// Update sweep request status
    pub fn update_sweep_status(&self, sweep_id: &str, status: &str, tx_sig: Option<&str>, error: Option<&str>) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        if status == "completed" {
            let now = chrono::Utc::now().timestamp();
            conn.execute(
                "UPDATE sweep_requests SET status = ?1, completed_at = ?2, tx_signature = ?3 WHERE id = ?4",
                params![status, now, tx_sig, sweep_id],
            )?;
        } else {
            conn.execute(
                "UPDATE sweep_requests SET status = ?1, error_message = ?2 WHERE id = ?3",
                params![status, error, sweep_id],
            )?;
        }
        Ok(())
    }

    /// Get pending sweep requests
    pub fn get_pending_sweep_requests(&self) -> Result<Vec<(String, String)>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, pocket_id FROM sweep_requests WHERE status = 'pending'"
        )?;

        let rows = stmt.query_map([], |row| {
            Ok((row.get(0)?, row.get(1)?))
        })?;

        let mut result = Vec::new();
        for row in rows {
            result.push(row.map_err(|e| MazeError::DatabaseError(e.to_string()))?);
        }
        Ok(result)
    }

    /// Get sweep maze graph
    pub fn get_sweep_maze_graph(&self, sweep_id: &str) -> Result<String> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT maze_graph_json FROM sweep_requests WHERE id = ?1"
        )?;

        stmt.query_row(params![sweep_id], |row| row.get::<_, String>(0))
            .map_err(|e| MazeError::DatabaseError(e.to_string())) }

    /// Get maze progress for a funding request
    pub fn get_maze_progress(&self, request_id: &str) -> Result<(usize, usize, u8, u8)> {
        let conn = self.conn.lock().unwrap();
        
        // Get total nodes and completed nodes
        let total: usize = conn.query_row(
            "SELECT COUNT(*) FROM maze_nodes WHERE request_id = ?1",
            params![request_id],
            |row| row.get(0)
        ).unwrap_or(0);
        
        let completed: usize = conn.query_row(
            "SELECT COUNT(*) FROM maze_nodes WHERE request_id = ?1 AND status = 'completed'",
            params![request_id],
            |row| row.get(0)
        ).unwrap_or(0);
        
        // Get total levels and current level
        let total_levels: u8 = conn.query_row(
            "SELECT MAX(level) FROM maze_nodes WHERE request_id = ?1",
            params![request_id],
            |row| row.get::<_, Option<u8>>(0)
        ).unwrap_or(Some(0)).unwrap_or(0);
        
        let current_level: u8 = conn.query_row(
            "SELECT MIN(level) FROM maze_nodes WHERE request_id = ?1 AND status != 'completed'",
            params![request_id],
            |row| row.get::<_, Option<u8>>(0)
        ).unwrap_or(Some(0)).unwrap_or(0);
        
        Ok((completed, total, current_level, total_levels))
    }

    // === Sweep Maze Node Functions ===

    /// Store a sweep maze node
    pub fn store_sweep_node(&self, sweep_id: &str, node: &crate::relay::maze::MazeNode) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        let inputs_json = serde_json::to_string(&node.inputs).unwrap_or_default();
        let outputs_json = serde_json::to_string(&node.outputs).unwrap_or_default();

        conn.execute(
            r#"INSERT OR REPLACE INTO sweep_maze_nodes
               (sweep_id, node_index, level, address, keypair_encrypted,
                inputs, outputs, amount_in, amount_out, status)
               VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)"#,
            params![
                sweep_id,
                node.index,
                node.level,
                node.address,
                node.keypair_encrypted,
                inputs_json,
                outputs_json,
                node.amount_in,
                node.amount_out,
                node.status,
            ],
        )?;
        Ok(())
    }

    /// Get sweep node status
    pub fn get_sweep_node_status(&self, sweep_id: &str, node_index: u16) -> Result<Option<String>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT status FROM sweep_maze_nodes WHERE sweep_id = ?1 AND node_index = ?2"
        )?;

        let result = stmt.query_row(params![sweep_id, node_index], |row| {
            row.get::<_, String>(0)
        });

        match result {
            Ok(status) => Ok(Some(status)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(MazeError::DatabaseError(e.to_string())),
        }
    }

    /// Update sweep node status
    pub fn update_sweep_node_status(&self, sweep_id: &str, node_index: u16, status: &str, tx_sig: Option<&str>) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE sweep_maze_nodes SET status = ?1, tx_signature = ?2 WHERE sweep_id = ?3 AND node_index = ?4",
            params![status, tx_sig, sweep_id, node_index],
        )?;
        Ok(())
    }

    /// Get sweep maze progress
    pub fn get_sweep_maze_progress(&self, sweep_id: &str) -> Result<(usize, usize, u8, u8)> {
        let conn = self.conn.lock().unwrap();

        let total: usize = conn.query_row(
            "SELECT COUNT(*) FROM sweep_maze_nodes WHERE sweep_id = ?1",
            params![sweep_id],
            |row| row.get(0)
        ).unwrap_or(0);

        let completed: usize = conn.query_row(
            "SELECT COUNT(*) FROM sweep_maze_nodes WHERE sweep_id = ?1 AND status = 'completed'",
            params![sweep_id],
            |row| row.get(0)
        ).unwrap_or(0);

        let total_levels: u8 = conn.query_row(
            "SELECT MAX(level) FROM sweep_maze_nodes WHERE sweep_id = ?1",
            params![sweep_id],
            |row| row.get::<_, Option<u8>>(0)
        ).unwrap_or(Some(0)).unwrap_or(0);

        let current_level: u8 = conn.query_row(
            "SELECT MIN(level) FROM sweep_maze_nodes WHERE sweep_id = ?1 AND status != 'completed'",
            params![sweep_id],
            |row| row.get::<_, Option<u8>>(0)
        ).unwrap_or(Some(0)).unwrap_or(0);

        Ok((completed, total, current_level, total_levels))
    }

    // === Destination Wallet Functions ===

    pub fn add_destination_wallet(&self, owner_meta_hash: &str, slot: u8, wallet_address: &str) -> Result<()> {
        if slot < 1 || slot > 5 {
            return Err(MazeError::InvalidParameters("Slot must be 1-5".into()));
        }
        let created_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let conn = self.conn.lock().unwrap();

        conn.execute(
            "INSERT OR REPLACE INTO destination_wallets (owner_meta_hash, slot, wallet_address, created_at) VALUES (?1, ?2, ?3, ?4)",
            params![owner_meta_hash, slot, wallet_address, created_at],
        )?;
        Ok(())
    }

    pub fn get_destination_wallets(&self, owner_meta_hash: &str) -> Result<Vec<(u8, String)>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT slot, wallet_address FROM destination_wallets WHERE owner_meta_hash = ?1 ORDER BY slot"
        )?;
        let rows = stmt.query_map(params![owner_meta_hash], |row: &rusqlite::Row| {
            Ok((row.get::<_, u8>(0)?, row.get::<_, String>(1)?))
        })?;
        let mut wallets = Vec::new();
        for row in rows {
            wallets.push(row?);
        }
        Ok(wallets)
    }

    pub fn get_destination_wallet(&self, owner_meta_hash: &str, slot: u8) -> Result<Option<String>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT wallet_address FROM destination_wallets WHERE owner_meta_hash = ?1 AND slot = ?2"
        )?;
        let result = stmt.query_row(params![owner_meta_hash, slot], |row: &rusqlite::Row| {
            row.get::<_, String>(0)
        });
        match result {
            Ok(addr) => Ok(Some(addr)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(MazeError::DatabaseError(e.to_string())),
        }
    }

    pub fn delete_destination_wallet(&self, owner_meta_hash: &str, slot: u8) -> Result<bool> {
        let conn = self.conn.lock().unwrap();
        let rows = conn.execute(
            "DELETE FROM destination_wallets WHERE owner_meta_hash = ?1 AND slot = ?2",
            params![owner_meta_hash, slot],
        )?;
        Ok(rows > 0)
    }

    /// Get protocol statistics (no autopurge, so direct query)
    pub fn get_protocol_stats(&self) -> Result<ProtocolStats> {
        let conn = self.conn.lock().unwrap();
        let now = chrono::Utc::now().timestamp();
        let cutoff_24h = now - 86400;

        // Total nodes (maze_nodes + sweep_maze_nodes)
        let maze_nodes: i64 = conn.query_row(
            "SELECT COUNT(*) FROM maze_nodes",
            [],
            |row| row.get(0)
        ).unwrap_or(0);

        let sweep_nodes: i64 = conn.query_row(
            "SELECT COUNT(*) FROM sweep_maze_nodes",
            [],
            |row| row.get(0)
        ).unwrap_or(0);

        let total_nodes = maze_nodes + sweep_nodes;

        // Total hops (from funding_requests + sweep_requests)
        let funding_hops: i64 = conn.query_row(
            "SELECT COALESCE(SUM(json_extract(maze_graph_json, '$.total_transactions')), 0) FROM funding_requests WHERE maze_graph_json IS NOT NULL",
            [],
            |row| row.get(0)
        ).unwrap_or(0);

        let sweep_hops: i64 = conn.query_row(
            "SELECT COALESCE(SUM(json_extract(maze_graph_json, '$.total_transactions')), 0) FROM sweep_requests WHERE maze_graph_json IS NOT NULL",
            [],
            |row| row.get(0)
        ).unwrap_or(0);

        let total_hops = funding_hops + sweep_hops;

        // Nodes in last 24h
        let nodes_24h_maze: i64 = conn.query_row(
            "SELECT COUNT(*) FROM maze_nodes mn JOIN funding_requests fr ON mn.request_id = fr.id WHERE fr.created_at > ?1",
            params![cutoff_24h],
            |row| row.get(0)
        ).unwrap_or(0);

        let nodes_24h_sweep: i64 = conn.query_row(
            "SELECT COUNT(*) FROM sweep_maze_nodes smn JOIN sweep_requests sr ON smn.sweep_id = sr.id WHERE sr.created_at > ?1",
            params![cutoff_24h],
            |row| row.get(0)
        ).unwrap_or(0);

        let nodes_24h = nodes_24h_maze + nodes_24h_sweep;

        Ok(ProtocolStats {
            total_nodes_alltime: total_nodes,
            total_hops_alltime: total_hops,
            nodes_24h,
        })
    }

    /// Get final node tx_signature for a funding request
    pub fn get_final_tx_signature(&self, request_id: &str) -> Result<Option<String>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT tx_signature FROM maze_nodes WHERE request_id = ?1 AND tx_signature IS NOT NULL ORDER BY node_index DESC LIMIT 1"
        )?;
        let result = stmt.query_row(params![request_id], |row| row.get(0));
        match result {
            Ok(sig) => Ok(Some(sig)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(MazeError::DatabaseError(e.to_string())),
        }
    }

    /// Store MCP API key
    pub fn store_mcp_api_key(&self, api_key_hash: &str, wallet_address: &str, owner_meta_hash: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        let now = chrono::Utc::now().timestamp();
        conn.execute(
            "INSERT OR REPLACE INTO mcp_api_keys (api_key_hash, wallet_address, owner_meta_hash, created_at) VALUES (?1, ?2, ?3, ?4)",
            params![api_key_hash, wallet_address, owner_meta_hash, now],
        )?;
        Ok(())
    }
}
impl Drop for PocketDatabase {
    fn drop(&mut self) {
        // Securely wipe encryption key from memory
        self.encryption_key.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encryption_roundtrip() {
        let db = PocketDatabase::new(Some(":memory:"), "test_master_key_123").unwrap();
        let plaintext = b"Hello, Maze Pocket!";
        let encrypted = db.encrypt(plaintext).unwrap();
        let decrypted = db.decrypt(&encrypted).unwrap();
        assert_eq!(plaintext.to_vec(), decrypted);
    }

    #[test]
    fn test_pocket_crud() {
        let db = PocketDatabase::new(Some(":memory:"), "test_master_key_123").unwrap();
        
        let keypair_encrypted = db.encrypt(b"fake_keypair_bytes").unwrap();
        let pocket = MazePocket {
            id: "pocket_test123".to_string(),
            owner_meta_hash: "owner_hash_abc".to_string(),
            stealth_pubkey: "7xKj...3nM".to_string(),
            keypair_encrypted,
            funding_maze_id: Some("maze_123".to_string()),
            funding_amount_lamports: 1_000_000_000,
            created_at: chrono::Utc::now().timestamp(),
            last_sweep_at: None,
            status: PocketStatus::Active,
        };

        db.create_pocket(&pocket).unwrap();

        let retrieved = db.get_pocket("pocket_test123").unwrap().unwrap();
        assert_eq!(retrieved.id, pocket.id);
        assert_eq!(retrieved.owner_meta_hash, pocket.owner_meta_hash);

        let pockets = db.list_pockets("owner_hash_abc").unwrap();
        assert_eq!(pockets.len(), 1);
    }
}
