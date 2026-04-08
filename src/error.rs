//! Error types for SDP Maze Pocket

use thiserror::Error;

#[derive(Error, Debug)]
pub enum MazeError {
    #[error("Database error: {0}")]
    DatabaseError(String),

    #[error("Encryption error: {0}")]
    EncryptionError(String),

    #[error("Decryption error: {0}")]
    DecryptionError(String),

    #[error("RPC error: {0}")]
    RpcError(String),

    #[error("Invalid parameters: {0}")]
    InvalidParameters(String),

    #[error("Insufficient funds: required {required}, available {available}")]
    InsufficientFunds { required: u64, available: u64 },

    #[error("Request not found: {0}")]
    RequestNotFound(String),

    #[error("Pocket not found: {0}")]
    PocketNotFound(String),

    #[error("Transaction error: {0}")]
    TransactionError(String),

    #[error("Maze generation error: {0}")]
    MazeGenerationError(String),

    #[error("Crypto error: {0}")]
    CryptoError(String),

    #[error("Unauthorized: {0}")]
    Unauthorized(String),

    #[error("Pocket already exists: {0}")]
    PocketAlreadyExists(String),

    #[error("Pocket is empty")]
    PocketEmpty,

    #[error("Sweep in progress")]
    SweepInProgress,
    
    #[error("Invalid meta address: {0}")]
    InvalidMetaAddress(String),
    
    #[error("Request expired")]
    RequestExpired,
    
    #[error("Keypair error: {0}")]
    KeypairError(String),
    
    #[error("Parse error: {0}")]
    ParseError(String),
}

pub type Result<T> = std::result::Result<T, MazeError>;

impl From<rusqlite::Error> for MazeError {
    fn from(err: rusqlite::Error) -> Self {
        MazeError::DatabaseError(err.to_string())
    }
}

impl From<solana_client::client_error::ClientError> for MazeError {
    fn from(err: solana_client::client_error::ClientError) -> Self {
        MazeError::RpcError(err.to_string())
    }
}
impl From<ed25519_dalek::SignatureError> for MazeError {
    fn from(err: ed25519_dalek::SignatureError) -> Self {
        MazeError::KeypairError(err.to_string())
    }
}

impl From<solana_sdk::pubkey::ParsePubkeyError> for MazeError {
    fn from(err: solana_sdk::pubkey::ParsePubkeyError) -> Self {
        MazeError::ParseError(err.to_string())
    }
}
