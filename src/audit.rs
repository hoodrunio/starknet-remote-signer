use chrono::{DateTime, Utc};
use serde::Serialize;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::sync::Arc;
use starknet::core::utils::parse_cairo_short_string;
use starknet_crypto::Felt;
use tokio::sync::Mutex;

use crate::errors::SignerError;

#[derive(Serialize)]
pub struct AttestationAuditEntry {
    // Timestamp
    timestamp: DateTime<Utc>,
    
    // Request info
    source_ip: String,
    chain_id: String,
    chain_id_hex: String,
    
    // Transaction details
    sender_address: String,
    nonce: String,
    
    // Attestation specific (extracted from calldata)
    attestation_contract: Option<String>,
    attested_block_hash: Option<String>,
    
    // Signature info
    tx_hash: String,
    signature_r: String,
    signature_s: String,
    
    // Result
    success: bool,
    error: Option<String>,
    duration_ms: u64,
}

impl AttestationAuditEntry {
    pub fn from_request(
        request: &SignRequest,
        source_ip: &str,
        start_time: std::time::Instant,
    ) -> Self {
        // Parse chain ID to human readable
        let chain_id_str = parse_cairo_short_string(&request.chain_id)
            .unwrap_or_else(|_| format!("{:#x}", request.chain_id));
        
        // Extract attestation specific data from calldata
        // Attestation calldata structure:
        // [0]: "0x1" (call array length)
        // [1]: attestation contract address
        // [2]: selector (attest function)
        // [3]: "0x1" (calldata length)
        // [4]: block hash being attested
        let attestation_contract = request.transaction.calldata.get(1)
            .map(|f| format!("{:#x}", f));
            
        let attested_block_hash = request.transaction.calldata.get(4)
            .map(|f| format!("{:#x}", f));
        
        Self {
            timestamp: Utc::now(),
            source_ip: source_ip.to_string(),
            chain_id: chain_id_str,
            chain_id_hex: format!("{:#x}", request.chain_id),
            sender_address: format!("{:#x}", request.transaction.sender_address),
            nonce: format!("{:#x}", request.transaction.nonce),
            attestation_contract,
            attested_block_hash,
            tx_hash: String::new(), // Will be filled later
            signature_r: String::new(), // Will be filled later
            signature_s: String::new(), // Will be filled later
            success: false,
            error: None,
            duration_ms: start_time.elapsed().as_millis() as u64,
        }
    }
    
    pub fn set_transaction_hash(&mut self, tx_hash: Felt) {
        self.tx_hash = format!("{:#x}", tx_hash);
    }
    
    pub fn set_signature(&mut self, signature: &[Felt]) {
        if signature.len() >= 2 {
            self.signature_r = format!("{:#x}", signature[0]);
            self.signature_s = format!("{:#x}", signature[1]);
        }
    }
    
    pub fn set_success(&mut self, success: bool) {
        self.success = success;
    }
    
    pub fn set_error(&mut self, error: String) {
        self.error = Some(error);
        self.success = false;
    }
    
    pub fn update_duration(&mut self, start_time: std::time::Instant) {
        self.duration_ms = start_time.elapsed().as_millis() as u64;
    }
}

pub struct AuditLogger {
    file: Arc<Mutex<File>>,
}

impl AuditLogger {
    pub fn new(log_path: &str) -> Result<Self, SignerError> {
        let path = Path::new(log_path);
        
        // Create directory if it doesn't exist
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| SignerError::Internal(format!("Failed to create audit log directory: {}", e)))?;
        }
        
        // Open file in append mode
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .map_err(|e| SignerError::Internal(format!("Failed to open audit log file: {}", e)))?;
        
        Ok(Self {
            file: Arc::new(Mutex::new(file)),
        })
    }
    
    pub async fn log(&self, entry: &AttestationAuditEntry) -> Result<(), SignerError> {
        let json = serde_json::to_string(entry)
            .map_err(|e| SignerError::Internal(format!("Failed to serialize audit entry: {}", e)))?;
        
        let mut file = self.file.lock().await;
        writeln!(file, "{}", json)
            .map_err(|e| SignerError::Internal(format!("Failed to write audit log: {}", e)))?;
        file.flush()
            .map_err(|e| SignerError::Internal(format!("Failed to flush audit log: {}", e)))?;
        
        Ok(())
    }
}

// Re-export for use in server
pub use crate::server::SignRequest; 