use std::sync::atomic::AtomicU64;
use std::sync::Arc;

use crate::audit::AuditLogger;
use crate::config::Config;
use crate::security::SecurityValidator;
use crate::signer::StarknetSigner;
use crate::validation::AttestationValidator;

/// Shared application state
#[derive(Clone)]
pub struct AppState {
    pub signer: StarknetSigner,
    pub config: Config,
    pub metrics: Arc<Metrics>,
    pub security: SecurityValidator,
    pub audit_logger: Option<Arc<AuditLogger>>,
    pub attestation_validator: AttestationValidator,
}

/// Basic metrics for monitoring
#[derive(Default)]
pub struct Metrics {
    pub sign_requests: AtomicU64,
    pub sign_errors: AtomicU64,
    pub health_checks: AtomicU64,
}

impl AppState {
    pub async fn new(config: Config) -> Result<Self, crate::errors::SignerError> {
        // Initialize keystore
        let mut keystore = config.create_keystore().await?;
        keystore.init(config.passphrase.as_deref()).await?;

        let signer = StarknetSigner::new(keystore).await?;
        let metrics = Arc::new(Metrics::default());

        // Initialize security validator (always create for proper validation)
        let security = SecurityValidator::new(
            config.security.allowed_chain_ids.clone(),
            config.security.allowed_ips.clone(),
        )?;

        // Initialize audit logger if configured
        let audit_logger = if config.audit.enabled {
            Some(Arc::new(AuditLogger::new(&config.audit.log_path)?))
        } else {
            None
        };

        // Initialize attestation validator (chain will be detected per request)
        let attestation_validator = AttestationValidator::new(None, true);

        Ok(Self {
            signer,
            config,
            metrics,
            security,
            audit_logger,
            attestation_validator,
        })
    }
}
