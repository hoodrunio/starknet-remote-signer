use anyhow::Result;

use crate::cli::ListKeysArgs;
use crate::key_management::service::KeyManagementService;

/// List keys from the specified keystore backend
pub async fn list_keys(args: ListKeysArgs) -> Result<()> {
    KeyManagementService::list_keys(&args.backend, args.keystore_path, args.keystore_dir).await
}
