use anyhow::Result;

use crate::cli::DeleteKeyArgs;
use crate::key_management::service::KeyManagementService;

/// Delete a key from the specified keystore backend
pub async fn delete_key(args: DeleteKeyArgs) -> Result<()> {
    KeyManagementService::delete_key(
        &args.backend,
        &args.key_name,
        args.keystore_path,
        args.keystore_dir,
        args.confirm,
    )
    .await
}
