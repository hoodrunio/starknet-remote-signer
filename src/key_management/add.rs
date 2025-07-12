use anyhow::Result;

use crate::cli::AddKeyArgs;
use crate::key_management::service::KeyManagementService;

/// Add a new key to the specified keystore backend
pub async fn add_key(args: AddKeyArgs) -> Result<()> {
    KeyManagementService::add_key(
        &args.backend,
        &args.key_name,
        &args.private_key,
        args.keystore_path,
        args.keystore_dir,
        None, // env_var not used in add command
        args.passphrase,
    )
    .await
}
