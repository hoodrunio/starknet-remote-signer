use anyhow::Result;
use clap::Parser;

use starknet_remote_signer::{cli, Cli};

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    cli::dispatch_commands(cli).await
}
