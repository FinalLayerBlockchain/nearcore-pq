use near_chain::types::LatestKnown;
use near_chain_configs::GenesisValidationMode;
use near_primitives::block::Tip;
use near_primitives::block_header::BlockHeader;
use near_primitives::hash::CryptoHash;
use near_store::{DBCol, FINAL_HEAD_KEY, HEAD_KEY, HEADER_HEAD_KEY, LATEST_KNOWN_KEY, NodeStorage};
use std::path::Path;
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};

const SPICE_EXECUTION_HEAD_KEY: &[u8] = b"SPICE_EXECUTION_HEAD";
const SPICE_FINAL_EXECUTION_HEAD_KEY: &[u8] = b"SPICE_FINAL_EXECUTION_HEAD";

#[derive(clap::Args)]
pub(crate) struct ResetHeadCommand {
    #[clap(long)]
    hash: String,
}

impl ResetHeadCommand {
    pub(crate) fn run(
        &self,
        home_dir: &Path,
        genesis_validation: GenesisValidationMode,
    ) -> anyhow::Result<()> {
        let near_config = nearcore::config::load_config(&home_dir, genesis_validation)?;
        let opener = NodeStorage::opener(
            home_dir,
            &near_config.config.store,
            near_config.config.cold_store.as_ref(),
            near_config.cloud_storage_context(),
        );
        let storage = opener.open()?;
        let store = storage.get_hot_store();

        let target_hash = CryptoHash::from_str(&self.hash)
            .map_err(|e| anyhow::anyhow!("Invalid hash: {}", e))?;

        let header: BlockHeader = store
            .get_ser(DBCol::BlockHeader, target_hash.as_ref())
            .ok_or_else(|| anyhow::anyhow!("Block header not found for hash {}", target_hash))?;

        let tip = Tip::from_header(&header);

        let now_ns = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;
        let latest_known = LatestKnown { height: tip.height, seen: now_ns };

        println!("Resetting HEAD to height={} hash={}", tip.height, tip.last_block_hash);

        let mut store_update = store.store_update();
        store_update.set_ser(DBCol::BlockMisc, HEAD_KEY, &tip);
        store_update.set_ser(DBCol::BlockMisc, FINAL_HEAD_KEY, &tip);
        store_update.set_ser(DBCol::BlockMisc, HEADER_HEAD_KEY, &tip);
        store_update.set_ser(DBCol::BlockMisc, LATEST_KNOWN_KEY, &latest_known);
        store_update.set_ser(DBCol::BlockMisc, SPICE_EXECUTION_HEAD_KEY, &tip);
        store_update.set_ser(DBCol::BlockMisc, SPICE_FINAL_EXECUTION_HEAD_KEY, &tip);
        store_update.commit();

        println!("SUCCESS: All keys reset to height {}", tip.height);
        Ok(())
    }
}
