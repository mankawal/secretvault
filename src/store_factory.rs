use std::sync::Arc;

use crate::config;
use crate::memvault;
use crate::rocksvault;
use crate::prelude;

pub fn create_store(cfg: &config::ServiceConfig)
    -> std::io::Result<Arc<dyn prelude::KVStore + Send + Sync>>
{
    match cfg.store.name.as_str() {
        "rocks" => rocksvault::build_kvstore_rocks(&cfg.store),
        "mem" => memvault::build_kvstore_mem(&cfg.store),
        unsupported_store_name => {
            Err(std::io::Error::new(std::io::ErrorKind::InvalidInput,
                    std::format!("Unsupported store name {}",
                                 unsupported_store_name)))
        }
    }
}
