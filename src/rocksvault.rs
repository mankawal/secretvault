use std::sync::Arc;
use crate::prelude::KVStore;
use crate::config;

// --- RocksDb based KVStore

pub fn build_kvstore_rocks(cfg: &config::StoreConfig)
    -> std::io::Result<Arc<dyn KVStore + Send + Sync>>
{
    Ok(Arc::new(RocksDbVault::new(&cfg.dbpath)))
}

#[derive(Clone)]
pub struct RocksDbVault
{
    db: Arc<rocksdb::DB>
}

impl RocksDbVault
{
    fn new (dbpath: &str) -> Self
    {
        let mut options = rocksdb::Options::default();
        options.create_if_missing(true);
        
        let cfs = 
            rocksdb::DB::list_cf(&options, dbpath)
            .unwrap_or_default();
        RocksDbVault {
            db: Arc::new(rocksdb::DB::open_cf(
                        &options, dbpath, cfs).unwrap())
        }
    }
}

impl KVStore for RocksDbVault
{
    fn create_locker(&self, locker: String) -> std::io::Result<()>
    {
        // TODO: Customizations for small db size, point lookups
        // are available here for use as directed by the service config.
        // Using the default for now.
        let opts = rocksdb::Options::default();
        match self.db.create_cf(&locker, &opts) {
            Ok(()) => Ok(()),
            Err(e) => Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    std::format!("Rockdb CF creation {} failed: {}",
                                 &locker, e))),
        }
    }
    
    fn delete_locker(&self, locker: &str) -> std::io::Result<()>
    {
        match self.db.drop_cf(locker) {
            Ok(()) => Ok(()),
            Err(e) => Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    std::format!("rocks-db column-family drop {} failed; {}",
                                 locker, e))),
        }
    }

    

    fn add_kv(&self, locker: &str, k: String, v: String)
        -> std::io::Result<()>
    {
        match self.db.cf_handle(locker) {
            Some(cf) => {
                match self.db.get_cf(&cf, &k) {
                    Ok(Some(_)) => Err(std::io::Error::new(
                            std::io::ErrorKind::AlreadyExists,
                            std::format!(
                                "Duplicate key, {}", &k))),
                    Ok(None) => {
                        self.update_kv(locker, &k, v)
                    },
                    Err(_e) => {
                        self.update_kv(locker, &k, v)
                    },
                }
            },
            None => Err(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "Locker not found")),
        }
    }
    fn update_kv(&self, locker: &str, k: &str, v: String)
        -> std::io::Result<()>
    {
        match self.db.cf_handle(locker) {
            Some(cf) => {
                let mut opts = rocksdb::WriteOptions::default();
                opts.set_sync(true);
                match self.db.put_cf_opt(&cf, k, v, &opts) {
                    Ok(()) => Ok(()),
                    Err(e) => Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidInput,
                            std::format!(
                                "key, value insertion failed, {}", e))),
                }
            },
            None => Err(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "Locker not found")),
        }
    }

    fn remove_kv(&self, locker: &str, k: &str)
        -> std::io::Result<()>
    {
        match self.db.cf_handle(locker) {
            Some(cf) => {
                let mut opts = rocksdb::WriteOptions::default();
                opts.set_sync(true);
                match self.db.delete_cf_opt(&cf, k, &opts) {
                    Ok(()) => Ok(()),
                    Err(e) => Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidInput,
                            std::format!(
                                "key, value insertion failed, {}", e))),
                }
            },
            None => Err(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "Locker not found")),
        }
    }
    fn get_kv(&self, locker: &str, k: &str) -> std::io::Result<String>
    {
        match self.db.cf_handle(locker) {
            Some(cf) => {
                match self.db.get_cf(&cf, k) {
                    Ok(res_bytes) => {
                        if let Some(bytes) = res_bytes {
                            Ok(std::string::String::from_utf8(bytes).unwrap())
                        } else {
                            Err(std::io::Error::new(
                                    std::io::ErrorKind::InvalidInput,
                                        "key lookup returned null".to_string()))
                        }
                    },
                    Err(e) => Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidInput,
                            std::format!(
                                "key lookup failed, {}", e))),
                }
            },
            None => Err(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "Locker not found")),
        }
    }
}

