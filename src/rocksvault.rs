use std::sync::Arc;
use crate::prelude::KVStore;
use crate::config;

#[allow(unused_variables)]

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

    fn create_cf(&self, dbname: &str)
        -> std::io::Result<()>
    {
        let opts = rocksdb::Options::default();
        match self.db.create_cf(&dbname, &opts) {
            Ok(()) => Ok(()),
            Err(e) => Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    std::format!("Rockdb CF creation {} failed: {}",
                                 &dbname, e))),
            }
    }

    fn move_key(&self, from_db: &str, to_db: &str, k: &str)
        -> std::io::Result<()>
    {
        let Some(from_cf) = self.db.cf_handle(from_db) else {
            return Err(std::io::Error::new(std::io::ErrorKind::NotFound,
                    "Db not found"));
        };
        let Ok(res_bytes) = self.db.get_cf(&from_cf, k) else {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput,
                    std::format!("key lookup failed in db {from_db}")));
        };
        let Some(bytes) = res_bytes else {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput,
                    "key lookup returned null"));
        };
        let to_cf = self.db.cf_handle(to_db);
        let Some(to_cf) = to_cf else {
            return Err(std::io::Error::new(std::io::ErrorKind::NotFound,
                    "Deferred removal dbname not found"));
        };
        if let Ok(Some(_)) =  self.db.get_cf(&to_cf, k) {
            return Err(std::io::Error::new(
                    std::io::ErrorKind::AlreadyExists,
                    std::format!
                    ("key {} found in TO_CF",&k)));
        }
        if let Err(e) =  self.update_kv(
            &to_db, &k, std::string::String::from_utf8(bytes).unwrap()) {
            return Err(e);
        }
        if let Err(e) = self.delete_key(from_db, &k) {
            return Err(e);
        }
        Ok(())
    }

    fn delete_key(&self, dbname: &str, k: &str)
        -> std::io::Result<()>
    {
        match self.db.cf_handle(dbname) {
            Some(cf) => {
                let mut opts = rocksdb::WriteOptions::default();
                opts.set_sync(true);
                match self.db.delete_cf_opt(&cf, k, &opts) {
                    Ok(()) => Ok(()),
                    Err(e) =>
                        Err(std::io::Error::new(
                                std::io::ErrorKind::InvalidInput,
                                std::format!(
                                    "key deletion failed, {}", e)))
                }
            }
            None => Err(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "Db not found")),
        }
    }
}

impl KVStore for RocksDbVault
{
    fn create_db(&self, dbname: String) -> std::io::Result<()>
    {
        // TODO: Customizations for small db size, point lookups
        // are available here for use as directed by the service config.
        // Using the default for now.
        let dr_dbname = std::format!("del_pending_{dbname}");
        let metadata_dbname = std::format!("metadata_{dbname}");
        if let Err(e) = self.create_cf(&dbname) {
            return Err(e);
        }
        if let Err(e) = self.create_cf(&dr_dbname) {
            let _ = self.delete_db(&dbname);
            return Err(e);
        }
        if let Err(e) = self.create_cf(&metadata_dbname) {
            let _ = self.delete_db(&dbname);
            return Err(e);
        }
        Ok(())
    }
    
    fn delete_db(&self, dbname: &str) -> std::io::Result<()>
    {
        let deferred_removal_dbname = std::format!("del_pending_{dbname}");
        let metadata_dbname = std::format!("metadata_{dbname}");
        let _ = self.db.drop_cf(&deferred_removal_dbname);
        let _ = self.db.drop_cf(&metadata_dbname);
        match self.db.drop_cf(dbname) {
            Ok(()) => Ok(()),
            Err(e) => Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    std::format!("rocks-db column-family drop {} failed; {}",
                                 dbname, e))),
        }
    }   

    fn add_kv(&self, dbname: &str, k: String, v: String)
        -> std::io::Result<()>
    {
        let dr_dbname =
            std::format!("del_pending_{dbname}");
        let dr_db = self.db.cf_handle(&dr_dbname);
        let Some(dr_cf) = dr_db else {
            return Err(std::io::Error::new(std::io::ErrorKind::NotFound,
                    "Deferred-removal dbname not found"));
        };
        if let Ok(Some(_)) = self.db.get_cf(&dr_cf, &k) {
            return Err(std::io::Error::new(
                    std::io::ErrorKind::AlreadyExists,
                    std::format!("Key {} in DELETING state", &k)));
        }
        match self.db.cf_handle(dbname) {
            Some(cf) => {
                match self.db.get_cf(&cf, &k) {
                    Ok(Some(_)) => Err(std::io::Error::new(
                            std::io::ErrorKind::AlreadyExists,
                            std::format!("Duplicate key, {}", &k))),
                    Ok(None) => self.update_kv(dbname, &k, v),
                    Err(_e) => self.update_kv(dbname, &k, v)
                }
            },
            None => Err(std::io::Error::new(std::io::ErrorKind::NotFound,
                                            "Db not found")),
        }
    }
    fn update_kv(&self, dbname: &str, k: &str, v: String)
        -> std::io::Result<()>
    {
        println!("Adding [{k}:{}] to {dbname}", &v);
        match self.db.cf_handle(dbname) {
            Some(cf) => {
                let mut opts = rocksdb::WriteOptions::default();
                opts.set_sync(true);
                match self.db.put_cf_opt(&cf, k, v, &opts) {
                    Ok(()) => Ok(()),
                    Err(e) => Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidInput,
                            std::format!(
                                "key update failed, {}", e))),
                }
            },
            None => Err(std::io::Error::new(std::io::ErrorKind::NotFound,
                                            "Db not found")),
        }
    }

    fn remove_kv(&self, dbname: &str, k: &str)
        -> std::io::Result<()>
    {
        let deferred_removal_dbname =
            std::format!("del_pending_{dbname}");
        let found_in_del_pending = 
            self.delete_key(&deferred_removal_dbname, k).is_ok();
        if let Err(e) = self.delete_key(dbname, k) {
            if e.kind() == std::io::ErrorKind::InvalidInput &&
                found_in_del_pending {
                    return Ok(());
                }
                return Err(e);
        }
        Ok(())
    }

    fn get_kv(&self, dbname: &str, k: &str) -> std::io::Result<String>
    {
        match self.db.cf_handle(dbname) {
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
                    "Db not found")),
        }
    }

    fn initiate_kv_removal(&self, dbname: &str, k: &str)
        -> std::io::Result<()>
    {
        let dr_dbname = std::format!("del_pending_{dbname}");
        match self.move_key(dbname, &dr_dbname, &k) {
            Ok(()) => Ok(()),
            Err(e) => {
                if e.kind() == std::io::ErrorKind::AlreadyExists {
                    Err(std::io::Error::new(
                            std::io::ErrorKind::AlreadyExists,
                            "key in DELETING state."))
                } else {
                    Err(e)
                }
            }
        }
    }

    fn cancel_kv_removal(&self, dbname: &str, k: &str)
        -> std::io::Result<()>
    {
        let dr_dbname = std::format!("del_pending_{dbname}");
        match self.move_key(&dr_dbname, dbname, &k) {
            Ok(()) => Ok(()),
            Err(e) => {
                if e.kind() == std::io::ErrorKind::AlreadyExists {
                    Err(std::io::Error::new(
                            std::io::ErrorKind::AlreadyExists,
                            "Duplicate key in ACTIVE state."))
                } else {
                    Err(e)
                }
            }
        }
    }

    fn complete_kv_removal(&self, dbname: &str, k: &str)
        -> std::io::Result<()>
    {
        self.remove_kv(dbname, k)
    }

    fn list_keys_in_removal(&self, dbname: &str) -> std::io::Result<Vec<String>>
    {
        let mut keys = Vec::new();
        let dr_dbname = std::format!("del_pending_{dbname}");
        let Some(dr_db) = self.db.cf_handle(&dr_dbname) else {
            return Err(std::io::Error::new(std::io::ErrorKind::NotFound,
                    "Db not found"));
        };
        let iter = self.db.iterator_cf(&dr_db, rocksdb::IteratorMode::Start);
        /*
        {
            return Err(std::io::Error::new(std::io::ErrorKind::Other,
                    "Failed to assign iterator on db"));
        };
        */
        for item in iter {
            let (k, _) = item.unwrap();
            let k = std::string::String::from_utf8(k.to_vec()).unwrap();
            println!("Deferred delete key: {}", k);
            keys.push(k);
        }
        Ok(keys)
    }

}

