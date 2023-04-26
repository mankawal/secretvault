use std::sync::{Arc, RwLock};
use std::collections::HashMap;

use crate::prelude::KVStore;
use crate::config;

pub fn build_kvstore_mem(_cfg: &config::StoreConfig)
    -> std::io::Result<Arc<dyn KVStore + Send + Sync>>
{
    let mv = MemVaultMap::new();
    Ok(Arc::new(mv))
}

#[derive(Debug, Default)]
pub struct MemVaultMap 
{
    map: Arc<RwLock<HashMap<String, MemVault>>>
}

impl MemVaultMap
{
    pub fn new() -> MemVaultMap 
    {
        MemVaultMap{ map: Arc::new(RwLock::new(HashMap::new())) }
    }
}

impl Clone for MemVaultMap
{
    fn clone(&self) -> MemVaultMap
    {
        MemVaultMap{ map: self.map.clone() }
    }

}

impl KVStore for MemVaultMap
{
    fn create_db(&self, vault: String) -> std::io::Result<()>
    {
        let mut map_locked = self.map.write().unwrap();
        match map_locked.insert(vault, MemVault::new()) {
            Some(_) => Err(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                "Duplicate vault name")),
            None => Ok(()),
        }
    }

    fn delete_db(&self, vault: &str) -> std::io::Result<()>
    {
        let mut map_locked = self.map.write().unwrap();
        match map_locked.remove(vault) {
            Some(_) => Ok(()),
            None => Err(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "Vault not found")),
        }
    }

    fn add_kv(&self, vault: &str,
              k: String, v: String) -> std::io::Result<()>
    {
        let map_locked = self.map.read().unwrap();
        match map_locked.get(vault) {
            Some(vault) =>  vault.add(k, v),
            None => Err(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "Vault not found")),
        }
    }
    fn update_kv(&self, vault: &str,
              k: &str, v: String) -> std::io::Result<()>
    {
        let map_locked = self.map.read().unwrap();
        match map_locked.get(vault) {
            Some(vault) => {
                match vault.update(k, v) {
                    true => Ok(()),
                    false => Err(std::io::Error::new(
                            std::io::ErrorKind::NotFound,
                            std::format!("Key {} not found", &k)))
                }
            },
            None => Err(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "Vault not found")),
        }
    }
    fn remove_kv(&self, vault: &str, k: &str) -> std::io::Result<()>
    {
        let map_locked = self.map.read().unwrap();
        match map_locked.get(vault) {
            Some(vault) => {
                match vault.del(k) {
                    true => Ok(()),
                    false => Err(std::io::Error::new(
                            std::io::ErrorKind::NotFound,
                            "Key not found")),
                }
            },
            None => Err(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "Vault not found")),
        }
    }

    fn get_kv(&self, vault: &str, k: &str) -> std::io::Result<String>
    {
        let map_locked = self.map.read().unwrap();
        match map_locked.get(vault) {
            Some(vault) => {
                match vault.get(k) {
                    Some(value) => Ok(value),
                    None => Err(std::io::Error::new(
                            std::io::ErrorKind::NotFound,
                            "Key not found")),
                }
            },
            None => Err(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "Vault not found")),
        }
    }

    fn initiate_kv_removal(&self, vault: &str, k: &str)
        -> std::io::Result<()>
    {
        let map_locked = self.map.read().unwrap();
        match map_locked.get(vault) {
            Some(vault) => {
                vault.initiate_kv_removal(k)
            },
            None => Err(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "Vault not found")),
        }
    }

    fn cancel_kv_removal(&self, vault: &str, k: &str)
        -> std::io::Result<()>
    {
        let map_locked = self.map.read().unwrap();
        match map_locked.get(vault) {
            Some(vault) => {
                vault.cancel_kv_removal(k)
            },
            None => Err(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "Vault not found")),
        }
    }

    fn complete_kv_removal(&self, vault: &str, k: &str)
        -> std::io::Result<()>
    {
        self.remove_kv(vault, k)
    }

    fn list_keys_in_removal(&self, vault: &str)
        -> std::io::Result<Vec<String>>
    {
        let map_locked = self.map.read().unwrap();
        match map_locked.get(vault) {
            Some(vault) => {
                vault.list_keys_in_removal()
            },
            None => Err(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "Vault not found")),
        }
    }
}

impl std::fmt::Display for MemVaultMap
{
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result
    {
        let map_locked = self.map.read().unwrap();
        for (k,v) in map_locked.iter() {
            write!(f, "\n---- vault: {k} ----:\n{v}\n",)?;
        }
        Ok(())
    }
}

#[derive(Debug, Default)]
struct Vault
{
    map: HashMap<String, String>,
    del_map: HashMap<String, String>,
}

impl Vault
{
    fn initiate_kv_removal(&mut self, k: &str)
        -> std::io::Result<()>
    {
        match self.map.get(k) {
            Some(v) => {
                self.del_map.insert(k.to_string(), v.to_string());
                self.map.remove(k);
                Ok(())
            },
            None => Err(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "Key {k} not found"))
        }
    }

    fn cancel_kv_removal(&mut self, k: &str)
        -> std::io::Result<()>
    {
        match self.del_map.get(k) {
            Some(v) => {
                self.map.insert(k.to_string(), v.to_string());
                self.del_map.remove(k);
                Ok(())
            },
            None => Err(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "Key {k} not found"))
        }
    }
}

#[derive(Debug, Default)]
pub struct MemVault
{
    vault: Arc<RwLock<Vault>>
}

impl MemVault
{
    pub fn new() -> MemVault
    {
        MemVault{ vault: Arc::new(RwLock::new(Vault::default())) }
    }
    
    pub fn add(&self, key: String, val: String)
        -> std::io::Result<()>
    {
        let mut vault_locked = self.vault.write().unwrap();
        // Do not allow creating a key if its old incarnation
        // is in `deleting` state.
        if vault_locked.del_map.get(&key).is_some() {
            return Err(std::io::Error::new(
                    std::io::ErrorKind::AlreadyExists,
                    std::format!("Key found in DELETING state.")));
        }
        if vault_locked.map.insert(key, val).is_some() {
            return Err(std::io::Error::new(
                    std::io::ErrorKind::AlreadyExists,
                    std::format!("Duplicate key found.")));
        }
        Ok(())
    }

    pub fn del(&self, key: &str) -> bool
    {
        let mut vault_locked = self.vault.write().unwrap();
        vault_locked.map.remove(key).is_some() ||
            vault_locked.del_map.remove(key).is_some()
    }

    pub fn get(&self, key: &str) -> Option<String>
    {
        let vault_locked = self.vault.read().unwrap();
        vault_locked.map.get(key).map(|val| val.clone())
    }

    pub fn update(&self, k: &str, v: String) -> bool
    {
        let mut vault_locked = self.vault.write().unwrap();
        match vault_locked.map.get_mut(k) {
            Some(old_val) => {
                *old_val = v;
                true
            },
            None => false,
        }
    }

    pub fn initiate_kv_removal(&self, k: &str)
        -> std::io::Result<()>
    {
        let mut vault_locked = self.vault.write().unwrap();
        vault_locked.initiate_kv_removal(&k)
    }

    pub fn cancel_kv_removal(&self, k: &str)
        -> std::io::Result<()>
    {
        let mut vault_locked = self.vault.write().unwrap();
        vault_locked.cancel_kv_removal(&k)
    }

    pub fn list_keys_in_removal(&self)
        -> std::io::Result<Vec<String>>
    {
        let vault_locked = self.vault.read().unwrap();
        Ok(vault_locked.map.clone().into_keys().collect())
    }
}

impl std::fmt::Display for MemVault
{
    fn fmt(&self, f:&mut std::fmt::Formatter) -> std::fmt::Result
    {
        let vault_locked = self.vault.read().unwrap();
        for (k,v) in vault_locked.map.iter() {
            write!(f, "{k}: {v}\n")?;
        }
        write!(f, " - Keys in removal - \n")?;
        for (k,_) in vault_locked.del_map.iter() {
            write!(f, "\t{k}\n")?;
        }
        Ok(())
    }
}

