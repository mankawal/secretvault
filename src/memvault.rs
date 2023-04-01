use std::sync::{Arc, RwLock};
use std::collections::HashMap;

use crate::prelude::KVStore;
use crate::config;

pub fn build_kvstore_mem(_cfg: &config::StoreConfig)
    -> std::io::Result<Arc<dyn KVStore + Send + Sync>>
{
    let mv = MemVault::new();
    Ok(Arc::new(mv))
}

#[derive(Debug, Default)]
pub struct MemVault 
{
    map: Arc<RwLock<HashMap<String, MemLocker>>>
}

impl MemVault
{
    pub fn new() -> MemVault 
    {
        MemVault{ map: Arc::new(RwLock::new(HashMap::new())) }
    }
}

impl Clone for MemVault
{
    fn clone(&self) -> MemVault
    {
        MemVault{ map: self.map.clone() }
    }

}

impl KVStore for MemVault
{
    fn create_locker(&self, locker: String) -> std::io::Result<()>
    {
        let mut map_locked = self.map.write().unwrap();
        match map_locked.insert(locker, MemLocker::new()) {
            Some(_) => Err(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                "Duplicate locker name")),
            None => Ok(()),
        }
    }

    fn delete_locker(&self, locker: &str) -> std::io::Result<()>
    {
        let mut map_locked = self.map.write().unwrap();
        match map_locked.remove(locker) {
            Some(_) => Ok(()),
            None => Err(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "Locker not found")),
        }
    }

    fn add_kv(&self, locker: &str,
              k: String, v: String) -> std::io::Result<()>
    {
        let map_locked = self.map.read().unwrap();
        match map_locked.get(locker) {
            Some(locker) => {
                match locker.add(k, v) {
                    true => Ok(()),
                    false => Err(std::io::Error::new(
                            std::io::ErrorKind::AlreadyExists,
                            "Duplicate key")),
                }
            },
            None => Err(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "Locker not found")),
        }
    }
    fn update_kv(&self, locker: &str,
              k: &str, v: String) -> std::io::Result<()>
    {
        let map_locked = self.map.read().unwrap();
        match map_locked.get(locker) {
            Some(locker) => {
                match locker.update(k, v) {
                    true => Ok(()),
                    false => Err(std::io::Error::new(
                            std::io::ErrorKind::NotFound,
                            std::format!("Key {} not found", &k)))
                }
            },
            None => Err(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "Locker not found")),
        }
    }
    fn remove_kv(&self, locker: &str, k: &str) -> std::io::Result<()>
    {
        let map_locked = self.map.read().unwrap();
        match map_locked.get(locker) {
            Some(locker) => {
                match locker.del(k) {
                    true => Ok(()),
                    false => Err(std::io::Error::new(
                            std::io::ErrorKind::NotFound,
                            "Key not found")),
                }
            },
            None => Err(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "Locker not found")),
        }
    }

    fn get_kv(&self, locker: &str, k: &str) -> std::io::Result<String>
    {
        let map_locked = self.map.read().unwrap();
        match map_locked.get(locker) {
            Some(locker) => {
                match locker.get(k) {
                    Some(value) => Ok(value),
                    None => Err(std::io::Error::new(
                            std::io::ErrorKind::NotFound,
                            "Key not found")),
                }
            },
            None => Err(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "Locker not found")),
        }
    }
}

impl std::fmt::Display for MemVault
{
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result
    {
        let map_locked = self.map.read().unwrap();
        for (k,v) in map_locked.iter() {
            write!(f, "\n---- locker: {k} ----:\n{v}\n",)?;
        }
        Ok(())
    }
}

#[derive(Debug, Default)]
pub struct MemLocker
{
    map: Arc<RwLock<HashMap<String, String>>>
}

impl MemLocker
{
    pub fn new() -> MemLocker
    {
        MemLocker{ map: Arc::new(RwLock::new(HashMap::new())) }
    }
    
    pub fn add(&self, key: String, val: String) -> bool
    {
        let mut map_locked = self.map.write().unwrap();
        map_locked.insert(key, val).is_none()
    }

    pub fn del(&self, key: &str) -> bool
    {
        let mut map_locked = self.map.write().unwrap();
        map_locked.remove(key).is_some()
    }

    pub fn get(&self, key: &str) -> Option<String>
    {
        let map_locked = self.map.read().unwrap();
        map_locked.get(key).map(|val| val.clone())
    }

    pub fn update(&self, k: &str, v: String) -> bool
    {
        let mut map_locked = self.map.write().unwrap();
        match map_locked.get_mut(k) {
            Some(old_val) => {
                *old_val = v;
                true
            },
            None => false,
        }
    }
}

impl std::fmt::Display for MemLocker
{
    fn fmt(&self, f:&mut std::fmt::Formatter) -> std::fmt::Result
    {
        let map_locked = self.map.read().unwrap();
        for (k,v) in map_locked.iter() {
            write!(f, "{k}: {v}")?;
        }
        Ok(())
    }
}

