use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::{thread, time};
use serde::{Deserialize};
use serde_json;
use tonic::{Request, Response, Status,
    transport::{
        // For client
        Certificate, Channel, ClientTlsConfig,
        // For server
        Identity, Server, ServerTlsConfig,
        server::{TcpConnectInfo, TlsConnectInfo}
    }
};
use rocksdb;

use secret_vault::{
    GetConfigRequest, GetConfigResponse,
    CreateLockerRequest, CreateLockerResponse,
    DeleteLockerRequest, DeleteLockerResponse,
    AddSecretRequest, AddSecretResponse,
    RemoveSecretRequest, RemoveSecretResponse,
    GetSecretRequest, GetSecretResponse,
    UpdateSecretRequest, UpdateSecretResponse,
    secret_vault_server::{SecretVault, SecretVaultServer},
    secret_vault_client::SecretVaultClient,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>>
{
    let config = read_and_parse_config()?;
    println!("config: {:?}", config);

    let addr = std::format!("0.0.0.0:{}", &config.serve.port);
    let service_addr = addr.parse().unwrap();
    let service = SecretVaultService::new(&config).unwrap();
    println!("service_addr: {:?}", &service_addr);

    if config.test {
        // test_vault_locker();
        test_client_workflow(&config);
    }

    if config.serve.tls {
        let cert = std::fs::read_to_string(config.security.tls_cert_path)?;
        let key = std::fs::read_to_string(config.security.tls_key_path)?;
        let identity = Identity::from_pem(cert, key);

        Server::builder()
            .tls_config(ServerTlsConfig::new().identity(identity))?
            .add_service(SecretVaultServer::new(service))
            .serve(service_addr)
            .await?;
    } else {
    Server::builder()
        .add_service(SecretVaultServer::new(service))
        .serve(service_addr)
        .await?;
    }
    Ok(())
}

// --- Config ----

#[derive(Deserialize, Debug)]
struct ProtoConfig
{
    rest: bool,
    grpc: bool,
    graphql: bool,
}

#[derive(Deserialize, Debug)]
struct EndpointConfig
{
    port: u32,
    tls: bool,
    cors_origin: Vec<String>,
    cache: bool,
    proto : ProtoConfig,
}

#[derive(Deserialize, Debug)]
pub struct StoreConfig
{
    name: String,
    endpoint: String,
    dbuser: String,
    dbpassword: String,
    dbpath: String,
}

#[derive(Deserialize, Debug)]
struct SecurityConfig
{
    master_password: bool,
    postq_creds: bool,
    locker_name_hash: bool,

    tls_cert_path: String,
    tls_key_path: String,
}

#[derive(Deserialize, Debug)]
struct BackupConfig
{
    interval: u64,
    cloud_endpoint: String, 
}

#[derive(Deserialize, Debug)]
struct ServiceConfig
{
    serve: EndpointConfig,
    store: StoreConfig,
    security: SecurityConfig,
    backup: BackupConfig,
    test: bool
}

fn get_config_str() -> std::io::Result<String>
{
    let mut configfile =
        std::path::PathBuf::from("./config.json");
    match std::fs::read_to_string(&configfile) {
        Ok(config_str) => Ok(config_str),
        Err(e) => Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                std::format!("failed to read config file {}, err: {}",
                             configfile.display(), e))),
    }
}

fn read_and_parse_config() -> std::io::Result<ServiceConfig>
{
    match get_config_str() {
        Ok(config_str) => {
            match serde_json::from_str(&config_str) {
                Ok(config) => Ok(config),
                Err(e) => Err(std::io::Error::new(
                        std::io::ErrorKind::Other, std::format!(
                            "parsing json file failed, err: {}", e)))
            }
        },
        Err(e) => Err(e),
    }
}

// --- Service implementation ---

// [Future] Plugin entry function.
// pub fn build_kvstore() -> std::io::Result<Arc<dyn KVStore + Send + Sync>>;

pub trait KVStore
{
    fn create_locker(&self, locker: String) -> std::io::Result<()>;
    fn delete_locker(&self, locker: &String) -> std::io::Result<()>;

    fn add_kv(&self, locker: &String, k: String, v: String)
        -> std::io::Result<()>;
    fn get_kv(&self, locker: &String, k: &String) -> std::io::Result<String>;
    fn update_kv(&self, locker: &String, k: &String, v: String)
        -> std::io::Result<()>;
    fn remove_kv(&self, locker: &String, k: &String) -> std::io::Result<()>;
}

// --- Service implementation ---

pub struct SecretVaultService
{
    pub lockers: Arc<dyn KVStore + Send + Sync>,
}

impl SecretVaultService
{
    fn new(cfg: &ServiceConfig) -> std::io::Result<SecretVaultService>
    {
        let store = 
            match cfg.store.name.as_str() {
                "rocks" => build_kvstore_rocks(&cfg.store),
                "mem" => build_kvstore_mem(&cfg.store),
                unsupported_store_name => {
                    panic!("Unsupported store name {}",
                           unsupported_store_name);
                }
            };
        match store {
            Ok(store) =>
                Ok(SecretVaultService {
                    lockers: store,
                }),
            Err(e) => Err(e),
        }
    }
}

#[tonic::async_trait]
impl SecretVault for SecretVaultService
{
    async fn get_config(&self, _req: Request<GetConfigRequest>) ->
        Result<Response<GetConfigResponse>, Status>
    {
        match get_config_str() {
            // Insertion succeeded
            Ok(config_str) =>  Ok(Response::new(GetConfigResponse{
                config: config_str,
            })),
            // Found a duplicate, failed
            Err(e) => Err(Status::new(tonic::Code::Unknown,
                    std::format!("Err: {}", e))),
        }
    }
    async fn create_locker(&self, req: Request<CreateLockerRequest>) ->
        Result<Response<CreateLockerResponse>, Status>
    {
        let req = req.into_inner();
        match self.lockers.create_locker(req.locker_id) {
            // Insertion succeeded
            Ok(_) =>  Ok(Response::new(CreateLockerResponse{})),
            // Found a duplicate, failed
            Err(e) => Err(Status::new(tonic::Code::AlreadyExists,
                    std::format!("Err: {}", e))),
        }
    }

    async fn delete_locker(&self, req: Request<DeleteLockerRequest>)
        -> Result<Response<DeleteLockerResponse>, Status>
    {
        let req = req.into_inner();
        match self.lockers.delete_locker(&req.locker_id) {
            Ok(_) =>  Ok(Response::new(DeleteLockerResponse{})),
            Err(e) => Err(Status::new(tonic::Code::NotFound,
                    std::format!("Err: {}", e))),
        }
    }

    async fn add_secret(&self, req: Request<AddSecretRequest>)
        -> Result<Response<AddSecretResponse>, Status>
    {
        let req = req.into_inner();
        match self.lockers.add_kv(
            &req.locker_id, req.secret_key, req.secret_blob) {
            Ok(_) => Ok(Response::new(AddSecretResponse{})),
            // TODO: Sending this error response might inform
            // a malicious actor of presence/absence of a secret.
            Err(e) => Err(Status::new(tonic::Code::AlreadyExists,
                    std::format!("Err: {}", e))),
        }
    }

    async fn remove_secret(&self, req: Request<RemoveSecretRequest>)
        -> Result<Response<RemoveSecretResponse>, Status>
    {
        let req = req.into_inner();
        match self.lockers.remove_kv(&req.locker_id, &req.secret_key) {
            Ok(_) => Ok(Response::new(RemoveSecretResponse{})),
            // TODO: Sending this error response might inform
            // a malicious actor of presence/absence of a secret.
            Err(e)=> Err(Status::new(tonic::Code::AlreadyExists,
                    std::format!("Err: {}", e))),
        }
    }

    async fn get_secret(&self, req: Request<GetSecretRequest>)
        -> Result<Response<GetSecretResponse>, Status>
    {
        let req = req.into_inner();
        match self.lockers.get_kv(&req.locker_id, &req.secret_key) {
            Ok(blob) => Ok(Response::new(GetSecretResponse{
                secret_blob: blob,
            })),
            Err(e) => Err(Status::new(tonic::Code::NotFound,
                    std::format!("Err: {}", e))),
        }
    }

    async fn update_secret(&self, req: Request<UpdateSecretRequest>)
        -> Result<Response<UpdateSecretResponse>, Status>
    {
        let req = req.into_inner();
        match self.lockers.update_kv(
            &req.locker_id, &req.secret_key, req.secret_blob) {
            Ok(_) => Ok(Response::new(UpdateSecretResponse{})),
            // TODO: Sending this error response might inform
            // a malicious actor of presence/absence of a secret.
            Err(e) => Err(Status::new(tonic::Code::InvalidArgument,
                    std::format!("Err: {}", e))),
        }
    }
}

pub mod secret_vault {
    tonic::include_proto!("secret_vault");
}

// -- Internal data-structures

pub fn build_kvstore_mem(_cfg: &StoreConfig)
    -> std::io::Result<Arc<dyn KVStore + Send + Sync>>
{
    let memvault = MemVault::new();
    Ok(Arc::new(memvault))
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

    // TODO: Implement as Debug Display trait.
    pub fn show(&self)
    {
        let map_locked = self.map.read().unwrap();
        for (k,v) in map_locked.iter() {
            println!("\n---- locker: {k} ----:\n");
            v.show();
        }
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

    fn delete_locker(&self, locker: &String) -> std::io::Result<()>
    {
        let mut map_locked = self.map.write().unwrap();
        match map_locked.remove(locker) {
            Some(_) => Ok(()),
            None => Err(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "Locker not found")),
        }
    }

    fn add_kv(&self, locker: &String,
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
    fn update_kv(&self, locker: &String,
              k: &String, v: String) -> std::io::Result<()>
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
    fn remove_kv(&self, locker: &String, k: &String) -> std::io::Result<()>
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

    fn get_kv(&self, locker: &String, k: &String) -> std::io::Result<String>
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
        match map_locked.insert(key, val) {
            Some(_) => false,
            None => true,
        }
    }

    pub fn del(&self, key: &String) -> bool
    {
        let mut map_locked = self.map.write().unwrap();
        match map_locked.remove(key) {
            Some(_) => true,
            None => false,
        }
    }

    pub fn get(&self, key: &String) -> Option<String>
    {
        let map_locked = self.map.read().unwrap();
        match map_locked.get(key) {
            Some(val) => Some(val.clone()),
            None => None
        }
    }

    pub fn update(&self, k: &String, v: String) -> bool
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

    pub fn clone(&self) -> MemLocker
    {
        MemLocker{ map: self.map.clone() }
    }

    // TODO: Implement as Debug Display trait.
    pub fn show(&self)
    {
        let map_locked = self.map.read().unwrap();
        for (k,v) in map_locked.iter() {
            println!("{k}: {v}");
        }
    }
}

// --- RocksDb based KVStore

pub fn build_kvstore_rocks(cfg: &StoreConfig)
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
            rocksdb::DB::list_cf(&options, &dbpath)
            .unwrap_or(vec![]);
        RocksDbVault {
            db: Arc::new(rocksdb::DB::open_cf(
                        &options, &dbpath, cfs).unwrap())
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
    
    fn delete_locker(&self, locker: &String) -> std::io::Result<()>
    {
        match self.db.drop_cf(&locker) {
            Ok(()) => Ok(()),
            Err(e) => Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    std::format!("rocks-db column-family drop {} failed; {}",
                                 locker, e))),
        }
    }

    

    fn add_kv(&self, locker: &String, k: String, v: String)
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
    fn update_kv(&self, locker: &String, k: &String, v: String)
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

    fn remove_kv(&self, locker: &String, k: &String)
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
    fn get_kv(&self, locker: &String, k: &String) -> std::io::Result<String>
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
                                    std::format!(
                                        "key lookup returned null")))
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

// --- Test cases ---
// TODO: Formalize these as test case.

// Test Vault implementation
fn _test_vault_locker()
{
    let vault = MemVault::new();
    let vault_r = vault.clone();
    let thd1 = thread::spawn(move || {
        for i in 1..9 {
            thread::sleep(time::Duration::from_secs(3));

            println!("Read attempt {i}");
            vault_r.show();
        }
        println!("Reader thread done");
    });

    let thd2 = thread::spawn(move || {
        let lockername = String::from("l1");
        vault.create_locker(lockername.clone()).unwrap();
        for i in 1..5 {
            thread::sleep(time::Duration::from_secs(2));

            let k = std::format!("key_{i}");
            let v = std::format!("value_{i}");
            vault.add_kv(&lockername, k, v).unwrap();
        }
        for i in 1..5 {
            thread::sleep(time::Duration::from_secs(2));

            let k = std::format!("key_{i}");
            vault.remove_kv(&lockername, &k).unwrap();
        }
        println!("Writer thread done");
    });

    thd1.join().unwrap();
    thd2.join().unwrap();
    println!("Test complete");
}

// Test grpc service functionality
fn test_client_workflow(cfg: &ServiceConfig)
{
    let port: u32 = cfg.serve.port;
    let is_tls = cfg.serve.tls;
    let cert = std::fs::read_to_string("./tls/ca.pem").unwrap();
    let ca = Certificate::from_pem(cert);
    let tls = ClientTlsConfig::new()
        .ca_certificate(ca)
        .domain_name("example.com");

    // Reader thread
    let tls_r = tls.clone();
    let _thd1 = tokio::spawn(async move {
            let lockername = String::from("l1");
            let mut expected_key_value_pairs = HashMap::new();
            expected_key_value_pairs.insert(
                String::from("key_1"), String::from("value_1"));
            expected_key_value_pairs.insert(
                String::from("key_2"), String::from("value_2"));
            expected_key_value_pairs.insert(
                String::from("key_3"), String::from("value_3"));
            expected_key_value_pairs.insert(
                String::from("key_4"), String::from("value_4"));
            expected_key_value_pairs.insert(
                String::from("key_5"), String::from("value_5"));

            println!("Waiting to connect reader client");
            thread::sleep(time::Duration::from_secs(5));

            let channel = {
                if (is_tls) {
                    let addr = std::format!("https://0.0.0.0:{}", port);
                    Channel::from_shared(addr).unwrap()
                        .tls_config(tls_r).unwrap()
                        .connect()
                        .await
                        .unwrap()
                } else {
                    let addr = std::format!("http://0.0.0.0:{}", port);
                    Channel::from_shared(addr).unwrap()
                        .connect()
                        .await
                        .unwrap()
                }
            };
            let mut reader_client = SecretVaultClient::new(channel);
            for i in 1..4 {
                println!("Read attempt {i}");
                for (k,v) in expected_key_value_pairs.iter() {
                    let req = Request::new(GetSecretRequest {
                        locker_id: lockername.clone(),
                        secret_key: k.to_string(),
                    });
                    match reader_client.get_secret(req).await {
                        Ok(response) => {
                            let response = response.into_inner();
                            if &response.secret_blob != v {
                                println!("Key {}, retrieved value: {} \
                                    does not match expected value {}",
                                    k, response.secret_blob, v);
                            } else {
                                println!("Key {}, retrieved value: {} \
                                    matches expected value {}", k,
                                    response.secret_blob, v);
                            }
                        },
                        Err(e) => {
                            println!("Failed to retrieve secret {}, err: {}",
                                     k, e);
                        }
                    }
                }
                thread::sleep(time::Duration::from_secs(3));
            }
            println!("Reader thread done");
    });

    // Writer thread
    let _thd2 = tokio::spawn(async move {
            println!("Waiting to connect writer client");
            thread::sleep(time::Duration::from_secs(5));

            let channel = {
                if (is_tls) {
                    let addr = std::format!("https://0.0.0.0:{}", port);
                    Channel::from_shared(addr).unwrap()
                        .tls_config(tls).unwrap()
                        .connect()
                        .await
                        .unwrap()
                } else {
                    let addr = std::format!("http://0.0.0.0:{}", port);
                    Channel::from_shared(addr).unwrap()
                        .connect()
                        .await
                        .unwrap()
                }
            };
            let mut writer_client = SecretVaultClient::new(channel);

            thread::sleep(time::Duration::from_secs(2));

            let lockername = String::from("l1");
            let create_req = Request::new(CreateLockerRequest {
                locker_id: lockername.clone(),
            });
            match writer_client.create_locker(create_req).await {
                Ok(_) => { println!("Create locker"); },
                Err(e) => { println!("Failed to create locker\n{}", e); },
            }

            // Create k,v pairs 
            for i in 1..5 {
                let req = Request::new(AddSecretRequest {
                    locker_id: lockername.clone(),
                    secret_key: std::format!("key_{}", i),
                    secret_blob: std::format!("value_{}", i),
                });
                match writer_client.add_secret(req).await {
                    Ok(_) => { println!("Created secret (key_{})", i); },
                    Err(e) => {
                        println!("Failed to create secret (key_{}), {}", i, e);
                    },
                }
            }

            // Update k,v pairs
            for i in 1..5 {
                let req = Request::new(UpdateSecretRequest{
                    locker_id: lockername.clone(),
                    secret_key: std::format!("key_{}", i),
                    secret_blob: std::format!("value_{}", i+10),
                });
                match writer_client.update_secret(req).await {
                    Ok(_) => { println!("Updated secret (key_{})", i); },
                    Err(e) => {
                        println!("Failed to update secret (key_{}), {}", i, e);
                    },
                }
            }

            thread::sleep(time::Duration::from_secs(3));
            let del_req = Request::new(DeleteLockerRequest {
                locker_id: lockername.clone(),
            });
            match writer_client.delete_locker(del_req).await {
                Ok(_) => { println!("Deleted locker"); },
                Err(e) => { println!("Failed to delete locker, e: {}", e); },
            }
            println!("Writer thread done");
    });

    println!("Spawned test clients");
}

