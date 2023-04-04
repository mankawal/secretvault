use std::collections::HashMap;
use std::{thread, time, sync::Arc};
use tonic::{Request, Response, Status,
    transport::{
        // For client
        Certificate, Channel, ClientTlsConfig,
        // For server
        Identity, Server, ServerTlsConfig
    }
};

mod prelude;
mod config;
mod store_factory;
mod memvault;
mod rocksvault;
mod svc_rest;

use crate::prelude::KVStore;
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

pub mod secret_vault {
    tonic::include_proto!("secret_vault");
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>>
{
    let config = config::read_and_parse_config()?;
    println!("config: {:?}", config);

    if config.test {
        // test_vault_locker();
        test_client_workflow(&config);
    }

    let mut svc_handles = Vec::new();
    let kvstore = store_factory::create_store(&config).unwrap();
    let kvstore_grpc = kvstore.clone();
    if config.serve.proto.grpc != 0
    {
        let addr = std::format!("0.0.0.0:{}", &config.serve.proto.grpc);
        let service_addr = addr.parse()?;
        let service = SecretVaultService::new(&config, kvstore_grpc)?;
        println!("service_addr: {:?}", &service_addr);

        if config.serve.tls {
            let cert = std::fs::read_to_string(config.security.tls_cert_path)?;
            let key = std::fs::read_to_string(config.security.tls_key_path)?;
            let identity = Identity::from_pem(cert, key);

            svc_handles.push(Server::builder()
                .tls_config(ServerTlsConfig::new().identity(identity))?
                .add_service(SecretVaultServer::new(service))
                .serve(service_addr));
        } else {
            svc_handles.push(Server::builder()
                .add_service(SecretVaultServer::new(service))
                .serve(service_addr));
        }
    }
    if config.serve.proto.rest != 0
    {
        let _thd = tokio::spawn(async move {
            svc_rest::server(kvstore, config.serve.proto.rest,
                             config.serve.tls).await;
        });
    }

    for svc in svc_handles {
        svc.await?;
    }
    Ok(())
}

// --- GRPC service implementation ---

struct SecretVaultService
{
    pub lockers: Arc<dyn KVStore + Send + Sync>,
}

impl SecretVaultService
{
    pub fn new(_cfg: &config::ServiceConfig,
               store: Arc<dyn KVStore + Send + Sync>)
        -> std::io::Result<SecretVaultService>
    {
        Ok(SecretVaultService {
            lockers: store,
        })
    }
}

#[tonic::async_trait]
impl SecretVault for SecretVaultService
{
    async fn get_config(&self, _req: Request<GetConfigRequest>) ->
        Result<Response<GetConfigResponse>, Status>
    {
        match config::get_config_str() {
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


// --- Test cases ---
// Test Vault implementation
fn _test_vault_locker()
{
    let vault = memvault::MemVault::new();
    let vault_r = vault.clone();
    let thd1 = thread::spawn(move || {
        for i in 1..9 {
            thread::sleep(time::Duration::from_secs(3));

            println!("Read attempt {i}\n{vault_r}");
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
fn test_client_workflow(cfg: &config::ServiceConfig)
{
    let port = cfg.serve.proto.grpc;
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
                if is_tls {
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
                if is_tls {
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

