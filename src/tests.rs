#[allow(dead_code)]
use std::{thread, time, collections::HashMap};
use tonic::{Request,
    transport::{Certificate, Channel, ClientTlsConfig}
};

use crate::config;
use crate::prelude::KVStore;
use crate::memvault::MemVaultMap;
use crate::secret_vault::{
    CreateVaultRequest, DeleteVaultRequest,
    AddMetadataRequest, UpdateMetadataRequest, RemoveMetadataRequest,
    secret_vault_admin_client::SecretVaultAdminClient,
};
use crate::secret_vault::{
    CommonContext,
    CreateLockerRequest, DeleteLockerRequest, ReadLockerRequest,
    secret_vault_client::SecretVaultClient,
};

// Test memvault implementation
pub fn test_vault_locker()
{
    let vault = MemVaultMap::new();
    let vault_r = vault.clone();
    let thd1 = thread::spawn(move || {
        for attempt in 1..14 {
            let vaultname = String::from("v1");
            thread::sleep(time::Duration::from_secs(1));
            println!("Read attempt {attempt}\n{vault_r}");
        }
        println!("Reader thread done");
    });

    let thd2 = thread::spawn(move || {
        let vaultname = String::from("v1");
        vault.create_db(vaultname.clone()).unwrap();
        for i in 1..5 {
            thread::sleep(time::Duration::from_secs(1));

            let k = std::format!("key_{i}");
            let v = std::format!("value_{i}");
            vault.add_kv(&vaultname, k, v).unwrap();
        }
        for i in 1..5 {
            thread::sleep(time::Duration::from_secs(1));

            let k = std::format!("key_{i}");
            vault.initiate_kv_removal(&vaultname, &k).unwrap();
        }
        for i in 1..3 {
            thread::sleep(time::Duration::from_secs(1));

            let k = std::format!("key_{i}");
            vault.cancel_kv_removal(&vaultname, &k).unwrap();
        }
        for i in 3..4 {
            thread::sleep(time::Duration::from_secs(1));

            let k = std::format!("key_{i}");
            vault.complete_kv_removal(&vaultname, &k).unwrap();
        }
        for i in 4..5 {
            thread::sleep(time::Duration::from_secs(1));

            let k = std::format!("key_{i}");
            vault.cancel_kv_removal(&vaultname, &k).unwrap();
        }
        println!("Writer thread done");
    });

    thd1.join().unwrap();
    thd2.join().unwrap();
    println!("Test complete");
}

// Test grpc service functionality
pub async fn test_client_workflow(cfg: &config::ServiceConfig)
{
    let admin_port = cfg.serve_admin.proto.grpc;
    let admin_is_tls = cfg.serve_admin.tls;
    let admin_cert = std::fs::read_to_string("./tls/admin/ca.pem").unwrap();
    let admin_ca = Certificate::from_pem(admin_cert);
    let admin_tls = ClientTlsConfig::new()
        .ca_certificate(admin_ca)
        .domain_name("example.com");

    let thd_vault = tokio::spawn(async move {
        let channel = {
            if admin_is_tls {
                let addr = std::format!("https://0.0.0.0:{}", admin_port);
                Channel::from_shared(addr).unwrap()
                    .tls_config(admin_tls).unwrap()
                    .connect()
                    .await
                    .unwrap()
            } else {
                let addr = std::format!("http://0.0.0.0:{}", admin_port);
                Channel::from_shared(addr).unwrap()
                    .connect()
                    .await
                    .unwrap()
            }
        };
        let mut admin_client = SecretVaultAdminClient::new(channel);

        thread::sleep(time::Duration::from_secs(1));

        let vault = String::from("v1");
        let username = String::from("u1");
        let user_attrib = String::from("u1_attr_1");

        thread::sleep(time::Duration::from_secs(2));
        let create_req = Request::new(CreateVaultRequest {
            vault_id: vault.clone()
        });
        if let Err(e) =  admin_client.create_vault(create_req).await {
            println!("Failed to create vault: {}, err: {}", &vault, e);
        } else {
            println!("Created vault: {}", &vault);
        }

        thread::sleep(time::Duration::from_secs(1));
        let add_user_req = Request::new(AddMetadataRequest{
            vault_id: vault.clone(),
            name: username.clone(),
            value: user_attrib.clone(),
        });
        if let Err(e) =  admin_client.add_metadata(add_user_req).await {
            println!("Failed to create user {} in vault {}, err: {}",
                     &username, &vault, e);
        } else {
            println!("Created user {} in vault {}", &username, &vault);
        }

        thread::sleep(time::Duration::from_secs(7));
        let update_user_req = Request::new(UpdateMetadataRequest{
            vault_id: vault.clone(),
            name: username.clone(),
            value: String::from("u1_attr_2"),
        });
        if let Err(e) =  admin_client.update_metadata(update_user_req).await {
            println!("Failed to update user {} in vault {}, err: {}",
                     &username, &vault, e);
        }

        thread::sleep(time::Duration::from_secs(3));
        let remove_user_req = Request::new(RemoveMetadataRequest{
            vault_id: vault.clone(),
            name: username.clone(),
        });
        if let Err(e) =  admin_client.remove_metadata(remove_user_req).await {
            println!("Failed to delete user {} in vault {}, err: {}",
                     &username, &vault, e);
        }

        thread::sleep(time::Duration::from_secs(3));
        let delete_vault_req = Request::new(DeleteVaultRequest{
            vault_id: vault.clone()
        });
        if let Err(e) = admin_client.delete_vault(delete_vault_req).await {
            println!("Failed to delete vault {}, err: {}", &vault, e);
        }
    });


    let port = cfg.serve.proto.grpc;
    let is_tls = cfg.serve.tls;
    let cert = std::fs::read_to_string("./tls/ca.pem").unwrap();
    let ca = Certificate::from_pem(cert);
    let tls = ClientTlsConfig::new()
        .ca_certificate(ca)
        .domain_name("example.com");

    // Reader thread
    let tls_r = tls.clone();
    let thd1 = tokio::spawn(async move {
        let vault = String::from("v1");
        let username = String::from("u1");
        let user_ctx = String::from("u1_attr_1");
        let mut expected_key_value_pairs = HashMap::new();
        for i in 1..6 {
            expected_key_value_pairs.insert(
                std::format!("key_{i}"), std::format!("value_{i}"));
        }

        println!("Waiting to connect reader client");
        thread::sleep(time::Duration::from_secs(1));

        let channel = {
            if is_tls {
                let addr = std::format!("https://0.0.0.0:{}", port);
                Channel::from_shared(addr).unwrap()
                    .tls_config(tls_r).unwrap()
                    .connect().await.unwrap()
            } else {
                let addr = std::format!("http://0.0.0.0:{}", port);
                Channel::from_shared(addr).unwrap()
                    .connect().await.unwrap()
            }
        };
        let mut reader_client = SecretVaultClient::new(channel);
        for i in 1..8 {
            println!("Read attempt {i}");
            for (k,v) in expected_key_value_pairs.iter() {
                let req = Request::new(ReadLockerRequest {
                    context: CommonContext {
                        vault_id: vault.clone(),
                        user_name: username.clone(),
                        user_context: user_ctx.clone(),
                    },
                    locker_id: k.clone(),
                });
                match reader_client.read_locker(req).await {
                    Ok(response) => {
                        let response = response.into_inner();
                        if &response.locker_contents != v {
                            println!("Key {}, retrieved value: {} \
                                    does not match expected value {}",
                                    k, response.locker_contents, v);
                        } else {
                            println!("Key {}, retrieved value: {} \
                                    matches expected value {}", k,
                                    response.locker_contents, v);
                        }
                    },
                    Err(e) => {
                        println!("Failed to retrieve locker {}, err: {}",
                                 k, e);
                    }
                }
            }
            thread::sleep(time::Duration::from_secs(2));
        }
        println!("Reader thread done");
    });

    // Writer thread
    let thd2 = tokio::spawn(async move {
        println!("Waiting to connect writer client");
        thread::sleep(time::Duration::from_secs(2));

        let channel = {
            if is_tls {
                let addr = std::format!("https://0.0.0.0:{}", port);
                Channel::from_shared(addr).unwrap()
                    .tls_config(tls).unwrap()
                    .connect().await.unwrap()
            } else {
                let addr = std::format!("http://0.0.0.0:{}", port);
                Channel::from_shared(addr).unwrap()
                    .connect().await.unwrap()
            }
        };
        let mut writer_client = SecretVaultClient::new(channel);

        thread::sleep(time::Duration::from_secs(2));

        let vault = String::from("v1");
        let username = String::from("u1");
        let user_ctx = String::from("u1_attr_1");

        // Create lockers
        for i in 1..6 {
            let req = Request::new(CreateLockerRequest {
                context: CommonContext {
                    vault_id: vault.clone(),
                    user_name: username.clone(),
                    user_context: user_ctx.clone(),
                },
                locker_id: std::format!("key_{}", i),
                locker_contents: std::format!("value_{}", i),
            });
            match writer_client.create_locker(req).await {
                Ok(_) => { println!("Created locker (key_{})", i); },
                Err(e) => {
                    println!("Failed to create locker (key_{}), {}", i, e);
                },
            }
            thread::sleep(time::Duration::from_secs(1));
        }
        // Remove lockers
        thread::sleep(time::Duration::from_secs(2));
        for i in 1..6 {
            let req = Request::new(DeleteLockerRequest {
                context: CommonContext {
                    vault_id: vault.clone(),
                    user_name: username.clone(),
                    user_context: user_ctx.clone(),
                },
                locker_id: std::format!("key_{}", i),
            });
            match writer_client.delete_locker(req).await {
                Ok(_) => { println!("Removed locker (key_{})", i); },
                Err(e) => {
                    println!("Failed to remove locker (key_{}), {}", i, e);
                },
            }
        }
        println!("Writer thread done");
    });

    let _ = thd_vault.await;
    let _ = thd2.await;
    let _ = thd1.await;

    println!("Spawned test clients");
}
