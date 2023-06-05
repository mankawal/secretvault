use std::{env,sync::Arc};
use tonic::transport::{Identity, Server, ServerTlsConfig};

mod auth_token;
mod prelude;
mod config;
mod store_factory;
mod memvault;
mod rocksvault;
mod svc_grpc;
mod svc_grpc_admin;
mod svc_rest;
mod svc_rest_admin;
mod tests;

use crate::secret_vault::secret_vault_server::SecretVaultServer;
use crate::secret_vault::secret_vault_admin_server::SecretVaultAdminServer;
use crate::prelude::KVStore;

pub mod secret_vault {
    tonic::include_proto!("secret_vault");
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>>
{
    let config = config::read_and_parse_config()?;

    let args:Vec<_> = env::args().collect();
    if args.len() > 1 {
        tests::test_vault_locker();
        tests::test_client_workflow(&config).await;
        return Ok(());
    }

    auth_token::init().unwrap();

    let mut svc_thds = Vec::new();
    let kvstore = store_factory::create_store(&config).unwrap();

    if config.serve_admin.proto.grpc != 0
    {
        let kvstore_admin_grpc = kvstore.clone();
        svc_thds.push(tokio::spawn(async move {
            run_vault_admin_svc(kvstore_admin_grpc).await;
        }));
    }
    if config.serve.proto.grpc != 0
    {
        let kvstore_grpc = kvstore.clone();
        svc_thds.push(tokio::spawn(async move {
            run_vault_svc(kvstore_grpc).await;
        }));
    }

    if config.serve_admin.proto.rest != 0
    {
        let kvstore_admin_rest = kvstore.clone();
        svc_thds.push(tokio::spawn(async move {
            svc_rest_admin::server(kvstore_admin_rest,
                                   config.serve_admin.proto.rest,
                                   config.serve_admin.tls).await;
        }));
    }
    if config.serve.proto.rest != 0
    {
        svc_thds.push(tokio::spawn(async move {
            svc_rest::server(kvstore, config.serve.proto.rest,
                             config.serve.tls).await;
        }));
    }

    for thd in svc_thds {
        thd.await?;
    }

    Ok(())
}

async fn run_vault_svc(kvstore: Arc<dyn KVStore + Send + Sync>)
{
    let config = config::read_and_parse_config().unwrap();
    let addr = std::format!("0.0.0.0:{}", config.serve.proto.grpc);
    let service_addr = addr.parse().unwrap();
    let service = svc_grpc::SecretVaultService::new(&config, kvstore).unwrap();
    println!("service_addr: {:?}", &service_addr);

    if config.serve.tls {
        let cert = std::fs::read_to_string(config.serve.tls_cert_path).unwrap();
        let key = std::fs::read_to_string(config.serve.tls_key_path).unwrap();
        let identity = Identity::from_pem(cert, key);

        Server::builder()
            .tls_config(ServerTlsConfig::new().identity(identity)).unwrap()
            .add_service(SecretVaultServer::new(service))
            .serve(service_addr)
            .await.unwrap();
    } else {
        Server::builder()
            /*
            .add_service(SecretVaultServer::with_interceptor(
                    service, svc_grpc::SecretVaultService::intercept_for_auth))
            */
            .add_service(SecretVaultServer::new(service))
            .serve(service_addr)
            .await.unwrap();
    }
}

async fn run_vault_admin_svc(kvstore: Arc<dyn KVStore + Send + Sync>)
{
    let config = config::read_and_parse_config().unwrap();
    let addr = std::format!("0.0.0.0:{}", config.serve_admin.proto.grpc);
    let service_addr = addr.parse().unwrap();
    let service = svc_grpc_admin::SecretVaultAdminService::new(&config, kvstore).unwrap();
    println!("service_addr: {:?}", &service_addr);

    if config.serve.tls {
        let cert = std::fs::read_to_string(config.serve_admin.tls_cert_path).unwrap();
        let key = std::fs::read_to_string(config.serve_admin.tls_key_path).unwrap();
        let identity = Identity::from_pem(cert, key);

        Server::builder()
            .tls_config(ServerTlsConfig::new().identity(identity)).unwrap()
            .add_service(SecretVaultAdminServer::new(service))
            .serve(service_addr)
            .await.unwrap();
    } else {
        Server::builder()
            .add_service(SecretVaultAdminServer::new(service))
            .serve(service_addr)
            .await.unwrap();
    }
}
