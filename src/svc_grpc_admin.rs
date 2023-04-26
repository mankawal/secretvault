use std::sync::Arc;
use crate::config;
use crate::prelude::KVStore;

use tonic::{Request, Response, Status};
use crate::secret_vault::{
    GetAdminConfigRequest, GetAdminConfigResponse,
    CreateVaultRequest, CreateVaultResponse,
    DeleteVaultRequest, DeleteVaultResponse,
    AddMetadataRequest, AddMetadataResponse,
    RemoveMetadataRequest, RemoveMetadataResponse,
    GetMetadataRequest, GetMetadataResponse,
    UpdateMetadataRequest, UpdateMetadataResponse,
    secret_vault_admin_server::{SecretVaultAdmin},
};
use crate::config::ServiceConfig;

pub struct SecretVaultAdminService
{
    pub vaults: Arc<dyn KVStore + Send + Sync>,
}

impl SecretVaultAdminService
{
    pub fn new(_cfg: &ServiceConfig,
               store: Arc<dyn KVStore + Send + Sync>)
        -> std::io::Result<SecretVaultAdminService>
    {
        Ok(SecretVaultAdminService {
            vaults: store,
        })
    }
}

#[tonic::async_trait]
impl SecretVaultAdmin for SecretVaultAdminService
{
    async fn get_admin_config(&self, _req: Request<GetAdminConfigRequest>) ->
        Result<Response<GetAdminConfigResponse>, Status>
    {
        match config::get_config_str() {
            // Insertion succeeded
            Ok(config_str) =>  Ok(Response::new(GetAdminConfigResponse{
                config: config_str,
            })),
            // Found a duplicate, failed
            Err(e) => Err(Status::new(tonic::Code::Unknown,
                    std::format!("Err: {}", e))),
        }
    }
    async fn create_vault(&self, req: Request<CreateVaultRequest>) ->
        Result<Response<CreateVaultResponse>, Status>
    {
        let req = req.into_inner();
        match self.vaults.create_db(req.vault_id) {
            // Insertion succeeded
            Ok(_) =>  Ok(Response::new(CreateVaultResponse{})),
            // Found a duplicate, failed
            Err(e) => Err(Status::new(tonic::Code::AlreadyExists,
                    std::format!("Err: {}", e))),
        }
    }

    async fn delete_vault(&self, req: Request<DeleteVaultRequest>)
        -> Result<Response<DeleteVaultResponse>, Status>
    {
        let req = req.into_inner();
        match self.vaults.delete_db(&req.vault_id) {
            Ok(_) =>  Ok(Response::new(DeleteVaultResponse{})),
            Err(e) => Err(Status::new(tonic::Code::NotFound,
                    std::format!("Err: {}", e))),
        }
    }

    async fn add_metadata(&self, req: Request<AddMetadataRequest>)
        -> Result<Response<AddMetadataResponse>, Status>
    {
        let req = req.into_inner();
        match self.vaults.add_kv(
            &req.vault_id, req.name, req.value) {
            Ok(_) => Ok(Response::new(AddMetadataResponse{})),
            // TODO: Sending this error response might inform
            // a malicious actor of presence/absence of a secret.
            Err(e) => Err(Status::new(tonic::Code::AlreadyExists,
                    std::format!("Err: {}", e))),
        }
    }

    async fn remove_metadata(&self, req: Request<RemoveMetadataRequest>)
        -> Result<Response<RemoveMetadataResponse>, Status>
    {
        let req = req.into_inner();
        match self.vaults.remove_kv(&req.vault_id, &req.name) {
            Ok(_) => Ok(Response::new(RemoveMetadataResponse{})),
            // TODO: Sending this error response might inform
            // a malicious actor of presence/absence of a secret.
            Err(e)=> Err(Status::new(tonic::Code::AlreadyExists,
                    std::format!("Err: {}", e))),
        }
    }

    async fn get_metadata(&self, req: Request<GetMetadataRequest>)
        -> Result<Response<GetMetadataResponse>, Status>
    {
        let req = req.into_inner();
        match self.vaults.get_kv(&req.vault_id, &req.name) {
            Ok(blob) => Ok(Response::new(GetMetadataResponse{
                value: blob,
            })),
            Err(e) => Err(Status::new(tonic::Code::NotFound,
                    std::format!("Err: {}", e))),
        }
    }

    async fn update_metadata(&self, req: Request<UpdateMetadataRequest>)
        -> Result<Response<UpdateMetadataResponse>, Status>
    {
        let req = req.into_inner();
        match self.vaults.update_kv(
            &req.vault_id, &req.name, req.value) {
            Ok(_) => Ok(Response::new(UpdateMetadataResponse{})),
            // TODO: Sending this error response might inform
            // a malicious actor of presence/absence of a secret.
            Err(e) => Err(Status::new(tonic::Code::InvalidArgument,
                    std::format!("Err: {}", e))),
        }
    }
}
