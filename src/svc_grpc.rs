use std::sync::Arc;
use crate::config;
use crate::prelude::KVStore;

use tonic::{Request, Response, Status};
use crate::secret_vault::{VaultContext,
    GetConfigRequest, GetConfigResponse,
    CreateLockerRequest, CreateLockerResponse,
    DeleteLockerRequest, DeleteLockerResponse,
    AddSecretRequest, AddSecretResponse,
    RemoveSecretRequest, RemoveSecretResponse,
    GetSecretRequest, GetSecretResponse,
    UpdateSecretRequest, UpdateSecretResponse,
    secret_vault_server::{SecretVault},
};
use crate::config::ServiceConfig;

pub struct SecretVaultService
{
    pub lockers: Arc<dyn KVStore + Send + Sync>,
}

impl SecretVaultService
{
    pub fn new(_cfg: &ServiceConfig,
               store: Arc<dyn KVStore + Send + Sync>)
        -> std::io::Result<SecretVaultService>
    {
        Ok(SecretVaultService {
            lockers: store,
        })
    }

    pub fn check_context(&self, ctx: &VaultContext) ->
        Result<(), Status>
    {
        // Check if the corresponding vault exists.
        // TODO: Check if user's is authorized for the operation.
        // For now, this is a simple check on whether the incoming
        // user_context matches the user's attribute stored in the
        // vault's metadata locker.
        match self.lockers.get_kv(&ctx.vault_id, &ctx.user_name) {
            // Insertion succeeded
            Ok(user_attrib) =>  {
                if user_attrib.eq(&ctx.user_context) {
                    Ok(())
                } else {
                    Err(Status::new(tonic::Code::Unauthenticated,
                                    "Stale/incorrect user context"))
                }
            },
            // Found a duplicate, failed
            Err(_) =>
                Err(Status::new(tonic::Code::NotFound, std::format!(
                            "Vault {} not found", &ctx.vault_id)))
        }
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
        if let Err(e) = self.check_context(&req.context) {
            return Err(e);
        }
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
        if let Err(e) = self.check_context(&req.context) {
            return Err(e);
        }
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
        if let Err(e) = self.check_context(&req.context) {
            return Err(e);
        }
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
        if let Err(e) = self.check_context(&req.context) {
            return Err(e);
        }
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
        if let Err(e) = self.check_context(&req.context) {
            return Err(e);
        }
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
        if let Err(e) = self.check_context(&req.context) {
            return Err(e);
        }
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
