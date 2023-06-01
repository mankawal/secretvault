use std::sync::Arc;
use crate::config;
use crate::prelude::KVStore;

use tonic::{Request, Response, Status};
use crate::secret_vault::{CommonContext,
    GetConfigRequest, GetConfigResponse,
    CreateLockerRequest, CreateLockerResponse,
    ReadLockerRequest, ReadLockerResponse,
    UpdateLockerRequest, UpdateLockerResponse,
    InitiateLockerDeletionRequest, InitiateLockerDeletionResponse,
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

    pub fn check_context(&self, ctx: &CommonContext) ->
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
            Err(_) =>
                Err(Status::new(tonic::Code::NotFound, std::format!(
                            "Vault {} not found", &ctx.vault_id)))
        }
    }

    pub fn intercept_for_auth(req: Request<()>)
        -> Result<Request<()>, Status>
    {
            println!("Intercepted request: {:?}", req);
            Ok(req)
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
        let Some(ctx) = req.context else {
            return Err(Status::new(tonic::Code::InvalidArgument,
                        "Failed to extract vault context from request"));
        };
        if let Err(e) = self.check_context(&ctx) {
            return Err(e);
        }
        match self.lockers.add_kv(&ctx.vault_id,
                                  req.locker_id, req.locker_contents) {
            Ok(_) =>  Ok(Response::new(CreateLockerResponse{})),
            Err(e) => Err(Status::new(tonic::Code::InvalidArgument,
                    std::format!("Err: {}", e))),
        }
    }

    async fn update_locker(&self, req: Request<UpdateLockerRequest>)
        -> Result<Response<UpdateLockerResponse>, Status>
    {
        let req = req.into_inner();
        let Some(ctx) = req.context else {
            return Err(Status::new(tonic::Code::InvalidArgument,
                        "Failed to extract vault context from request"));
        };
        if let Err(e) = self.check_context(&ctx) {
            return Err(e);
        }
        match self.lockers.update_kv(
            &ctx.vault_id, &req.locker_id, req.locker_contents) {
            Ok(_) => Ok(Response::new(UpdateLockerResponse {})),
            Err(e) => Err(Status::new(tonic::Code::NotFound,
                    std::format!("Err: {}", e))),
        }
    }

    async fn read_locker(&self, req: Request<ReadLockerRequest>)
        -> Result<Response<ReadLockerResponse>, Status>
    {
        let req = req.into_inner();
        let Some(ctx) = req.context else {
            return Err(Status::new(tonic::Code::InvalidArgument,
                        "Failed to extract vault context from request"));
        };
        if let Err(e) = self.check_context(&ctx) {
            return Err(e);
        }
        match self.lockers.get_kv(&ctx.vault_id, &req.locker_id) {
            Ok(contents) => Ok(Response::new(ReadLockerResponse {
                locker_contents: contents,
            })),
            Err(e) => Err(Status::new(tonic::Code::NotFound,
                    std::format!("Err: {}", e))),
        }
    }

    async fn initiate_locker_deletion(&self, req: Request<InitiateLockerDeletionRequest>)
        -> Result<Response<InitiateLockerDeletionResponse>, Status>
    {
        let req = req.into_inner();
        let Some(ctx) = req.context else {
            return Err(Status::new(tonic::Code::InvalidArgument,
                        "Failed to extract vault context from request"));
        };
        if let Err(e) = self.check_context(&ctx) {
            return Err(e);
        }
        match self.lockers.initiate_kv_removal(
            &ctx.vault_id, &req.locker_id) {
            Ok(_) =>  Ok(Response::new(InitiateLockerDeletionResponse{})),
            Err(e) => Err(Status::new(tonic::Code::NotFound,
                    std::format!("Err: {}", e))),
        }
    }
}
