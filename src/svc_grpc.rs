use std::sync::Arc;
use crate::config;
use crate::prelude::KVStore;

use tonic::{
    Request, Response, Status,
    metadata::MetadataMap,
};
use crate::secret_vault::{CommonContext,
    GetConfigRequest, GetConfigResponse,
    CreateLockerRequest, CreateLockerResponse,
    ReadLockerRequest, ReadLockerResponse,
    UpdateLockerRequest, UpdateLockerResponse,
    InitiateLockerDeletionRequest, InitiateLockerDeletionResponse,
    GetAuthRequest, GetAuthResponse,
    secret_vault_server::{SecretVault},
};
use crate::config::ServiceConfig;

use crate::auth_token;

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

    pub fn validate_context_in_kvstore(&self, ctx: &CommonContext) ->
        Result<(), Status>
    {
        match self.lockers.get_kv(&ctx.vault_id, &ctx.user_name) {
            Ok(user_attrib) =>  {
                if user_attrib.eq(&ctx.user_context) {
                    Ok(())
                } else {
                    Err(Status::new(tonic::Code::InvalidArgument,
                                    "Stale/incorrect user context"))
                }
            },
            Err(_) =>
                Err(Status::new(tonic::Code::NotFound, std::format!(
                            "Vault {} or user {}not found", &ctx.vault_id,
                            &ctx.user_name)))
        }
    }

    pub fn check_context(&self, ctx: Option<CommonContext>) ->
        Result<CommonContext, Status>
    {
        let Some(ctx) = ctx else {
            return Err(Status::new(tonic::Code::InvalidArgument,
                        "Failed to extract vault context from request"));
        };
        match self.validate_context_in_kvstore(&ctx) {
            Ok(()) => Ok(ctx),
            Err(s) => Err(s),
        }
    }

    pub fn compare_and_check_context(&self, ctx: Option<CommonContext>,
                                     ctx_in_token: &CommonContext) ->
        Result<CommonContext, Status>
    {
        let Some(ctx) = ctx else {
            return Err(Status::new(tonic::Code::InvalidArgument,
                        "Failed to extract vault context from request"));
        };
        if !ctx.eq(&ctx_in_token) {
            return Err(Status::new(tonic::Code::Unauthenticated,
                                "Context in token and request do not match"));
        }
        match self.validate_context_in_kvstore(&ctx) {
            Ok(()) => Ok(ctx),
            Err(s) => Err(s),
        }
    }

    pub fn check_auth_and_context(&self, metamap: &MetadataMap)
        -> Result<CommonContext, Status>
    {
        let Some(token) = metamap.get("Authorization") else {
            return Err(Status::new(tonic::Code::Unauthenticated,
                       "No user token provided with the request"));
        };
        let Ok(token) = token.to_str() else {
            return Err(Status::new(tonic::Code::InvalidArgument,
                       "Invalid token in Authorization header"));
        };
        let words:Vec<_> = token.split_whitespace().collect();
        if words.len() < 2 || words[0].to_lowercase() != "bearer" {
            return Err(Status::new(tonic::Code::Unauthenticated,
                        "Null/invalid bearer token in Authorization header"));
        }
        match auth_token::decode_token(&words[1]) {
            Ok(ctx_in_token) => {
                println!("vault: {}, user: {}, user_ctx: {}",
                         &ctx_in_token.vault_id, &ctx_in_token.user_name,
                         &ctx_in_token.user_context);
                Ok(ctx_in_token)
            },
            Err(e) => Err(Status::new(
                    tonic::Code::Unauthenticated, std::format!(
                        "Bearer token decryption failed, err: {:?}", e))),
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
        let ctx_in_token = self.check_auth_and_context(req.metadata())?;
        let inreq = req.into_inner();
        let ctx = self.compare_and_check_context(
            inreq.context, &ctx_in_token)?;
        match self.lockers.add_kv(&ctx.vault_id,
                                  inreq.locker_id, inreq.locker_contents) {
            Ok(_) =>  Ok(Response::new(CreateLockerResponse{})),
            Err(e) => Err(Status::new(tonic::Code::InvalidArgument,
                    std::format!("Err: {}", e))),
        }
    }

    async fn update_locker(&self, req: Request<UpdateLockerRequest>)
        -> Result<Response<UpdateLockerResponse>, Status>
    {
        let ctx_in_token = self.check_auth_and_context(req.metadata())?;
        let inreq = req.into_inner();
        let ctx = self.compare_and_check_context(
            inreq.context, &ctx_in_token)?;
        match self.lockers.update_kv(
            &ctx.vault_id, &inreq.locker_id, inreq.locker_contents) {
            Ok(_) => Ok(Response::new(UpdateLockerResponse {})),
            Err(e) => Err(Status::new(tonic::Code::NotFound,
                    std::format!("Err: {}", e))),
        }
    }

    async fn read_locker(&self, req: Request<ReadLockerRequest>)
        -> Result<Response<ReadLockerResponse>, Status>
    {
        let ctx_in_token = self.check_auth_and_context(req.metadata())?;
        let inreq = req.into_inner();
        let ctx = self.compare_and_check_context(
            inreq.context, &ctx_in_token)?;
        match self.lockers.get_kv(&ctx.vault_id, &inreq.locker_id) {
            Ok(contents) => Ok(Response::new(ReadLockerResponse {
                locker_contents: contents,
            })),
            Err(e) => Err(Status::new(tonic::Code::NotFound,
                    std::format!("Err: {}", e))),
        }
    }

    async fn initiate_locker_deletion(
        &self, req: Request<InitiateLockerDeletionRequest>)
        -> Result<Response<InitiateLockerDeletionResponse>, Status>
    {
        let ctx_in_token = self.check_auth_and_context(req.metadata())?;
        let inreq = req.into_inner();
        let ctx = self.compare_and_check_context(
            inreq.context, &ctx_in_token)?;
        match self.lockers.initiate_kv_removal(
            &ctx.vault_id, &inreq.locker_id) {
            Ok(_) =>  Ok(Response::new(InitiateLockerDeletionResponse{})),
            Err(e) => Err(Status::new(tonic::Code::NotFound,
                    std::format!("Err: {}", e))),
        }
    }

    async fn get_auth(&self, req: Request<GetAuthRequest>)
        -> Result<Response<GetAuthResponse>, Status>
    {
        let inreq = req.into_inner();
        let ctx = self.check_context(inreq.context)?;
        match auth_token::generate_token(&ctx) {
            Ok(token) => Ok(Response::new(GetAuthResponse{
                auth_token: token,
            })),
            Err(e) => Err(Status::new(tonic::Code::Internal,
                            std::format!("{:?}", e))),
        }
    }
}
