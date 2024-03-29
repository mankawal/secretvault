use axum::{
    error_handling::HandleErrorLayer,
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    routing::{post, get, delete},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::{
    net::SocketAddr,
    sync::Arc,
    time::Duration,
};
use tower::{BoxError, ServiceBuilder};
use tower_http::trace::TraceLayer;

use crate::config;
use crate::prelude::KVStore;

type Store = Arc<dyn KVStore + Send + Sync>;

pub async fn server(store: Arc<dyn KVStore + Send + Sync>,
                    port: u16, _tls: bool)
{
    // Compose the routes
    let app = Router::new()
        .route("/admin_config", get(get_admin_config))
        .route("/vault", post(create_vault).delete(delete_vault))
        .route("/metadata", post(add_metadata).delete(remove_metadata)
               .put(update_metadata).get(get_metadata))
        .route("/pending_delete", delete(delete_locker)
               .put(resuscitate_locker))
        // Add middleware to all routes
        .layer(
            ServiceBuilder::new()
            .layer(HandleErrorLayer::new(|error: BoxError| async move {
                if error.is::<tower::timeout::error::Elapsed>() {
                    Ok(StatusCode::REQUEST_TIMEOUT)
                } else {
                    Err((
                            StatusCode::INTERNAL_SERVER_ERROR,
                            format!("Unhandled internal error: {}", error),
                            ))
                }
            }))
            .timeout(Duration::from_secs(10))
            .layer(TraceLayer::new_for_http())
            .into_inner(),
            )
        .with_state(store);

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    axum::Server::bind(&addr)
        .serve(app.into_make_service()).
        await.unwrap();
}

// --- Handlers for route `admin_config` ---

async fn get_admin_config(State(_): State<Store>)
    -> Result<impl IntoResponse, StatusCode>
{
    match config::get_config_str() {
        Ok(config_str) => Ok(config_str),
        Err(e) => {
            println!("Failed to read config, err: {:?}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

// --- Handlers for route `vault` ---

#[derive(Debug, Deserialize, Default)]
pub struct VaultId {
    pub vault_id: String,
}
async fn create_vault(State(store): State<Store>, Json(input): Json<VaultId>)
    -> impl IntoResponse
{
    match store.create_db(input.vault_id) {
        Ok(_) => StatusCode::CREATED,
        Err(e) => {
            println!("Failed to create locker, err: {:?}", e);
            StatusCode::FOUND
        },
    }
}
async fn delete_vault(State(store): State<Store>, Json(input): Json<VaultId>)
    -> impl IntoResponse
{
    match store.delete_db(&input.vault_id) {
        Ok(_) => StatusCode::NO_CONTENT,
        Err(e) => {
            println!("Failed to delete locker, err: {:?}", e);
            StatusCode::NOT_FOUND
        },
    }
}

// --- Handlers for route `metadata` ---

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct Metadata {
    pub vault_id: String,
    pub name: String,
    pub value: String,
}

#[derive(Debug, Deserialize, Default)]
pub struct MetadataKey {
    pub vault_id: String,
    pub name: String,
}

async fn add_metadata(State(store): State<Store>, Json(input): Json<Metadata>)
    -> impl IntoResponse
{
    match store.add_kv(&input.vault_id,
                       input.name, input.value) {
        Ok(_) => StatusCode::CREATED,
        Err(e) => {
            println!("Failed to create locker, err: {:?}", e);
            StatusCode::FOUND
        },
    }
}
async fn remove_metadata(State(store): State<Store>, Json(input): Json<MetadataKey>)
    -> impl IntoResponse
{
    match store.remove_kv(&input.vault_id, &input.name) {
        Ok(_) => StatusCode::NO_CONTENT,
        Err(e) => {
            println!("Failed to delete locker, err: {:?}", e);
            StatusCode::NOT_FOUND
        },
    }
}
async fn update_metadata(State(store): State<Store>, Json(input): Json<Metadata>)
    -> impl IntoResponse
{
    match store.update_kv(&input.vault_id,
                          &input.name, input.value) {
        Ok(_) => StatusCode::OK,
        Err(e) => {
            println!("Failed to update locker, err: {:?}", e);
            StatusCode::NOT_FOUND
        },
    }
}
async fn get_metadata(State(store): State<Store>, Json(input): Json<MetadataKey>)
    -> Result<impl IntoResponse, StatusCode>
{
    match store.get_kv(&input.vault_id, &input.name)
    {
        Ok(blob) => {
            let locker = Metadata {
                vault_id: input.vault_id,
                name: input.name,
                value: blob
            };
            Ok(Json(locker))
        },
        Err(e) => {
            println!("Failed to find locker, err: {:?}", e);
            Err(StatusCode::NOT_FOUND)
        }
    }
}

// --- Handlers for route `pending_delete` ---

#[derive(Debug, Deserialize, Default)]
pub struct LockerId {
    pub vault_id: String,
    pub locker_id: String,
}

async fn delete_locker(State(store): State<Store>, Json(input): Json<LockerId>)
    -> impl IntoResponse
{
    /*
    println!("Trying to complete delete action on locker: {} in vault: {}",
             &input.locker_id, &input.vault_id);
    */
    match store.complete_kv_removal(&input.vault_id, &input.locker_id) {
        Ok(_) => StatusCode::NO_CONTENT,
        Err(e) => {
            println!("Failed to delete locker, err: {:?}", e);
            StatusCode::NOT_FOUND
        },
    }
}

async fn resuscitate_locker(State(store): State<Store>, Json(input): Json<LockerId>)
    -> impl IntoResponse
{
    match store.cancel_kv_removal(&input.vault_id, &input.locker_id) {
        Ok(_) => StatusCode::NO_CONTENT,
        Err(e) => {
            println!("Failed to delete locker, err: {:?}", e);
            StatusCode::NOT_FOUND
        },
    }
}
