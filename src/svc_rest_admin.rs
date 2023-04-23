use axum::{
    error_handling::HandleErrorLayer,
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    routing::{post, get},
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
// use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use crate::config;
use crate::prelude::KVStore;

type Store = Arc<dyn KVStore + Send + Sync>;

pub async fn server(store: Arc<dyn KVStore + Send + Sync>,
                    port: u16, _tls: bool)
{
    /*
       tracing_subscriber::registry()
       .with(
       tracing_subscriber::EnvFilter::try_from_default_env()
       .unwrap_or_else(|_| "example_todos=debug,tower_http=debug".into()),
       )
       .with(tracing_subscriber::fmt::layer())
       .init();
       */

    // Compose the routes
    let app = Router::new()
        .route("/admin_config", get(get_admin_config))
        .route("/vault", post(create_vault).delete(delete_vault))
        .route("/metadata", post(add_metadata).delete(remove_metadata)
               .put(update_metadata).get(get_metadata))
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
    // tracing::debug!("listening on {}", addr);
    axum::Server::bind(&addr)
        .serve(app.into_make_service()).
        await.unwrap();
}

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

#[derive(Debug, Deserialize, Default)]
pub struct LockerId {
    pub vault_id: String,
}
async fn create_vault(State(store): State<Store>, Json(input): Json<LockerId>)
    -> impl IntoResponse
{
    match store.create_locker(input.vault_id) {
        Ok(_) => StatusCode::CREATED,
        Err(e) => {
            println!("Failed to create locker, err: {:?}", e);
            StatusCode::FOUND
        },
    }
}
async fn delete_vault(State(store): State<Store>, Json(input): Json<LockerId>)
    -> impl IntoResponse
{
    match store.delete_locker(&input.vault_id) {
        Ok(_) => StatusCode::NO_CONTENT,
        Err(e) => {
            println!("Failed to delete locker, err: {:?}", e);
            StatusCode::NOT_FOUND
        },
    }
}

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
            println!("Failed to create secret, err: {:?}", e);
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
            println!("Failed to delete secret, err: {:?}", e);
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
            println!("Failed to update secret, err: {:?}", e);
            StatusCode::NOT_FOUND
        },
    }
}
async fn get_metadata(State(store): State<Store>, Json(input): Json<MetadataKey>)
    -> Result<impl IntoResponse, StatusCode>
{
    let res = store.get_kv(&input.vault_id, &input.name);
    if let Ok(blob) = res {
        let secret = Metadata {
            vault_id: input.vault_id,
            name: input.name,
            value: blob
        };
        return Ok(Json(secret));
    }
    println!("Failed to find secret, err: {:?}", res);
    Err(StatusCode::NOT_FOUND)
}
