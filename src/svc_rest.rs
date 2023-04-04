use axum::{
    error_handling::HandleErrorLayer,
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    routing::{post},
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
    // let db = Db::default();

    // Compose the routes
    let app = Router::new()
        .route("/locker", post(create_locker).delete(delete_locker))
        .route("/secret", post(add_secret).delete(remove_secret)
               .put(update_secret).get(get_secret))
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

    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    // tracing::debug!("listening on {}", addr);
    axum::Server::bind(&addr)
        .serve(app.into_make_service()).
        await.unwrap();
}

#[derive(Debug, Deserialize, Default)]
pub struct LockerId {
    pub locker_id: String,
}
async fn create_locker(State(store): State<Store>, Json(input): Json<LockerId>)
    -> impl IntoResponse
{
    match store.create_locker(input.locker_id) {
        Ok(_) => StatusCode::CREATED,
        Err(e) => {
            println!("Failed to create locker, err: {:?}", e);
            StatusCode::FOUND
        },
    }
}
async fn delete_locker(State(store): State<Store>, Json(input): Json<LockerId>)
    -> impl IntoResponse
{
    match store.delete_locker(&input.locker_id) {
        Ok(_) => StatusCode::NO_CONTENT,
        Err(e) => {
            println!("Failed to delete locker, err: {:?}", e);
            StatusCode::NOT_FOUND
        },
    }
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct Secret {
    pub locker_id: String,
    pub secret_key: String,
    pub secret_blob: String,
}

#[derive(Debug, Deserialize, Default)]
pub struct SecretKey {
    pub locker_id: String,
    pub secret_key: String,
}

async fn add_secret(State(store): State<Store>, Json(input): Json<Secret>)
    -> impl IntoResponse
{
    match store.add_kv(&input.locker_id,
                       input.secret_key, input.secret_blob) {
        Ok(_) => StatusCode::CREATED,
        Err(e) => {
            println!("Failed to create secret, err: {:?}", e);
            StatusCode::FOUND
        },
    }
}
async fn remove_secret(State(store): State<Store>, Json(input): Json<SecretKey>)
    -> impl IntoResponse
{
    match store.remove_kv(&input.locker_id, &input.secret_key) {
        Ok(_) => StatusCode::NO_CONTENT,
        Err(e) => {
            println!("Failed to delete secret, err: {:?}", e);
            StatusCode::NOT_FOUND
        },
    }
}
async fn update_secret(State(store): State<Store>, Json(input): Json<Secret>)
    -> impl IntoResponse
{
    match store.update_kv(&input.locker_id,
                          &input.secret_key, input.secret_blob) {
        Ok(_) => StatusCode::OK,
        Err(e) => {
            println!("Failed to update secret, err: {:?}", e);
            StatusCode::NOT_FOUND
        },
    }
}
async fn get_secret(State(store): State<Store>, Json(input): Json<SecretKey>)
    -> Result<impl IntoResponse, StatusCode>
{
    let res = store.get_kv(&input.locker_id, &input.secret_key);
    if let Ok(blob) = res {
        let secret = Secret {
            locker_id: input.locker_id,
            secret_key: input.secret_key,
            secret_blob: blob
        };
        return Ok(Json(secret));
    }
    println!("Failed to find secret, err: {:?}", res);
    Err(StatusCode::NOT_FOUND)
}
