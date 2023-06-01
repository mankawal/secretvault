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
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use crate::config;
use crate::prelude::KVStore;

type Store = Arc<dyn KVStore + Send + Sync>;

pub async fn server(store: Arc<dyn KVStore + Send + Sync>,
                    port: u16, _tls: bool)
{
       tracing_subscriber::registry()
       .with(
       tracing_subscriber::EnvFilter::try_from_default_env()
       .unwrap_or_else(|_| "example_todos=debug,tower_http=debug".into()),
       )
       .with(tracing_subscriber::fmt::layer())
       .init();

    // Compose the routes
    let app = Router::new()
        .route("/config", get(get_config))
        .route("/locker",
               post(create_locker).delete(delete_locker)
               .put(update_locker).get(read_locker))
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
    tracing::debug!("listening on {}", addr);
    axum::Server::bind(&addr)
        .serve(app.into_make_service()).
        await.unwrap();
}

async fn get_config(State(_): State<Store>)
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
pub struct CommonContext {
    pub vault_id: String,
    pub user_name: String,
    pub user_context: String,
}

fn check_context(store: &Store, ctx: &CommonContext) ->
    Result<(), Box<dyn std::error::Error>>
{
        // Check if the corresponding vault exists.
        // TODO: Check if user's is authorized for the operation.
        // For now, this is a simple check on whether the incoming
        // user_context matches the user's attribute stored in the
        // vault's metadata locker.
        match store.get_kv(&ctx.vault_id, &ctx.user_name) {
            // Insertion succeeded
            Ok(user_attrib) =>  {
                if user_attrib.eq(&ctx.user_context) {
                    Ok(())
                } else {
                    // User attribute failed to match
                    Err(Box::new(std::io::Error::new(std::io::ErrorKind::InvalidInput,
                                            "incorrect user context")))
                }
            },
            // Failed to find vault or key
            Err(e) => Err(Box::new(e)),
        }
}

#[derive(Debug, Deserialize, Default)]
pub struct LockerId {
    pub context: CommonContext,
    pub locker_id: String,
}
#[derive(Debug, Deserialize, Default)]
pub struct Locker {
    pub context: CommonContext,
    pub locker_id: String,
    pub locker_contents: String,
}
#[derive(Debug, Serialize, Default)]
pub struct LockerContents {
    pub contents: String,
}

async fn create_locker(State(store): State<Store>, Json(input): Json<Locker>)
    -> impl IntoResponse
{
    if let Err(e) = check_context(&store, &input.context) {
        println!("Request context check failed, err: {:?}", e);
        return StatusCode::FORBIDDEN;
    }
    match store.add_kv(&input.context.vault_id,
                          input.locker_id, input.locker_contents) {
        Ok(_) => StatusCode::CREATED,
        Err(e) => {
            println!("Failed to create locker, err: {:?}", e);
            StatusCode::FOUND
        },
    }
}

async fn update_locker(State(store): State<Store>, Json(input): Json<Locker>)
    -> impl IntoResponse
{
    if let Err(e) = check_context(&store, &input.context) {
        println!("Request context check failed, err: {:?}", e);
        return StatusCode::FORBIDDEN;
    }
    match store.update_kv(&input.context.vault_id,
                          &input.locker_id, input.locker_contents) {
        Ok(_) => StatusCode::OK,
        Err(e) => {
            println!("Failed to create locker, err: {:?}", e);
            StatusCode::FOUND
        },
    }
}

async fn delete_locker(State(store): State<Store>, Json(input): Json<LockerId>)
    -> impl IntoResponse
{
    if let Err(e) = check_context(&store, &input.context) {
        println!("Request context check failed, err: {:?}", e);
        return StatusCode::FORBIDDEN;
    }
    match store.initiate_kv_removal(
        &input.context.vault_id, &input.locker_id) {
        Ok(_) => StatusCode::NO_CONTENT,
        Err(e) => {
            println!("Failed to delete locker, err: {:?}", e);
            StatusCode::NOT_FOUND
        },
    }
}

async fn read_locker(State(store): State<Store>, Json(input): Json<LockerId>)
    -> Result<impl IntoResponse, StatusCode>
{
    if let Err(e) = check_context(&store, &input.context) {
        println!("Request context check failed, err: {:?}", e);
        return Err(StatusCode::FORBIDDEN);
    }
    match store.get_kv(&input.context.vault_id, &input.locker_id) {
        Ok(contents) => {
            let result = LockerContents {
                contents: contents
            };
            return Ok(Json(result));
        },
        Err(e) => {
            println!("Failed to find secret, err: {:?}", e);
            Err(StatusCode::NOT_FOUND)
        }
    }
}
