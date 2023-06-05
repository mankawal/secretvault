use axum::{
    error_handling::HandleErrorLayer,
    extract::State,
    http::{header, Request, StatusCode},
    middleware::Next,
    response::IntoResponse,
    routing::{post, get},
    Json, Router, Extension,
    middleware,
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
use crate::auth_token;

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
        .route("/auth", get(get_auth))
        .route("/locker",
               post(create_locker).delete(delete_locker)
               .put(update_locker).get(read_locker)
               .route_layer(middleware::from_fn_with_state(
                       store.clone(), rest_auth))
        )
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

#[derive(Debug, Deserialize, Default, Clone, PartialEq)]
pub struct CommonContext {
    pub vault_id: String,
    pub user_name: String,
    pub user_context: String,
}

fn validate_context_in_kvstore(store: &Store, ctx: &CommonContext) ->
    Result<(), Box<dyn std::error::Error>>
{
    // Check if the corresponding vault exists.
    // TODO: Check if user's is authorized for the operation.
    // For now, this is a simple check on whether the incoming
    // user_context matches the user's attribute stored in the
    // vault's metadata locker.
    match store.get_kv(&ctx.vault_id, &ctx.user_name) {
        Ok(user_attrib) =>  {
            // println!("Found user for {}, {} => {}", &ctx.vault_id,
            //          &ctx.user_name, &ctx.user_context);
            if user_attrib.eq(&ctx.user_context) {
                Ok(())
            } else {
                // User attribute failed to match
                Err(Box::new(std::io::Error::new(std::io::ErrorKind::InvalidInput,
                                                 "incorrect user context")))
            }
        },
        // Failed to find vault or key
        Err(e) => {
            Err(Box::new(e))
        }
    }
}

#[derive(Debug, Serialize)]
struct ErrorResponse {
    msg: String,
}

async fn rest_auth<ReqType>(
    State(store): State<Store>, mut req: Request<ReqType>, next: Next<ReqType>
    ) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)>
{
    let token = req.headers().get(header::AUTHORIZATION)
        .and_then(|auth_hdr| { auth_hdr.to_str().ok() })
        .and_then(|auth_value| {
            if auth_value.starts_with("Bearer") {
                Some(auth_value[7..].to_owned())
            } else {
                None
            }
        });
    let token = token.ok_or_else(|| {
        let json_error = ErrorResponse {msg: "Empty token".to_string()};
        (StatusCode::UNAUTHORIZED, Json(json_error))
    })?;

    let (vault, user, userctx) =
        auth_token::decode_token(&token).map_err (|err| {
            let json_error = ErrorResponse {
                msg: std::format!("Failed to decode auth token {:?}", err) };
            (StatusCode::UNAUTHORIZED, Json(json_error))
        })?;
    let ctx_in_token = CommonContext {
        vault_id: vault,
        user_name: user,
        user_context: userctx
    };
    validate_context_in_kvstore(&store, &ctx_in_token).map_err (|err| {
        let json_error = ErrorResponse {
            msg: std::format!("Token context validation failed: {:?}", err)
        };
        (StatusCode::UNAUTHORIZED, Json(json_error))
    })?;

    req.extensions_mut().insert(ctx_in_token);
    Ok(next.run(req).await)
}

#[derive(Debug, Serialize, Default)]
struct AuthResponse {
    token: String,
}

async fn get_auth(
    State(store): State<Store>, Json(input): Json<CommonContext>
    ) -> Result<impl IntoResponse, StatusCode>
{
    if validate_context_in_kvstore(&store, &input).is_err() {
        return Err(StatusCode::FORBIDDEN);
    }
    match auth_token::generate_token(
        &input.vault_id, &input.user_name, &input.user_context) {
        Ok(token) => {
            let result = AuthResponse {token: token};
            println!("Result token: {:?}", result);
            Ok(Json(result))
        },
        Err(e) => {
            println!("Failed to generate auth token for vault: {} \
                     user: {}, err: {e}", input.vault_id, input.user_name);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
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

#[axum_macros::debug_handler]
async fn create_locker(
    Extension(ext): Extension<CommonContext>,
    State(store): State<Store>, Json(input): Json<Locker>)
    -> impl IntoResponse
{
    if ext != input.context {
        println!("Context in bearer token and request do not match"); 
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

async fn update_locker(
    Extension(ext): Extension<CommonContext>,
    State(store): State<Store>, Json(input): Json<Locker>)
    -> impl IntoResponse
{
    if ext != input.context {
        println!("Context in bearer token and request do not match"); 
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

async fn delete_locker(
    Extension(ext): Extension<CommonContext>,
    State(store): State<Store>, Json(input): Json<LockerId>)
    -> impl IntoResponse
{
    if ext != input.context {
        println!("Context in bearer token and request do not match"); 
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

async fn read_locker(
    Extension(ext): Extension<CommonContext>,
    State(store): State<Store>, Json(input): Json<LockerId>)
    -> Result<impl IntoResponse, StatusCode>
{
    if ext != input.context {
        println!("Context in bearer token and request do not match"); 
        return Err(StatusCode::FORBIDDEN);
    }
    match store.get_kv(&input.context.vault_id, &input.locker_id) {
        Ok(contents) => {
            let result = LockerContents {
                contents: contents
            };
            Ok(Json(result))
        },
        Err(e) => {
            println!("Failed to find locker, err: {:?}", e);
            Err(StatusCode::NOT_FOUND)
        }
    }
}
