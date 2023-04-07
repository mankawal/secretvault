#[allow(dead_code)]

/// Provides a RESTful web server managing some Todos.
///
/// API will be:
///
/// - `POST /locker/:locker_id`: create a locker with given name
/// - `DELETE /locker/:locker_id`: delete a locker
///
/// - `GET /secret/:locker_id, secret_key`: return the secret_blob stored against
///     the secret_key in the given locker.
/// - `POST /secret/:locker_id, secret_key, secret_blob`:
///     create a new secret with the given key, blob in the given locker.
/// - `PUT /secret/:locker_id, secret_key, secret_blob`:
///     updates the secret against the given key, blob in the given locker.
/// - `DELETE /secret/:locker_id, secret_key`: delete a specific secret.
/*
use std::env;

#[tokio::main]
async fn main() {
    if env::var_os("RUST_LOG").is_none() {
        // Set `RUST_LOG=todos=debug` to see debug logs,
        // this only shows access logs.
        env::set_var("RUST_LOG", "todos=info");
    }
    pretty_env_logger::init();

    let db = models::blank_db();

    let api = filters::api_endpoints(db);

    // View access logs by setting `RUST_LOG=todos`.
    let routes = api.with(warp::log("todos"));
    // Start up the server...
    warp::serve(routes).run(([127, 0, 0, 1], 3030)).await;
}
*/

pub mod filters {
    use super::handlers;
    use super::todos_handlers;
    use super::models::{Db, LockerId, Secret, SecretKey};
    use super::models::{DbTodos, ListOptions, Todo};
    use warp::Filter;

    /// The 4 TODOs filters combined.
    pub fn api_endpoints(
        db: Db,
    ) -> impl Filter<Extract = impl warp::Reply,
                     Error = warp::Rejection> + Clone
    {
        filter_get_config()
            .or(filter_create_locker(db.clone()))
            .or(filter_delete_locker(db.clone()))
            .or(filter_add_secret(db.clone()))
            .or(filter_remove_secret(db.clone()))
            .or(filter_update_secret(db.clone()))
            .or(filter_get_secret(db.clone()))
        /*
        todos_list(db.clone())
            .or(todos_create(db.clone()))
            .or(todos_update(db.clone()))
            .or(todos_delete(db))
        */
    }

    /// GET /config
    pub fn filter_get_config(
    ) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
        warp::path!("get_config")
            .and(warp::get())
            .and_then(handlers::get_config)
    }

    /// POST /locker?locker_id="locker1"
    pub fn filter_create_locker(
        db: Db,
    ) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
        warp::path!("create_locker")
            .and(warp::post())
            .and(json_body_locker())
            .and(with_db(db))
            .and_then(handlers::create_locker)
    }

    /// DELETE /locker?locker_id="locker1"
    pub fn filter_delete_locker(
        db: Db,
    ) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
        warp::path!("delete_locker")
            .and(warp::delete())
            .and(json_body_locker())
            .and(with_db(db))
            .and_then(handlers::delete_locker)
    }

    /// POST /add_secret?locker_id="locker1"&secret_key="k1"&secret_blob="v1"
    pub fn filter_add_secret(
        db: Db,
    ) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
        warp::path!("add_secret")
            .and(warp::post())
            .and(json_body_secret())
            .and(with_db(db))
            .and_then(handlers::add_secret)
    }

    /// DELETE /delete_secret?locker_id="locker1"&secret_key="k1"
    pub fn filter_remove_secret(
        db: Db,
    ) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
        warp::path!("delete_locker")
            .and(warp::delete())
            .and(json_body_secret_key())
            .and(with_db(db))
            .and_then(handlers::remove_secret)
    }

    /// GET /get_secret?locker_id="locker1"&secret_key="k1"
    pub fn filter_get_secret(
        db: Db,
    ) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
        warp::path!("get_secret")
            .and(warp::get())
            .and(json_body_secret_key())
            .and(with_db(db))
            .and_then(handlers::get_secret)
    }

    /// PUT /update_secret?locker_id="locker1"&secret_key="k1"&secret_blob="v1"
    pub fn filter_update_secret(
        db: Db,
    ) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
        warp::path!("update_secret")
            .and(warp::put())
            .and(json_body_secret())
            .and(with_db(db))
            .and_then(handlers::update_secret)
    }

    /// ---- Todos apis

    /// GET /todos?offset=3&limit=5
    pub fn todos_list(
        db: DbTodos,
    ) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
        warp::path!("todos")
            .and(warp::get())
            .and(warp::query::<ListOptions>())
            .and(with_db_todos(db))
            .and_then(todos_handlers::list_todos)
    }

    /// POST /todos with JSON body
    pub fn todos_create(
        db: DbTodos,
    ) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
        warp::path!("todos")
            .and(warp::post())
            .and(json_body())
            .and(with_db_todos(db))
            .and_then(todos_handlers::create_todo)
    }

    /// PUT /todos/:id with JSON body
    pub fn todos_update(
        db: DbTodos,
    ) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
        warp::path!("todos" / u64)
            .and(warp::put())
            .and(json_body())
            .and(with_db_todos(db))
            .and_then(todos_handlers::update_todo)
    }

    /// DELETE /todos/:id
    pub fn todos_delete(
        db: DbTodos,
    ) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
        // We'll make one of our endpoints admin-only to show how authentication filters are used
        let admin_only = warp::header::exact("authorization", "Bearer admin");

        warp::path!("todos" / u64)
            // It is important to put the auth check _after_ the path filters.
            // If we put the auth check before, the request `PUT /todos/invalid-string`
            // would try this filter and reject because the authorization header doesn't match,
            // rather because the param is wrong for that other path.
            .and(admin_only)
            .and(warp::delete())
            .and(with_db_todos(db))
            .and_then(todos_handlers::delete_todo)
    }

    fn with_db(db: Db)
        -> impl Filter<
            Extract = (Db,),
            Error = std::convert::Infallible> + Clone
    {
        warp::any().map(move || db.clone())
    }

    fn with_db_todos(db: DbTodos)
        -> impl Filter<
            Extract = (DbTodos,),
            Error = std::convert::Infallible> + Clone
    {
        warp::any().map(move || db.clone())
    }

    fn json_body()
        -> impl Filter<
            Extract = (Todo,),
            Error = warp::Rejection> + Clone
    {
        // TODO: The max length should be configurable
        // When accepting a body, we want a JSON body
        // (and to reject huge payloads)...
        warp::body::content_length_limit(512 * 16).and(warp::body::json())
    }

    fn json_body_locker()
        -> impl Filter<
            Extract = (LockerId,),
            Error = warp::Rejection> + Clone
   {
        // TODO: The max length should be configurable
        // When accepting a body, we want a JSON body
        // (and to reject huge payloads)...
        warp::body::content_length_limit(512 * 16).and(warp::body::json())
    }
    fn json_body_secret()
        -> impl Filter<
            Extract = (Secret,),
            Error = warp::Rejection> + Clone
    {
        // TODO: The max length should be configurable
        // When accepting a body, we want a JSON body
        // (and to reject huge payloads)...
        warp::body::content_length_limit(4096 * 16).and(warp::body::json())
    }
    fn json_body_secret_key()
        -> impl Filter<
            Extract = (SecretKey,),
            Error = warp::Rejection> + Clone
    {
        // TODO: The max length should be configurable
        // When accepting a body, we want a JSON body
        // (and to reject huge payloads)...
        warp::body::content_length_limit(2096 * 16).and(warp::body::json())
    }

}

mod handlers
{
    use super::models::{Db, LockerId, Secret, SecretKey};
    use std::convert::Infallible;
    use warp::http::StatusCode;

    pub async fn get_config() -> Result<impl warp::Reply, Infallible>
    {
        log::debug!("get_config");
        Ok(warp::reply::json(&String::from("")))
    }

    pub async fn create_locker(locker: LockerId, db: Db)
        -> Result<impl warp::Reply, Infallible>
    {
        log::debug!("create_locker: {:?}", locker);

        match db.create_locker(locker.id) {
            Ok(_) => Ok(StatusCode::CREATED),
            Err(e) => {
                log::debug!("create locker failed: {:?}", e);
                Ok(StatusCode::BAD_REQUEST)
            }
        }
    }

    pub async fn delete_locker(locker: LockerId, db: Db)
        -> Result<impl warp::Reply, Infallible>
    {
        log::debug!("delete_locker: {:?}", locker);
        match db.delete_locker(&locker.id) {
            Ok(_) => Ok(StatusCode::NO_CONTENT),
            Err(e) => {
                log::debug!(" -> delete locker failed: {:?}", e);
                Ok(StatusCode::NOT_FOUND)
            }
        }
    }

    pub async fn add_secret(secret: Secret, db: Db)
        -> Result<impl warp::Reply, Infallible>
    {
        log::debug!("add_secret: {:?}", secret);

        match db.add_kv(&secret.locker_id,
                        secret.secret_key, secret.secret_blob) {
            Ok(_) => Ok(StatusCode::CREATED),
            Err(e) => {
                log::debug!(" -> add secret failed: {:?}", e);
                Ok(StatusCode::BAD_REQUEST)
            }
        }
    }

    pub async fn remove_secret(sk: SecretKey, db: Db)
        -> Result<impl warp::Reply, Infallible>
    {
        log::debug!("remove_secret: {:?}", sk);
        match db.remove_kv(&sk.locker_id, &sk.secret_key) {
            Ok(_) => Ok(StatusCode::NO_CONTENT),
            Err(e) => {
                log::debug!(" -> remove secret failed: {:?}", e);
                Ok(StatusCode::NOT_FOUND)
            }
        }
    }

    pub async fn update_secret(secret: Secret, db: Db)
        -> Result<impl warp::Reply, Infallible>
    {
        log::debug!("update_secret: {:?}", secret);

        match db.update_kv(&secret.locker_id,
                           &secret.secret_key, secret.secret_blob) {
            Ok(_) => Ok(StatusCode::CREATED),
            Err(e) => {
                log::debug!(" -> update secret failed: {:?}", e);
                Ok(StatusCode::BAD_REQUEST)
            }
        }
    }
    
    pub async fn get_secret(sk: SecretKey, db: Db)
        -> Result<impl warp::Reply, Infallible>
    {
        log::debug!("get_secret: {:?}", sk);
        match db.get_kv(&sk.locker_id, &sk.secret_key) {
            Ok(blob) => {
                let secret = Secret {
                    locker_id: sk.locker_id,
                    secret_key: sk.secret_key,
                    secret_blob: blob
                };
                Ok(warp::reply::json(&secret))
            }
            Err(e) => {
                log::debug!("get secret failed: {:?}", e);
                Ok(warp::reply::json(&String::from("")))
            }
        }
    }
}

/// These are our API handlers, the ends of each filter chain.
/// Notice how thanks to using `Filter::and`, we can define a function
/// with the exact arguments we'd expect from each filter in the chain.
/// No tuples are needed, it's auto flattened for the functions.
mod todos_handlers {
    use super::models::{DbTodos, ListOptions, Todo};
    use std::convert::Infallible;
    use warp::http::StatusCode;

    pub async fn list_todos(opts: ListOptions, db: DbTodos) -> Result<impl warp::Reply, Infallible> {
        // Just return a JSON array of todos, applying the limit and offset.
        let todos = db.lock().await;
        let todos: Vec<Todo> = todos
            .clone()
            .into_iter()
            .skip(opts.offset.unwrap_or(0))
            .take(opts.limit.unwrap_or(std::usize::MAX))
            .collect();
        Ok(warp::reply::json(&todos))
    }

    pub async fn create_todo(create: Todo, db: DbTodos) -> Result<impl warp::Reply, Infallible> {
        log::debug!("create_todo: {:?}", create);

        let mut vec = db.lock().await;

        for todo in vec.iter() {
            if todo.id == create.id {
                log::debug!("    -> id already exists: {}", create.id);
                // Todo with id already exists, return `400 BadRequest`.
                return Ok(StatusCode::BAD_REQUEST);
            }
        }

        // No existing Todo with id, so insert and return `201 Created`.
        vec.push(create);

        Ok(StatusCode::CREATED)
    }

    pub async fn update_todo(
        id: u64,
        update: Todo,
        db: DbTodos,
    ) -> Result<impl warp::Reply, Infallible> {
        log::debug!("update_todo: id={}, todo={:?}", id, update);
        let mut vec = db.lock().await;

        // Look for the specified Todo...
        for todo in vec.iter_mut() {
            if todo.id == id {
                *todo = update;
                return Ok(StatusCode::OK);
            }
        }

        log::debug!("    -> todo id not found!");

        // If the for loop didn't return OK, then the ID doesn't exist...
        Ok(StatusCode::NOT_FOUND)
    }

    pub async fn delete_todo(id: u64, db: DbTodos) -> Result<impl warp::Reply, Infallible> {
        log::debug!("delete_todo: id={}", id);

        let mut vec = db.lock().await;

        let len = vec.len();
        vec.retain(|todo| {
            // Retain all Todos that aren't this id...
            // In other words, remove all that *are* this id...
            todo.id != id
        });

        // If the vec is smaller, we found and deleted a Todo!
        let deleted = vec.len() != len;

        if deleted {
            // respond with a `204 No Content`, which means successful,
            // yet no body expected...
            Ok(StatusCode::NO_CONTENT)
        } else {
            log::debug!("    -> todo id not found!");
            Ok(StatusCode::NOT_FOUND)
        }
    }
}

mod models {
    use serde_derive::{Deserialize, Serialize};
    use std::sync::Arc;
    use tokio::sync::Mutex;
    use crate::prelude::KVStore;

    /// So we don't have to tackle how different database work, we'll just use
    /// a simple in-memory DB, a vector synchronized by a mutex.
    pub type DbTodos = Arc<Mutex<Vec<Todo>>>;
    pub type Db = Arc<dyn KVStore + Send + Sync>;

    pub fn blank_db() -> DbTodos {
        Arc::new(Mutex::new(Vec::new()))
    }

    #[derive(Debug, Deserialize, Serialize, Clone)]
    pub struct LockerId
    {
        pub id: String,
    }

    #[derive(Debug, Deserialize, Serialize, Clone)]
    pub struct Secret
    {
        pub locker_id: String,
        pub secret_key: String,
        pub secret_blob: String,
    }

    #[derive(Debug, Deserialize, Serialize, Clone)]
    pub struct SecretKey
    {
        pub locker_id: String,
        pub secret_key: String,
    }

    #[derive(Debug, Deserialize, Serialize, Clone)]
    pub struct Todo {
        pub id: u64,
        pub text: String,
        pub completed: bool,
    }

    // The query parameters for list_todos.
    #[derive(Debug, Deserialize)]
    pub struct ListOptions {
        pub offset: Option<usize>,
        pub limit: Option<usize>,
    }
}

#[cfg(test)]
mod tests {
    use warp::http::StatusCode;
    use warp::test::request;

    use super::{
        filters,
        models::{self, Todo},
    };

    #[tokio::test]
    async fn test_post() {
        let db = models::blank_db();
        let api = filters::todos(db);

        let resp = request()
            .method("POST")
            .path("/todos")
            .json(&todo1())
            .reply(&api)
            .await;

        assert_eq!(resp.status(), StatusCode::CREATED);
    }

    #[tokio::test]
    async fn test_post_conflict() {
        let db = models::blank_db();
        db.lock().await.push(todo1());
        let api = filters::todos(db);

        let resp = request()
            .method("POST")
            .path("/todos")
            .json(&todo1())
            .reply(&api)
            .await;

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_put_unknown() {
        let _ = pretty_env_logger::try_init();
        let db = models::blank_db();
        let api = filters::todos(db);

        let resp = request()
            .method("PUT")
            .path("/todos/1")
            .header("authorization", "Bearer admin")
            .json(&todo1())
            .reply(&api)
            .await;

        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    fn todo1() -> Todo {
        Todo {
            id: 1,
            text: "test 1".into(),
            completed: false,
        }
    }
}
