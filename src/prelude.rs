
// [Future] Plugin entry function.
// pub fn build_kvstore() -> std::io::Result<Arc<dyn KVStore + Send + Sync>>;

pub trait KVStore
{
    fn create_db(&self, dbname: String) -> std::io::Result<()>;
    fn delete_db(&self, dbname: &str) -> std::io::Result<()>;

    fn add_kv(&self, dbname: &str, k: String, v: String)
        -> std::io::Result<()>;
    fn get_kv(&self, dbname: &str, k: &str) -> std::io::Result<String>;
    fn update_kv(&self, dbname: &str, k: &str, v: String)
        -> std::io::Result<()>;
    fn remove_kv(&self, dbname: &str, k: &str) -> std::io::Result<()>;

    fn initiate_kv_removal(&self, dbname: &str, k: &str)
        -> std::io::Result<()>;
    fn cancel_kv_removal(&self, dbname: &str, k: &str)
        -> std::io::Result<()>;
    fn complete_kv_removal(&self, dbname: &str, k: &str)
        -> std::io::Result<()>;
    fn list_keys_in_removal(&self, dbname: &str) -> std::io::Result<Vec<String>>;
}

