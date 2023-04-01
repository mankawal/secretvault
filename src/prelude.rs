
// [Future] Plugin entry function.
// pub fn build_kvstore() -> std::io::Result<Arc<dyn KVStore + Send + Sync>>;

pub trait KVStore
{
    fn create_locker(&self, locker: String) -> std::io::Result<()>;
    fn delete_locker(&self, locker: &str) -> std::io::Result<()>;

    fn add_kv(&self, locker: &str, k: String, v: String)
        -> std::io::Result<()>;
    fn get_kv(&self, locker: &str, k: &str) -> std::io::Result<String>;
    fn update_kv(&self, locker: &str, k: &str, v: String)
        -> std::io::Result<()>;
    fn remove_kv(&self, locker: &str, k: &str) -> std::io::Result<()>;
}

