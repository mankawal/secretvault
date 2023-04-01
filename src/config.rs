use serde::{Deserialize};

#[allow(dead_code)]
#[derive(Deserialize, Debug)]
pub struct ProtoConfig
{
    pub rest: u16,
    pub grpc: u16,
    pub graphql: u16,
}

#[allow(dead_code)]
#[derive(Deserialize, Debug)]
pub struct EndpointConfig
{
    pub tls: bool,
    pub cors_origin: Vec<String>,
    pub cache: bool,
    pub proto : ProtoConfig,
}

#[allow(dead_code)]
#[derive(Deserialize, Debug)]
pub struct StoreConfig
{
    pub name: String,
    pub endpoint: String,
    pub dbuser: String,
    pub dbpassword: String,
    pub dbpath: String,
}

#[allow(dead_code)]
#[derive(Deserialize, Debug)]
pub struct SecurityConfig
{
    pub master_password: bool,
    pub postq_creds: bool,
    pub locker_name_hash: bool,

    pub tls_cert_path: String,
    pub tls_key_path: String,
}

#[allow(dead_code)]
#[derive(Deserialize, Debug)]
pub struct BackupConfig
{
    pub interval: u64,
    pub cloud_endpoint: String, 
}

#[allow(dead_code)]
#[derive(Deserialize, Debug)]
pub struct ServiceConfig
{
    pub serve: EndpointConfig,
    pub store: StoreConfig,
    pub security: SecurityConfig,
    pub backup: BackupConfig,
    pub test: bool
}

pub fn get_config_str() -> std::io::Result<String>
{
    let configfile =
        std::path::PathBuf::from("./config.json");
    match std::fs::read_to_string(&configfile) {
        Ok(config_str) => Ok(config_str),
        Err(e) => Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                std::format!("failed to read config file {}, err: {}",
                             configfile.display(), e))),
    }
}

pub fn read_and_parse_config() -> std::io::Result<ServiceConfig>
{
    match get_config_str() {
        Ok(config_str) => {
            match serde_json::from_str(&config_str) {
                Ok(config) => Ok(config),
                Err(e) => Err(std::io::Error::new(
                        std::io::ErrorKind::Other, std::format!(
                            "parsing json file failed, err: {}", e)))
            }
        },
        Err(e) => Err(e),
    }
}
