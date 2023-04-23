fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::compile_protos("./protos/secret_vault_admin_service.proto")?;
    tonic_build::compile_protos("./protos/secret_vault_service.proto")?;
    Ok(())
}
