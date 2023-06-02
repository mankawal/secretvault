use pasetors::claims::{Claims, ClaimsValidationRules};
use pasetors::keys::{Generate, SymmetricKey};
use pasetors::{local, Local, version4::V4};
use pasetors::errors::Error;
use pasetors::token::UntrustedToken;
use core::convert::TryFrom;
use once_cell::sync::Lazy;

use crate::secret_vault::CommonContext;

static TOKEN_KEY: Lazy<Result<SymmetricKey<V4>, Error>> = Lazy::new(|| {
    println!("Generating new token");
    SymmetricKey::<V4>::generate()
});

pub fn init() -> Result<(), &'static Error>
{
    match Lazy::force(&TOKEN_KEY) {
        Ok(_) => Ok(()),
        Err(e) => Err(e),
    }
}

pub fn generate_token(ctx: &CommonContext) -> Result<String, Error>
{
    let Ok(key) = TOKEN_KEY.as_ref() else {
        panic!("Token key uninitialized, module init not invoked!");
    };

    let mut claims = Claims::new()?;
    claims.non_expiring();
    claims.add_additional("vault_id", ctx.vault_id.to_string())?;
    claims.add_additional("user_name", ctx.user_name.to_string())?;
    claims.add_additional("user_context", ctx.user_context.to_string())?;
    println!("claims: {:?}", &claims);

    println!("claims: {:?}", &claims);
    local::encrypt(&key, &claims, None /* footer */,
                   Some(b"implicit assertion"))
}

pub fn decode_token(token: &str) -> Result<CommonContext, Error>
{
    let Ok(key) = TOKEN_KEY.as_ref() else {
        panic!("Token key uninitialized, module init not invoked!");
    };

    let mut validation_rules = ClaimsValidationRules::new();
    validation_rules.allow_non_expiring();

    let untrusted = UntrustedToken::<Local, V4>::try_from(token)?;
    // println!("Converted input token to untrusted");

    let trusted = local::decrypt(
        &key, &untrusted, &validation_rules, None,
        Some(b"implicit assertion"))?;
    // println!("Decrypted untrusted token");

    let Some(claims) = trusted.payload_claims() else {
        return Err(Error::EmptyPayload);
    };
    // println!("Extracted claims from decrypted token");

    let Some(val) = claims.get_claim("vault_id") else {
        println!("Failed to get vault_id from claims");
        return Err(Error::InvalidClaim);
    };
    println!("vault_id: {:?}", val);
    let serde_json::Value::String(vault_id) = val else {
        println!("Invalid json value for vault_id in claims");
        return Err(Error::InvalidClaim);
    };

    let Some(val) = claims.get_claim("user_name") else {
        println!("Failed to get vault_id from claims");
        return Err(Error::InvalidClaim);
    };
    let serde_json::Value::String(user_name) = val else {
        println!("Invalid json value for user_name in claims");
        return Err(Error::InvalidClaim);
    };

    let Some(val) = claims.get_claim("user_context") else {
        println!("Failed to get user_name from claims");
        return Err(Error::InvalidClaim);
    };
    let serde_json::Value::String(user_context) = val else {
        println!("Invalid json value for user_context in claims");
        return Err(Error::InvalidClaim);
    };

    Ok(CommonContext {
        vault_id: vault_id.to_string(),
        user_name: user_name.to_string(),
        user_context: user_context.to_string(),
    })
}
