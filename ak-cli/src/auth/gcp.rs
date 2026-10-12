use ak_platform::{
    client::user::{AnyService, Client},
    generated::{agent::RequestHeader, agent_auth::TokenExchangeRequest},
    grpc::assert_response_valid,
};
use eyre::{Result, WrapErr};
use jsonwebtoken::dangerous::insecure_decode;
use serde::{Deserialize, Serialize};

pub const TOKEN_TYPE_JWT: &str = "urn:ietf:params:oauth:token-type:jwt";
pub const TOKEN_TYPE_ID_TOKEN: &str = "urn:ietf:params:oauth:token-type:id_token";

#[derive(Clone)]
pub struct CredentialsOpts {
    pub profile: String,
    pub client_id: String,
    /// The `subject_token_type` the Google credential config asked for. Google's
    /// libraries reject a response whose `token_type` doesn't match it.
    pub token_type: String,
}

/// Response for Google's executable-sourced external account credentials, as
/// read by gcloud and the Google Cloud client libraries.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExecutableResponse {
    pub version: i32,
    pub success: bool,
    #[serde(flatten)]
    pub result: ExecutableResult,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ExecutableResult {
    Token {
        token_type: String,
        id_token: String,
        expiration_time: i64,
    },
    Error {
        code: String,
        message: String,
    },
}

impl ExecutableResponse {
    pub fn error(code: &str, message: String) -> Self {
        Self {
            version: 1,
            success: false,
            result: ExecutableResult::Error {
                code: code.to_owned(),
                message,
            },
        }
    }
}

#[derive(Deserialize)]
struct ExpiryClaims {
    exp: i64,
}

pub async fn get_credentials(
    c: Client<AnyService>,
    opts: CredentialsOpts,
) -> Result<ExecutableResponse> {
    let res = c
        .auth()
        .cached_token_exchange(TokenExchangeRequest {
            header: Some(RequestHeader {
                profile: opts.profile,
            }),
            audience: opts.client_id,
            scopes: vec![],
            actor_token: None,
            actor_token_type: None,
        })
        .await
        .wrap_err("failed to exchange token")?
        .into_inner();
    assert_response_valid(res.header)?;

    // Google caches the response until `expiration_time`, so take it from the
    // token itself rather than trusting `expires_in` to be relative to now.
    let claims = insecure_decode::<ExpiryClaims>(&res.access_token)
        .map_err(|e| eyre::eyre!("exchanged token is not a JWT with an exp claim: {e}"))?
        .claims;

    Ok(ExecutableResponse {
        version: 1,
        success: true,
        result: ExecutableResult::Token {
            token_type: opts.token_type,
            id_token: res.access_token,
            expiration_time: claims.exp,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn token_response_shape() {
        let r = ExecutableResponse {
            version: 1,
            success: true,
            result: ExecutableResult::Token {
                token_type: TOKEN_TYPE_JWT.to_owned(),
                id_token: "t".to_owned(),
                expiration_time: 1700000000,
            },
        };
        assert_eq!(
            serde_json::to_value(r).unwrap(),
            json!({
                "version": 1,
                "success": true,
                "token_type": TOKEN_TYPE_JWT,
                "id_token": "t",
                "expiration_time": 1700000000,
            })
        );
    }

    #[test]
    fn error_response_shape() {
        let r = ExecutableResponse::error("401", "denied".to_owned());
        assert_eq!(
            serde_json::to_value(r).unwrap(),
            json!({"version": 1, "success": false, "code": "401", "message": "denied"})
        );
    }
}
