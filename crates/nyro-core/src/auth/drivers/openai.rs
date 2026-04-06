use std::collections::HashMap;

use anyhow::{Context, Result, anyhow, bail};
use async_trait::async_trait;
use base64::Engine;
use reqwest::header::{ACCEPT, CONTENT_TYPE};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::shared::{
    PkceAuthState, build_authorize_url, encode_scopes, expires_at_after, generate_code_challenge,
    generate_code_verifier, generate_state, parse_oauth_callback, parse_session_state,
    required_http_client, validate_callback_state,
};
use crate::auth::types::{
    AuthDriver, AuthDriverMetadata, AuthExchangeInput, AuthScheme, AuthSession, CreateAuthSession,
    CredentialBundle, ExchangeAuthContext, RefreshAuthContext, RuntimeBinding, StartAuthContext,
    StoredCredential,
};
use crate::db::models::Provider;

const OPENAI_AUTH_BASE_URL: &str = "https://auth.openai.com";
const OPENAI_AUTHORIZE_URL: &str = "https://auth.openai.com/oauth/authorize";
const OPENAI_TOKEN_URL: &str = "https://auth.openai.com/oauth/token";
const OPENAI_CLIENT_ID: &str = "app_EMoamEEZ73f0CkXaXp7hrann";
const OPENAI_REDIRECT_URI: &str = "http://localhost:1455/auth/callback";
const OPENAI_SCOPE: &str = "openid profile email offline_access";
const CODEX_API_BASE_URL: &str = "https://chatgpt.com/backend-api/codex";
const CODEX_MODELS_URL: &str = "https://chatgpt.com/backend-api/codex/models";
const CODEX_MODELS_CLIENT_VERSION: &str = "0.99.0";

#[derive(Debug, Default)]
pub struct OpenAIOAuthDriver;

#[derive(Debug, Deserialize)]
struct OpenAITokenResponse {
    access_token: Option<String>,
    refresh_token: Option<String>,
    expires_in: Option<i64>,
    scope: Option<String>,
}

#[derive(Debug, Deserialize)]
struct OpenAIErrorResponse {
    error: Option<String>,
    error_description: Option<String>,
    message: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct OpenAIAuthState {
    #[serde(flatten)]
    pkce: PkceAuthState,
}

impl OpenAIOAuthDriver {
    fn normalize_token_response(
        body: &str,
        fallback_refresh_token: Option<&str>,
    ) -> Result<CredentialBundle> {
        let token: OpenAITokenResponse =
            serde_json::from_str(body).context("parse openai oauth token response")?;
        let access_token = token
            .access_token
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| anyhow!("openai oauth token response missing access_token"))?;
        let expires_in = token.expires_in.unwrap_or(3600).max(1);

        Ok(CredentialBundle {
            access_token: Some(access_token),
            refresh_token: token
                .refresh_token
                .filter(|value| !value.trim().is_empty())
                .or_else(|| fallback_refresh_token.map(ToString::to_string)),
            expires_at: Some(expires_at_after(expires_in)),
            resource_url: Some(CODEX_API_BASE_URL.to_string()),
            subject_id: None,
            scopes: encode_scopes(token.scope.as_deref()),
            raw: serde_json::from_str(body).unwrap_or(serde_json::Value::Null),
        })
    }

    fn parse_error(body: &str) -> Option<String> {
        let parsed: OpenAIErrorResponse = serde_json::from_str(body).ok()?;
        parsed
            .error_description
            .filter(|value| !value.trim().is_empty())
            .or_else(|| parsed.message.filter(|value| !value.trim().is_empty()))
            .or_else(|| parsed.error.filter(|value| !value.trim().is_empty()))
    }

    fn decode_jwt_claims(token: &str) -> Option<Value> {
        let payload = token.split('.').nth(1)?;
        let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(payload)
            .ok()?;
        serde_json::from_slice(&decoded).ok()
    }

    fn extract_account_id(credential: &StoredCredential) -> Option<String> {
        let access_token = credential.access_token.as_deref()?.trim();
        if access_token.is_empty() {
            return None;
        }

        let claims = Self::decode_jwt_claims(access_token)?;
        claims
            .get("https://api.openai.com/auth")
            .and_then(Value::as_object)
            .and_then(|auth| auth.get("chatgpt_account_id"))
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToString::to_string)
            .or_else(|| {
                claims
                    .get("https://api.openai.com/auth.chatgpt_account_id")
                    .and_then(Value::as_str)
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .map(ToString::to_string)
            })
    }

    fn codex_models_source() -> String {
        format!("{CODEX_MODELS_URL}?client_version={CODEX_MODELS_CLIENT_VERSION}")
    }
}

#[async_trait]
impl AuthDriver for OpenAIOAuthDriver {
    fn metadata(&self) -> AuthDriverMetadata {
        AuthDriverMetadata {
            key: "codex",
            label: "Codex",
            scheme: AuthScheme::OAuthAuthCodePkce,
            supports_new_provider: true,
            supports_existing_provider: true,
        }
    }

    async fn start(&self, ctx: StartAuthContext) -> Result<CreateAuthSession> {
        let code_verifier = generate_code_verifier();
        let code_challenge = generate_code_challenge(&code_verifier);
        let state = generate_state();
        let auth_url = build_authorize_url(
            OPENAI_AUTHORIZE_URL,
            &[
                ("response_type", "code"),
                ("client_id", OPENAI_CLIENT_ID),
                ("redirect_uri", OPENAI_REDIRECT_URI),
                ("scope", OPENAI_SCOPE),
                ("code_challenge", &code_challenge),
                ("code_challenge_method", "S256"),
                ("state", &state),
                ("id_token_add_organizations", "true"),
                ("codex_cli_simplified_flow", "true"),
            ],
        )?;
        let session_state = serde_json::to_string(&OpenAIAuthState {
            pkce: PkceAuthState {
                code_verifier,
                state,
                redirect_uri: OPENAI_REDIRECT_URI.to_string(),
            },
        })?;

        Ok(CreateAuthSession {
            provider_id: ctx.provider_id,
            driver_key: self.metadata().key.to_string(),
            scheme: self.metadata().scheme.as_str().to_string(),
            status: "pending".to_string(),
            use_proxy: ctx.use_proxy,
            user_code: None,
            verification_uri: Some(OPENAI_AUTH_BASE_URL.to_string()),
            verification_uri_complete: Some(auth_url),
            state_json: Some(session_state),
            context_json: None,
            result_json: None,
            expires_at: Some(expires_at_after(10 * 60)),
            poll_interval_seconds: Some(2),
            last_error: None,
        })
    }

    async fn exchange(
        &self,
        session: &AuthSession,
        input: AuthExchangeInput,
        ctx: ExchangeAuthContext,
    ) -> Result<CredentialBundle> {
        let state: OpenAIAuthState = parse_session_state(session)?;
        let callback = parse_oauth_callback(&input)?;
        validate_callback_state(&state.pkce.state, callback.state.as_deref(), "openai")?;
        let code = callback
            .code
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| anyhow!("missing authorization code"))?;

        let client = required_http_client(ctx.http_client)?;
        let response = client
            .post(OPENAI_TOKEN_URL)
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(ACCEPT, "application/json")
            .form(&[
                ("grant_type", "authorization_code"),
                ("code", code),
                ("redirect_uri", state.pkce.redirect_uri.as_str()),
                ("client_id", OPENAI_CLIENT_ID),
                ("code_verifier", state.pkce.code_verifier.as_str()),
            ])
            .send()
            .await
            .context("exchange openai authorization code")?;

        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        if !status.is_success() {
            let detail = Self::parse_error(&body).unwrap_or(body);
            bail!("openai oauth token exchange failed: HTTP {status} {detail}");
        }

        Self::normalize_token_response(&body, None)
    }

    async fn refresh(
        &self,
        credential: &StoredCredential,
        ctx: RefreshAuthContext,
    ) -> Result<CredentialBundle> {
        let refresh_token = credential
            .refresh_token
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| anyhow!("openai oauth refresh token is missing"))?;
        let client = required_http_client(ctx.http_client)?;

        let response = client
            .post(OPENAI_TOKEN_URL)
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(ACCEPT, "application/json")
            .form(&[
                ("grant_type", "refresh_token"),
                ("client_id", OPENAI_CLIENT_ID),
                ("refresh_token", refresh_token),
                ("scope", "openid profile email"),
            ])
            .send()
            .await
            .context("refresh openai oauth token")?;

        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        if !status.is_success() {
            let detail = Self::parse_error(&body).unwrap_or(body);
            bail!("openai oauth token refresh failed: HTTP {status} {detail}");
        }

        Self::normalize_token_response(&body, Some(refresh_token))
    }

    fn bind_runtime(
        &self,
        _provider: &Provider,
        credential: &StoredCredential,
    ) -> Result<RuntimeBinding> {
        let account_id = Self::extract_account_id(credential)
            .ok_or_else(|| anyhow!("openai oauth access token missing chatgpt_account_id"))?;

        let mut extra_headers = HashMap::new();
        extra_headers.insert("ChatGPT-Account-ID".to_string(), account_id);

        Ok(RuntimeBinding {
            base_url_override: Some(CODEX_API_BASE_URL.to_string()),
            extra_headers,
            model_aliases: HashMap::new(),
            models_source_override: Some(Self::codex_models_source()),
            capabilities_source_override: Some("ai://models.dev/openai".to_string()),
            disable_default_auth: false,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{CODEX_API_BASE_URL, OpenAIOAuthDriver};
    use crate::auth::types::{AuthDriver, StoredCredential};
    use base64::Engine;

    #[test]
    fn extracts_account_id_from_access_token_claims() {
        let claims = r#"{"https://api.openai.com/auth":{"chatgpt_account_id":"acct-123"}}"#;
        let token = format!(
            "header.{}.sig",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(claims)
        );
        let credential = StoredCredential {
            access_token: Some(token),
            ..Default::default()
        };

        assert_eq!(
            OpenAIOAuthDriver::extract_account_id(&credential).as_deref(),
            Some("acct-123")
        );
    }

    #[test]
    fn builds_codex_runtime_binding() {
        let claims = r#"{"https://api.openai.com/auth":{"chatgpt_account_id":"acct-456"}}"#;
        let token = format!(
            "header.{}.sig",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(claims)
        );
        let credential = StoredCredential {
            access_token: Some(token),
            ..Default::default()
        };

        let binding = OpenAIOAuthDriver
            .bind_runtime(
                &crate::db::models::Provider {
                    id: "provider".to_string(),
                    name: "Codex".to_string(),
                    vendor: Some("codex".to_string()),
                    protocol: "openai".to_string(),
                    base_url: CODEX_API_BASE_URL.to_string(),
                    default_protocol: "openai".to_string(),
                    protocol_endpoints: "{}".to_string(),
                    preset_key: None,
                    channel: None,
                    models_source: None,
                    capabilities_source: None,
                    static_models: None,
                    api_key: String::new(),
                    use_proxy: false,
                    last_test_success: None,
                    last_test_at: None,
                    is_active: true,
                    created_at: String::new(),
                    updated_at: String::new(),
                },
                &credential,
            )
            .expect("binding should succeed");

        assert_eq!(
            binding
                .extra_headers
                .get("ChatGPT-Account-ID")
                .map(String::as_str),
            Some("acct-456")
        );
        assert_eq!(
            binding.models_source_override.as_deref(),
            Some(OpenAIOAuthDriver::codex_models_source().as_str())
        );
        assert!(!binding.disable_default_auth);
    }
}
