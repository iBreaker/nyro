use std::collections::HashMap;

use anyhow::{Context, Result, anyhow, bail};
use async_trait::async_trait;
use reqwest::header::{ACCEPT, CONTENT_TYPE};
use serde::{Deserialize, Serialize};

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

const GOOGLE_AUTHORIZE_URL: &str = "https://accounts.google.com/o/oauth2/v2/auth";
const GOOGLE_TOKEN_URL: &str = "https://oauth2.googleapis.com/token";
const GOOGLE_GEMINI_CLIENT_ID: &str =
    "681255809395-oo8ft2oprdrnp9e3aqf6av3hmdib135j.apps.googleusercontent.com";
const GOOGLE_GEMINI_CLIENT_SECRET: &str = "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";
const GOOGLE_GEMINI_SCOPE: &str = "https://www.googleapis.com/auth/cloud-platform";
const GOOGLE_GEMINI_REDIRECT_URI: &str = "https://codeassist.google.com/authcode";
const CLOUD_CODE_API_BASE_URL: &str = "https://cloudcode-pa.googleapis.com/v1internal";

#[derive(Debug, Default)]
pub struct GeminiCliDriver;

#[derive(Debug, Deserialize)]
struct GoogleTokenResponse {
    access_token: Option<String>,
    refresh_token: Option<String>,
    expires_in: Option<i64>,
    scope: Option<String>,
}

#[derive(Debug, Deserialize)]
struct GoogleErrorResponse {
    error: Option<String>,
    error_description: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct GeminiAuthState {
    #[serde(flatten)]
    pkce: PkceAuthState,
}

impl GeminiCliDriver {
    fn normalize_token_response(
        body: &str,
        fallback_refresh_token: Option<&str>,
    ) -> Result<CredentialBundle> {
        let token: GoogleTokenResponse =
            serde_json::from_str(body).context("parse google oauth token response")?;
        let access_token = token
            .access_token
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| anyhow!("google oauth token response missing access_token"))?;
        let expires_in = token.expires_in.unwrap_or(3600).max(1);
        let scope = token
            .scope
            .clone()
            .unwrap_or_else(|| GOOGLE_GEMINI_SCOPE.to_string());

        Ok(CredentialBundle {
            access_token: Some(access_token),
            refresh_token: token
                .refresh_token
                .filter(|value| !value.trim().is_empty())
                .or_else(|| fallback_refresh_token.map(ToString::to_string)),
            expires_at: Some(expires_at_after(expires_in)),
            resource_url: Some(CLOUD_CODE_API_BASE_URL.to_string()),
            subject_id: None,
            scopes: encode_scopes(Some(&scope)),
            raw: serde_json::from_str(body).unwrap_or(serde_json::Value::Null),
        })
    }

    fn parse_error(body: &str) -> Option<String> {
        let parsed: GoogleErrorResponse = serde_json::from_str(body).ok()?;
        parsed
            .error_description
            .filter(|value| !value.trim().is_empty())
            .or_else(|| parsed.error.filter(|value| !value.trim().is_empty()))
    }
}

#[async_trait]
impl AuthDriver for GeminiCliDriver {
    fn metadata(&self) -> AuthDriverMetadata {
        AuthDriverMetadata {
            key: "gemini-cli",
            label: "Gemini CLI",
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
            GOOGLE_AUTHORIZE_URL,
            &[
                ("response_type", "code"),
                ("client_id", GOOGLE_GEMINI_CLIENT_ID),
                ("redirect_uri", GOOGLE_GEMINI_REDIRECT_URI),
                ("scope", GOOGLE_GEMINI_SCOPE),
                ("access_type", "offline"),
                ("prompt", "select_account"),
                ("code_challenge_method", "S256"),
                ("code_challenge", &code_challenge),
                ("state", &state),
            ],
        )?;
        let session_state = serde_json::to_string(&GeminiAuthState {
            pkce: PkceAuthState {
                code_verifier,
                state,
                redirect_uri: GOOGLE_GEMINI_REDIRECT_URI.to_string(),
            },
        })?;

        Ok(CreateAuthSession {
            provider_id: ctx.provider_id,
            driver_key: self.metadata().key.to_string(),
            scheme: self.metadata().scheme.as_str().to_string(),
            status: "pending".to_string(),
            use_proxy: ctx.use_proxy,
            user_code: None,
            verification_uri: Some("https://accounts.google.com".to_string()),
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
        let state: GeminiAuthState = parse_session_state(session)?;
        let callback = parse_oauth_callback(&input)?;
        validate_callback_state(&state.pkce.state, callback.state.as_deref(), "google")?;
        let code = callback
            .code
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| anyhow!("missing authorization code"))?;

        let client = required_http_client(ctx.http_client)?;
        let response = client
            .post(GOOGLE_TOKEN_URL)
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(ACCEPT, "application/json")
            .form(&[
                ("grant_type", "authorization_code"),
                ("code", code),
                ("client_id", GOOGLE_GEMINI_CLIENT_ID),
                ("client_secret", GOOGLE_GEMINI_CLIENT_SECRET),
                ("redirect_uri", state.pkce.redirect_uri.as_str()),
                ("code_verifier", state.pkce.code_verifier.as_str()),
            ])
            .send()
            .await
            .context("exchange google authorization code")?;

        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        if !status.is_success() {
            let detail = Self::parse_error(&body).unwrap_or(body);
            bail!("google oauth token exchange failed: HTTP {status} {detail}");
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
            .ok_or_else(|| anyhow!("google oauth refresh token is missing"))?;
        let client = required_http_client(ctx.http_client)?;

        let response = client
            .post(GOOGLE_TOKEN_URL)
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(ACCEPT, "application/json")
            .form(&[
                ("grant_type", "refresh_token"),
                ("client_id", GOOGLE_GEMINI_CLIENT_ID),
                ("client_secret", GOOGLE_GEMINI_CLIENT_SECRET),
                ("refresh_token", refresh_token),
            ])
            .send()
            .await
            .context("refresh google oauth token")?;

        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        if !status.is_success() {
            let detail = Self::parse_error(&body).unwrap_or(body);
            bail!("google oauth token refresh failed: HTTP {status} {detail}");
        }

        Self::normalize_token_response(&body, Some(refresh_token))
    }

    fn bind_runtime(
        &self,
        _provider: &Provider,
        credential: &StoredCredential,
    ) -> Result<RuntimeBinding> {
        let access_token = credential
            .access_token
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| anyhow!("google oauth access token is missing"))?;

        let mut extra_headers = HashMap::new();
        extra_headers.insert(
            "Authorization".to_string(),
            format!("Bearer {access_token}"),
        );

        Ok(RuntimeBinding {
            base_url_override: Some(CLOUD_CODE_API_BASE_URL.to_string()),
            extra_headers,
            model_aliases: HashMap::new(),
            models_source_override: None,
            capabilities_source_override: Some("ai://models.dev/google".to_string()),
            disable_default_auth: true,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{CLOUD_CODE_API_BASE_URL, GOOGLE_GEMINI_SCOPE, GeminiCliDriver};
    use crate::auth::types::{AuthDriver, StoredCredential};

    #[test]
    fn normalize_token_response_uses_cloud_code_runtime_defaults() {
        let bundle = GeminiCliDriver::normalize_token_response(
            r#"{"access_token":"ya29.token","refresh_token":"refresh-123","expires_in":7200}"#,
            None,
        )
        .expect("google token response should parse");

        assert_eq!(bundle.access_token.as_deref(), Some("ya29.token"));
        assert_eq!(bundle.refresh_token.as_deref(), Some("refresh-123"));
        assert_eq!(
            bundle.resource_url.as_deref(),
            Some(CLOUD_CODE_API_BASE_URL)
        );
        assert_eq!(bundle.scopes, vec![GOOGLE_GEMINI_SCOPE.to_string()]);
    }

    #[test]
    fn builds_cloud_code_runtime_binding() {
        let binding = GeminiCliDriver
            .bind_runtime(
                &crate::db::models::Provider {
                    id: "provider".to_string(),
                    name: "Cloud Code".to_string(),
                    vendor: Some("cloud-code".to_string()),
                    protocol: "gemini".to_string(),
                    base_url: CLOUD_CODE_API_BASE_URL.to_string(),
                    default_protocol: "gemini".to_string(),
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
                &StoredCredential {
                    access_token: Some("ya29.token".to_string()),
                    ..Default::default()
                },
            )
            .expect("runtime binding should succeed");

        assert_eq!(
            binding.base_url_override.as_deref(),
            Some(CLOUD_CODE_API_BASE_URL)
        );
        assert_eq!(binding.models_source_override, None);
        assert_eq!(
            binding
                .extra_headers
                .get("Authorization")
                .map(String::as_str),
            Some("Bearer ya29.token")
        );
        assert!(binding.disable_default_auth);
    }
}
