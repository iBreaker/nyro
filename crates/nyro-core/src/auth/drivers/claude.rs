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

const CLAUDE_AUTHORIZE_URL: &str = "https://claude.ai/oauth/authorize";
const CLAUDE_TOKEN_URL: &str = "https://console.anthropic.com/v1/oauth/token";
const CLAUDE_CLIENT_ID: &str = "9d1c250a-e61b-44d9-88ed-5944d1962f5e";
const CLAUDE_REDIRECT_URI: &str = "https://platform.claude.com/oauth/code/callback";
const CLAUDE_SCOPE: &str =
    "org:create_api_key user:profile user:inference user:sessions:claude_code";
const CLAUDE_SETUP_SCOPE: &str = "user:inference";
const CLAUDE_API_BASE_URL: &str = "https://api.anthropic.com";
const CLAUDE_MODELS_URL: &str = "https://api.anthropic.com/v1/models";
const CLAUDE_OAUTH_BETA: &str = "oauth-2025-04-20";

#[derive(Debug, Default)]
pub struct ClaudeDriver;

#[derive(Debug, Default)]
pub struct ClaudeSetupTokenDriver;

#[derive(Debug, Deserialize)]
struct ClaudeTokenResponse {
    access_token: Option<String>,
    refresh_token: Option<String>,
    expires_in: Option<i64>,
    scope: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ClaudeErrorResponse {
    error: Option<String>,
    error_description: Option<String>,
    message: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ClaudeSessionState {
    #[serde(flatten)]
    pkce: PkceAuthState,
    scope: String,
}

#[derive(Debug, Clone, Copy)]
struct ClaudeConfig {
    key: &'static str,
    label: &'static str,
    scope: &'static str,
}

impl ClaudeConfig {
    const fn standard() -> Self {
        Self {
            key: "claude",
            label: "Claude",
            scope: CLAUDE_SCOPE,
        }
    }

    const fn setup_token() -> Self {
        Self {
            key: "claude-setup-token",
            label: "Claude Setup Token",
            scope: CLAUDE_SETUP_SCOPE,
        }
    }
}

impl ClaudeDriver {
    fn config(&self) -> ClaudeConfig {
        ClaudeConfig::standard()
    }
}

impl ClaudeSetupTokenDriver {
    fn config(&self) -> ClaudeConfig {
        ClaudeConfig::setup_token()
    }
}

fn metadata(config: ClaudeConfig) -> AuthDriverMetadata {
    AuthDriverMetadata {
        key: config.key,
        label: config.label,
        scheme: AuthScheme::OAuthAuthCodePkce,
        supports_new_provider: true,
        supports_existing_provider: true,
    }
}

fn normalize_token_response(
    body: &str,
    fallback_refresh_token: Option<&str>,
) -> Result<CredentialBundle> {
    let token: ClaudeTokenResponse =
        serde_json::from_str(body).context("parse claude token response")?;
    let access_token = token
        .access_token
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| anyhow!("claude token response missing access_token"))?;
    let expires_in = token.expires_in.unwrap_or(3600).max(1);

    Ok(CredentialBundle {
        access_token: Some(access_token),
        refresh_token: token
            .refresh_token
            .filter(|value| !value.trim().is_empty())
            .or_else(|| fallback_refresh_token.map(ToString::to_string)),
        expires_at: Some(expires_at_after(expires_in)),
        resource_url: Some(CLAUDE_API_BASE_URL.to_string()),
        subject_id: None,
        scopes: encode_scopes(token.scope.as_deref()),
        raw: serde_json::from_str(body).unwrap_or(serde_json::Value::Null),
    })
}

fn parse_error_response(body: &str) -> Option<String> {
    let parsed: ClaudeErrorResponse = serde_json::from_str(body).ok()?;
    parsed
        .error_description
        .filter(|value| !value.trim().is_empty())
        .or_else(|| parsed.message.filter(|value| !value.trim().is_empty()))
        .or_else(|| parsed.error.filter(|value| !value.trim().is_empty()))
}

async fn start(config: ClaudeConfig, ctx: StartAuthContext) -> Result<CreateAuthSession> {
    let code_verifier = generate_code_verifier();
    let code_challenge = generate_code_challenge(&code_verifier);
    let state = generate_state();
    let auth_url = build_authorize_url(
        CLAUDE_AUTHORIZE_URL,
        &[
            ("code", "true"),
            ("client_id", CLAUDE_CLIENT_ID),
            ("response_type", "code"),
            ("redirect_uri", CLAUDE_REDIRECT_URI),
            ("scope", config.scope),
            ("code_challenge", &code_challenge),
            ("code_challenge_method", "S256"),
            ("state", &state),
        ],
    )?;
    let session_state = serde_json::to_string(&ClaudeSessionState {
        pkce: PkceAuthState {
            code_verifier,
            state,
            redirect_uri: CLAUDE_REDIRECT_URI.to_string(),
        },
        scope: config.scope.to_string(),
    })?;

    Ok(CreateAuthSession {
        provider_id: ctx.provider_id,
        driver_key: config.key.to_string(),
        scheme: AuthScheme::OAuthAuthCodePkce.as_str().to_string(),
        status: "pending".to_string(),
        use_proxy: ctx.use_proxy,
        user_code: None,
        verification_uri: Some(CLAUDE_AUTHORIZE_URL.to_string()),
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
    session: &AuthSession,
    input: AuthExchangeInput,
    ctx: ExchangeAuthContext,
) -> Result<CredentialBundle> {
    let state: ClaudeSessionState = parse_session_state(session)?;
    let callback = parse_oauth_callback(&input)?;
    validate_callback_state(&state.pkce.state, callback.state.as_deref(), "claude")?;
    let code = callback
        .code
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| anyhow!("missing authorization code"))?;

    let client = required_http_client(ctx.http_client)?;
    let response = client
        .post(CLAUDE_TOKEN_URL)
        .header(CONTENT_TYPE, "application/json")
        .header(ACCEPT, "application/json, text/plain, */*")
        .header("User-Agent", "claude-cli/1.0.56 (external, cli)")
        .header("Accept-Language", "en-US,en;q=0.9")
        .header("Referer", "https://claude.ai/")
        .header("Origin", "https://claude.ai")
        .json(&serde_json::json!({
            "grant_type": "authorization_code",
            "client_id": CLAUDE_CLIENT_ID,
            "code": code,
            "redirect_uri": state.pkce.redirect_uri,
            "code_verifier": state.pkce.code_verifier,
            "state": state.pkce.state,
        }))
        .send()
        .await
        .context("exchange claude authorization code")?;

    let status = response.status();
    let body = response.text().await.unwrap_or_default();
    if !status.is_success() {
        let detail = parse_error_response(&body).unwrap_or(body);
        bail!("claude token exchange failed: HTTP {status} {detail}");
    }

    normalize_token_response(&body, None)
}

async fn refresh(
    credential: &StoredCredential,
    ctx: RefreshAuthContext,
) -> Result<CredentialBundle> {
    let refresh_token = credential
        .refresh_token
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| anyhow!("claude refresh token is missing"))?;
    let client = required_http_client(ctx.http_client)?;

    let response = client
        .post(CLAUDE_TOKEN_URL)
        .header(CONTENT_TYPE, "application/json")
        .header(ACCEPT, "application/json, text/plain, */*")
        .header("User-Agent", "claude-cli/1.0.56 (external, cli)")
        .header("Accept-Language", "en-US,en;q=0.9")
        .header("Referer", "https://claude.ai/")
        .header("Origin", "https://claude.ai")
        .json(&serde_json::json!({
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": CLAUDE_CLIENT_ID,
        }))
        .send()
        .await
        .context("refresh claude access token")?;

    let status = response.status();
    let body = response.text().await.unwrap_or_default();
    if !status.is_success() {
        let detail = parse_error_response(&body).unwrap_or(body);
        bail!("claude token refresh failed: HTTP {status} {detail}");
    }

    normalize_token_response(&body, Some(refresh_token))
}

fn bind_runtime(_provider: &Provider, credential: &StoredCredential) -> Result<RuntimeBinding> {
    let access_token = credential
        .access_token
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| anyhow!("claude access token is missing"))?;

    let mut extra_headers = HashMap::new();
    extra_headers.insert(
        "Authorization".to_string(),
        format!("Bearer {access_token}"),
    );
    extra_headers.insert("anthropic-version".to_string(), "2023-06-01".to_string());
    extra_headers.insert("anthropic-beta".to_string(), CLAUDE_OAUTH_BETA.to_string());

    Ok(RuntimeBinding {
        base_url_override: Some(CLAUDE_API_BASE_URL.to_string()),
        extra_headers,
        model_aliases: HashMap::new(),
        models_source_override: Some(CLAUDE_MODELS_URL.to_string()),
        capabilities_source_override: Some("ai://models.dev/anthropic".to_string()),
        disable_default_auth: true,
    })
}

#[async_trait]
impl AuthDriver for ClaudeDriver {
    fn metadata(&self) -> AuthDriverMetadata {
        metadata(self.config())
    }

    async fn start(&self, ctx: StartAuthContext) -> Result<CreateAuthSession> {
        start(self.config(), ctx).await
    }

    async fn exchange(
        &self,
        session: &AuthSession,
        input: AuthExchangeInput,
        ctx: ExchangeAuthContext,
    ) -> Result<CredentialBundle> {
        exchange(session, input, ctx).await
    }

    async fn refresh(
        &self,
        credential: &StoredCredential,
        ctx: RefreshAuthContext,
    ) -> Result<CredentialBundle> {
        refresh(credential, ctx).await
    }

    fn bind_runtime(
        &self,
        provider: &Provider,
        credential: &StoredCredential,
    ) -> Result<RuntimeBinding> {
        bind_runtime(provider, credential)
    }
}

#[async_trait]
impl AuthDriver for ClaudeSetupTokenDriver {
    fn metadata(&self) -> AuthDriverMetadata {
        metadata(self.config())
    }

    async fn start(&self, ctx: StartAuthContext) -> Result<CreateAuthSession> {
        start(self.config(), ctx).await
    }

    async fn exchange(
        &self,
        session: &AuthSession,
        input: AuthExchangeInput,
        ctx: ExchangeAuthContext,
    ) -> Result<CredentialBundle> {
        exchange(session, input, ctx).await
    }

    async fn refresh(
        &self,
        credential: &StoredCredential,
        ctx: RefreshAuthContext,
    ) -> Result<CredentialBundle> {
        refresh(credential, ctx).await
    }

    fn bind_runtime(
        &self,
        provider: &Provider,
        credential: &StoredCredential,
    ) -> Result<RuntimeBinding> {
        bind_runtime(provider, credential)
    }
}
