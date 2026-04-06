use std::collections::HashMap;

use anyhow::{Context, Result, anyhow, bail};
use async_trait::async_trait;
use base64::Engine;
use chrono::{Duration, Utc};
use rand::RngCore;
use reqwest::header::{ACCEPT, CONTENT_TYPE};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::auth::types::{
    AuthDriver, AuthDriverMetadata, AuthPollState, AuthProgress, AuthScheme, AuthSession,
    CreateAuthSession, CredentialBundle, RefreshAuthContext, RuntimeBinding, StartAuthContext,
    StoredCredential,
};
use crate::db::models::Provider;

const QWEN_OAUTH_BASE_URL: &str = "https://chat.qwen.ai";
const QWEN_OAUTH_DEVICE_CODE_ENDPOINT: &str = "https://chat.qwen.ai/api/v1/oauth2/device/code";
const QWEN_OAUTH_TOKEN_ENDPOINT: &str = "https://chat.qwen.ai/api/v1/oauth2/token";
const QWEN_OAUTH_CLIENT_ID: &str = "f0304373b74a44d2b584a3fb70ca9e56";
const QWEN_OAUTH_SCOPE: &str = "openid profile email model.completion";
const QWEN_DEVICE_GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:device_code";

#[derive(Debug, Default)]
pub struct QwenCodeCliDriver;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct QwenDeviceState {
    device_code: String,
    code_verifier: String,
}

#[derive(Debug, Deserialize)]
struct QwenDeviceAuthorizationResponse {
    device_code: String,
    user_code: String,
    verification_uri: String,
    verification_uri_complete: String,
    expires_in: i64,
}

#[derive(Debug, Deserialize)]
struct QwenErrorResponse {
    error: String,
    error_description: Option<String>,
}

#[derive(Debug)]
struct ParsedQwenTokenResponse {
    access_token: String,
    refresh_token: Option<String>,
    expires_in: i64,
    scope: Option<String>,
    resource_url: Option<String>,
    raw: Value,
}

impl QwenCodeCliDriver {
    fn normalize_runtime_base_url(resource_url: &str) -> Option<String> {
        let trimmed = resource_url.trim();
        if trimmed.is_empty() {
            return None;
        }
        let with_scheme = if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
            trimmed.to_string()
        } else {
            format!("https://{trimmed}")
        };
        let normalized = with_scheme.trim_end_matches('/').to_string();
        if normalized.ends_with("/v1") {
            Some(normalized)
        } else {
            Some(format!("{normalized}/v1"))
        }
    }

    fn expires_at_after(seconds: i64) -> String {
        (Utc::now() + Duration::seconds(seconds.max(1)))
            .format("%Y-%m-%d %H:%M:%S")
            .to_string()
    }

    fn encode_scopes(scope: Option<&str>) -> Vec<String> {
        scope
            .unwrap_or("")
            .split_whitespace()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToString::to_string)
            .collect()
    }

    fn generate_code_verifier() -> String {
        let mut bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut bytes);
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
    }

    fn generate_code_challenge(code_verifier: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(code_verifier.as_bytes());
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hasher.finalize())
    }

    fn parse_state(session: &AuthSession) -> Result<QwenDeviceState> {
        let raw = session
            .state_json
            .as_deref()
            .context("auth session missing state_json")?;
        serde_json::from_str(raw).context("parse qwen auth session state")
    }

    fn parse_error_response(body: &str) -> Option<QwenErrorResponse> {
        serde_json::from_str(body).ok()
    }

    fn parse_optional_string(value: Option<&Value>) -> Option<String> {
        value
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToString::to_string)
    }

    fn parse_optional_i64(value: Option<&Value>) -> Option<i64> {
        value
            .and_then(|value| match value {
                Value::Number(number) => number.as_i64(),
                Value::String(text) => text.trim().parse::<i64>().ok(),
                _ => None,
            })
            .filter(|value| *value > 0)
    }

    fn parse_token_response(body: &str, context: &str) -> Result<ParsedQwenTokenResponse> {
        let raw: Value = serde_json::from_str(body).with_context(|| context.to_string())?;
        let payload = raw.get("data").unwrap_or(&raw);
        let access_token = Self::parse_optional_string(payload.get("access_token"))
            .ok_or_else(|| anyhow!("qwen token response missing access_token"))?;

        Ok(ParsedQwenTokenResponse {
            access_token,
            refresh_token: Self::parse_optional_string(payload.get("refresh_token")),
            expires_in: Self::parse_optional_i64(payload.get("expires_in")).unwrap_or(3600),
            scope: Self::parse_optional_string(payload.get("scope")),
            resource_url: Self::parse_optional_string(payload.get("resource_url"))
                .or_else(|| Self::parse_optional_string(payload.get("endpoint"))),
            raw,
        })
    }

    fn build_http_client(ctx: &StartAuthContext) -> Result<reqwest::Client> {
        ctx.http_client
            .clone()
            .ok_or_else(|| anyhow!("missing auth http client"))
    }

    fn build_refresh_client(ctx: &RefreshAuthContext) -> Result<reqwest::Client> {
        ctx.http_client
            .clone()
            .ok_or_else(|| anyhow!("missing auth http client"))
    }
}

#[async_trait]
impl AuthDriver for QwenCodeCliDriver {
    fn metadata(&self) -> AuthDriverMetadata {
        AuthDriverMetadata {
            key: "qwen-code-cli",
            label: "Qwen Code",
            scheme: AuthScheme::OAuthDeviceCode,
            supports_new_provider: true,
            supports_existing_provider: true,
        }
    }

    async fn start(&self, ctx: StartAuthContext) -> Result<CreateAuthSession> {
        let code_verifier = Self::generate_code_verifier();
        let code_challenge = Self::generate_code_challenge(&code_verifier);
        let client = Self::build_http_client(&ctx)?;

        let response = client
            .post(QWEN_OAUTH_DEVICE_CODE_ENDPOINT)
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(ACCEPT, "application/json")
            .header("x-request-id", Uuid::new_v4().to_string())
            .form(&[
                ("client_id", QWEN_OAUTH_CLIENT_ID),
                ("scope", QWEN_OAUTH_SCOPE),
                ("code_challenge", code_challenge.as_str()),
                ("code_challenge_method", "S256"),
            ])
            .send()
            .await
            .context("request qwen device authorization")?;

        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        if !status.is_success() {
            bail!("qwen device authorization failed: HTTP {status} {body}");
        }

        let device: QwenDeviceAuthorizationResponse =
            serde_json::from_str(&body).context("parse qwen device authorization response")?;
        let state = serde_json::to_string(&QwenDeviceState {
            device_code: device.device_code,
            code_verifier,
        })?;

        Ok(CreateAuthSession {
            provider_id: ctx.provider_id,
            driver_key: self.metadata().key.to_string(),
            scheme: self.metadata().scheme.as_str().to_string(),
            status: "pending".to_string(),
            use_proxy: ctx.use_proxy,
            user_code: Some(device.user_code),
            verification_uri: Some(device.verification_uri),
            verification_uri_complete: Some(device.verification_uri_complete),
            state_json: Some(state),
            context_json: None,
            result_json: None,
            expires_at: Some(Self::expires_at_after(device.expires_in)),
            poll_interval_seconds: Some(2),
            last_error: None,
        })
    }

    async fn poll(&self, session: &AuthSession, ctx: RefreshAuthContext) -> Result<AuthPollState> {
        let state = Self::parse_state(session)?;
        let client = Self::build_refresh_client(&ctx)?;

        let response = client
            .post(QWEN_OAUTH_TOKEN_ENDPOINT)
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(ACCEPT, "application/json")
            .form(&[
                ("grant_type", QWEN_DEVICE_GRANT_TYPE),
                ("client_id", QWEN_OAUTH_CLIENT_ID),
                ("device_code", state.device_code.as_str()),
                ("code_verifier", state.code_verifier.as_str()),
            ])
            .send()
            .await
            .context("poll qwen device token")?;

        let status = response.status();
        let body = response.text().await.unwrap_or_default();

        if status.is_success() {
            let token = Self::parse_token_response(&body, "parse qwen token response")?;
            return Ok(AuthPollState::Ready(CredentialBundle {
                access_token: Some(token.access_token),
                refresh_token: token.refresh_token,
                expires_at: Some(Self::expires_at_after(token.expires_in)),
                resource_url: token.resource_url,
                subject_id: None,
                scopes: Self::encode_scopes(token.scope.as_deref()),
                raw: token.raw,
            }));
        }

        let error = Self::parse_error_response(&body);
        if status == reqwest::StatusCode::BAD_REQUEST
            && error
                .as_ref()
                .is_some_and(|value| value.error == "authorization_pending")
        {
            return Ok(AuthPollState::Pending(AuthProgress {
                user_code: session.user_code.clone(),
                verification_uri: session.verification_uri.clone(),
                verification_uri_complete: session.verification_uri_complete.clone(),
                expires_at: session.expires_at.clone(),
                poll_interval_seconds: session.poll_interval_seconds,
            }));
        }

        if status == reqwest::StatusCode::TOO_MANY_REQUESTS
            && error
                .as_ref()
                .is_some_and(|value| value.error == "slow_down")
        {
            let next_interval = session.poll_interval_seconds.unwrap_or(2).saturating_add(1);
            return Ok(AuthPollState::Pending(AuthProgress {
                user_code: session.user_code.clone(),
                verification_uri: session.verification_uri.clone(),
                verification_uri_complete: session.verification_uri_complete.clone(),
                expires_at: session.expires_at.clone(),
                poll_interval_seconds: Some(next_interval),
            }));
        }

        if let Some(error) = error {
            let message = error
                .error_description
                .filter(|value| !value.trim().is_empty())
                .unwrap_or_else(|| error.error.clone());
            return Ok(AuthPollState::Error {
                code: error.error,
                message,
            });
        }

        bail!("qwen device token poll failed: HTTP {status} {body}");
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
            .ok_or_else(|| anyhow!("qwen refresh token is missing"))?;
        let client = Self::build_refresh_client(&ctx)?;

        let response = client
            .post(QWEN_OAUTH_TOKEN_ENDPOINT)
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(ACCEPT, "application/json")
            .form(&[
                ("grant_type", "refresh_token"),
                ("refresh_token", refresh_token),
                ("client_id", QWEN_OAUTH_CLIENT_ID),
            ])
            .send()
            .await
            .context("refresh qwen access token")?;

        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        if !status.is_success() {
            if let Some(error) = Self::parse_error_response(&body) {
                let message = error
                    .error_description
                    .filter(|value| !value.trim().is_empty())
                    .unwrap_or_else(|| error.error.clone());
                bail!("qwen token refresh failed: {} - {}", error.error, message);
            }
            bail!("qwen token refresh failed: HTTP {status} {body}");
        }

        let token = Self::parse_token_response(&body, "parse qwen refresh token response")?;

        Ok(CredentialBundle {
            access_token: Some(token.access_token),
            refresh_token: Some(
                token
                    .refresh_token
                    .unwrap_or_else(|| refresh_token.to_string()),
            ),
            expires_at: Some(Self::expires_at_after(token.expires_in)),
            resource_url: token
                .resource_url
                .or_else(|| credential.resource_url.clone()),
            subject_id: credential.subject_id.clone(),
            scopes: if token.scope.is_some() {
                Self::encode_scopes(token.scope.as_deref())
            } else {
                credential.scopes.clone()
            },
            raw: token.raw,
        })
    }

    fn bind_runtime(
        &self,
        _provider: &Provider,
        credential: &StoredCredential,
    ) -> Result<RuntimeBinding> {
        let mut extra_headers = HashMap::new();
        extra_headers.insert("X-DashScope-AuthType".to_string(), "qwen-oauth".to_string());

        let mut model_aliases = HashMap::new();
        model_aliases.insert("*".to_string(), "coder-model".to_string());

        Ok(RuntimeBinding {
            base_url_override: credential
                .resource_url
                .as_deref()
                .and_then(Self::normalize_runtime_base_url),
            extra_headers,
            model_aliases,
            models_source_override: None,
            capabilities_source_override: if credential.resource_url.is_some() {
                Some(format!("{QWEN_OAUTH_BASE_URL}/api/models"))
            } else {
                None
            },
            disable_default_auth: false,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::QwenCodeCliDriver;
    use crate::auth::types::{AuthDriver, StoredCredential};

    #[test]
    fn normalizes_runtime_base_url() {
        assert_eq!(
            QwenCodeCliDriver::normalize_runtime_base_url("portal.qwen.ai"),
            Some("https://portal.qwen.ai/v1".to_string())
        );
        assert_eq!(
            QwenCodeCliDriver::normalize_runtime_base_url("https://portal.qwen.ai/v1"),
            Some("https://portal.qwen.ai/v1".to_string())
        );
    }

    #[test]
    fn parses_minimal_token_response_without_token_type() {
        let parsed = QwenCodeCliDriver::parse_token_response(
            r#"{"access_token":"token-123","expires_in":7200}"#,
            "parse qwen token response",
        )
        .expect("minimal qwen token response");

        assert_eq!(parsed.access_token, "token-123");
        assert_eq!(parsed.expires_in, 7200);
        assert_eq!(parsed.refresh_token, None);
        assert_eq!(parsed.resource_url, None);
    }

    #[test]
    fn parses_endpoint_as_resource_url() {
        let parsed = QwenCodeCliDriver::parse_token_response(
            r#"{"access_token":"token-123","endpoint":"https://portal.qwen.ai","scope":"openid profile"}"#,
            "parse qwen token response",
        )
        .expect("endpoint alias should parse");

        assert_eq!(
            parsed.resource_url.as_deref(),
            Some("https://portal.qwen.ai")
        );
        assert_eq!(parsed.scope.as_deref(), Some("openid profile"));
    }

    #[test]
    fn parses_nested_token_payload() {
        let parsed = QwenCodeCliDriver::parse_token_response(
            r#"{"data":{"access_token":"token-456","expires_in":"3600","resource_url":"https://portal.qwen.ai/v1"}}"#,
            "parse qwen token response",
        )
        .expect("nested token payload should parse");

        assert_eq!(parsed.access_token, "token-456");
        assert_eq!(parsed.expires_in, 3600);
        assert_eq!(
            parsed.resource_url.as_deref(),
            Some("https://portal.qwen.ai/v1")
        );
    }

    #[test]
    fn rejects_success_response_without_access_token() {
        let error = QwenCodeCliDriver::parse_token_response(
            r#"{"token_type":"Bearer"}"#,
            "parse qwen token response",
        )
        .expect_err("missing access_token should fail");

        assert!(error.to_string().contains("missing access_token"));
    }

    #[test]
    fn builds_runtime_binding_from_resource_url() {
        let binding = QwenCodeCliDriver
            .bind_runtime(
                &crate::db::models::Provider {
                    id: "provider".to_string(),
                    name: "Qwen Code".to_string(),
                    vendor: Some("qwen-code-cli".to_string()),
                    protocol: "openai".to_string(),
                    base_url: "https://portal.qwen.ai/v1".to_string(),
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
                &StoredCredential {
                    resource_url: Some("portal.qwen.ai".to_string()),
                    ..Default::default()
                },
            )
            .expect("runtime binding should succeed");

        assert_eq!(
            binding.base_url_override.as_deref(),
            Some("https://portal.qwen.ai/v1")
        );
        assert_eq!(
            binding
                .extra_headers
                .get("X-DashScope-AuthType")
                .map(String::as_str),
            Some("qwen-oauth")
        );
        assert_eq!(
            binding.capabilities_source_override.as_deref(),
            Some("https://chat.qwen.ai/api/models")
        );
        assert_eq!(
            binding.model_aliases.get("*").map(String::as_str),
            Some("coder-model")
        );
    }
}
