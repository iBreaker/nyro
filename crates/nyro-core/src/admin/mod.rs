use anyhow::Context;
use chrono::{DateTime, NaiveDateTime, Utc};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use reqwest::header::{AUTHORIZATION, HeaderMap, HeaderValue};
use serde::Serialize;
use serde_json::Value;

use crate::Gateway;
use crate::auth;
use crate::auth::types::{
    AuthBindingStatus, AuthPollState, AuthScheme, AuthSession, AuthSessionInitData,
    AuthSessionStatus, AuthSessionStatusData, CredentialBundle, ExchangeAuthContext,
    RefreshAuthContext, RuntimeBinding, StartAuthContext, StoredCredential, UpdateAuthSession,
    UpsertProviderAuthBinding,
};
use crate::db::models::*;
use crate::storage::traits::ProviderTestResult;

const MODELS_DEV_SNAPSHOT: &str = include_str!("../../assets/models.dev.json");
const PROVIDER_PRESETS_SNAPSHOT: &str = include_str!("../../assets/providers.json");
const MODELS_DEV_RUNTIME_FILE: &str = "models.dev.json";
const MODELS_DEV_SOURCE_URL: &str = "https://models.dev/api.json";
const MODELS_DEV_RUNTIME_TTL: Duration = Duration::from_secs(24 * 60 * 60);

#[derive(Clone)]
pub struct AdminService {
    gw: Gateway,
}

struct ResolvedAdminProviderRuntime {
    access_token: String,
    binding: RuntimeBinding,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProviderOAuthStatusData {
    pub provider_id: String,
    pub provider_name: String,
    pub driver_key: String,
    pub status: String,
    pub expires_at: Option<String>,
    pub resource_url: Option<String>,
    pub subject_id: Option<String>,
    pub last_error: Option<String>,
    pub updated_at: Option<String>,
    pub has_refresh_token: bool,
}

impl AdminService {
    pub fn new(gw: Gateway) -> Self {
        Self { gw }
    }

    // ── Providers ──

    pub async fn list_providers(&self) -> anyhow::Result<Vec<Provider>> {
        self.gw.storage.providers().list().await
    }

    pub async fn list_provider_presets(&self) -> anyhow::Result<Vec<Value>> {
        parse_provider_presets_snapshot()
    }

    pub async fn get_provider(&self, id: &str) -> anyhow::Result<Provider> {
        self.gw
            .storage
            .providers()
            .get(id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("provider not found: {id}"))
    }

    pub async fn init_oauth_session(
        &self,
        vendor: &str,
        use_proxy: bool,
    ) -> anyhow::Result<AuthSessionInitData> {
        let driver_key = auth::normalize_driver_key(vendor);
        if driver_key.is_empty() {
            anyhow::bail!("auth vendor cannot be empty");
        }
        let driver = auth::build_driver(&driver_key)
            .ok_or_else(|| anyhow::anyhow!("auth vendor not implemented: {driver_key}"))?;
        let client = self.gw.http_client_for_provider(use_proxy).await?;
        let created = driver
            .start(StartAuthContext {
                use_proxy,
                http_client: Some(client),
                ..Default::default()
            })
            .await?;
        let session = self.auth_sessions_store()?.create(created).await?;
        build_auth_session_init_data(&session)
    }

    pub async fn get_oauth_session_status(
        &self,
        session_id: &str,
    ) -> anyhow::Result<AuthSessionStatusData> {
        let store = self.auth_sessions_store()?;
        let session = store
            .get(session_id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("auth session not found: {session_id}"))?;

        match session.status.as_str() {
            "ready" => {
                let bundle = parse_auth_session_bundle(&session)?;
                return Ok(build_auth_session_ready_data(&session, &bundle));
            }
            "error" => {
                return Ok(AuthSessionStatusData::Error {
                    code: "AUTH_SESSION_ERROR".to_string(),
                    message: session
                        .last_error
                        .filter(|value| !value.trim().is_empty())
                        .unwrap_or_else(|| "auth session failed".to_string()),
                });
            }
            "cancelled" => {
                return Ok(AuthSessionStatusData::Error {
                    code: "AUTH_SESSION_CANCELLED".to_string(),
                    message: "auth session cancelled".to_string(),
                });
            }
            _ => {}
        }

        if is_expired_at(session.expires_at.as_deref()) {
            let updated = store
                .update(
                    &session.id,
                    UpdateAuthSession {
                        status: Some(AuthSessionStatus::Error.as_str().to_string()),
                        last_error: Some("auth session expired".to_string()),
                        ..Default::default()
                    },
                )
                .await?;
            return Ok(AuthSessionStatusData::Error {
                code: "AUTH_TIMEOUT".to_string(),
                message: updated
                    .last_error
                    .unwrap_or_else(|| "auth session expired".to_string()),
            });
        }

        if session.scheme == AuthScheme::OAuthAuthCodePkce.as_str()
            || session.scheme == AuthScheme::SetupToken.as_str()
        {
            return Ok(build_auth_session_pending_data(&session));
        }

        let driver = auth::build_driver(&session.driver_key).ok_or_else(|| {
            anyhow::anyhow!("auth vendor not implemented: {}", session.driver_key)
        })?;
        let client = self.gw.http_client_for_provider(session.use_proxy).await?;

        match driver
            .poll(
                &session,
                RefreshAuthContext {
                    use_proxy: session.use_proxy,
                    http_client: Some(client),
                    ..Default::default()
                },
            )
            .await?
        {
            AuthPollState::Pending(progress) => {
                let updated = store
                    .update(
                        &session.id,
                        UpdateAuthSession {
                            user_code: progress.user_code,
                            verification_uri: progress.verification_uri,
                            verification_uri_complete: progress.verification_uri_complete,
                            expires_at: progress.expires_at,
                            poll_interval_seconds: progress.poll_interval_seconds,
                            ..Default::default()
                        },
                    )
                    .await?;
                Ok(build_auth_session_pending_data(&updated))
            }
            AuthPollState::Ready(bundle) => {
                let updated = store
                    .update(
                        &session.id,
                        UpdateAuthSession {
                            status: Some(AuthSessionStatus::Ready.as_str().to_string()),
                            result_json: Some(serde_json::to_string(&bundle)?),
                            expires_at: bundle.expires_at.clone(),
                            last_error: Some(String::new()),
                            ..Default::default()
                        },
                    )
                    .await?;
                Ok(build_auth_session_ready_data(&updated, &bundle))
            }
            AuthPollState::Error { code, message } => {
                let updated = store
                    .update(
                        &session.id,
                        UpdateAuthSession {
                            status: Some(AuthSessionStatus::Error.as_str().to_string()),
                            last_error: Some(format!("{code}: {message}")),
                            ..Default::default()
                        },
                    )
                    .await?;
                Ok(AuthSessionStatusData::Error {
                    code,
                    message: updated.last_error.unwrap_or(message),
                })
            }
        }
    }

    pub async fn cancel_oauth_session(&self, session_id: &str) -> anyhow::Result<()> {
        self.auth_sessions_store()?.delete(session_id).await
    }

    pub async fn complete_oauth_session(
        &self,
        session_id: &str,
        input: auth::AuthExchangeInput,
    ) -> anyhow::Result<AuthSessionStatusData> {
        let store = self.auth_sessions_store()?;
        let session = store
            .get(session_id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("auth session not found: {session_id}"))?;
        if !session
            .status
            .eq_ignore_ascii_case(AuthSessionStatus::Pending.as_str())
        {
            anyhow::bail!("auth session is not pending");
        }

        let driver = auth::build_driver(&session.driver_key).ok_or_else(|| {
            anyhow::anyhow!("auth vendor not implemented: {}", session.driver_key)
        })?;

        let client = self.gw.http_client_for_provider(session.use_proxy).await?;
        let bundle = driver
            .exchange(
                &session,
                input,
                ExchangeAuthContext {
                    use_proxy: session.use_proxy,
                    http_client: Some(client),
                    ..Default::default()
                },
            )
            .await?;
        let updated = store
            .update(
                &session.id,
                UpdateAuthSession {
                    status: Some(AuthSessionStatus::Ready.as_str().to_string()),
                    result_json: Some(serde_json::to_string(&bundle)?),
                    expires_at: bundle.expires_at.clone(),
                    last_error: Some(String::new()),
                    ..Default::default()
                },
            )
            .await?;

        Ok(build_auth_session_ready_data(&updated, &bundle))
    }

    pub async fn create_provider_with_oauth_session(
        &self,
        session_id: &str,
        mut input: CreateProvider,
    ) -> anyhow::Result<Provider> {
        let store = self.auth_sessions_store()?;
        let session = store
            .get(session_id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("auth session not found: {session_id}"))?;
        if !session
            .status
            .eq_ignore_ascii_case(AuthSessionStatus::Ready.as_str())
        {
            anyhow::bail!("auth session is not ready");
        }

        let bundle = parse_auth_session_bundle(&session)?;
        let access_token = bundle
            .access_token
            .clone()
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| anyhow::anyhow!("auth session missing access token"))?;

        if input.vendor.as_deref().unwrap_or("").trim().is_empty() {
            input.vendor = Some(session.driver_key.clone());
        }
        input.api_key = access_token.clone();

        let provider = self.create_provider(input).await?;
        let provisioned = async {
            let binding = self
                .persist_provider_auth_binding(&provider, &session, &bundle)
                .await?;
            self.sync_provider_runtime_fields(&provider, &binding.stored_credential())
                .await
        }
        .await;

        let provider = match provisioned {
            Ok(provider) => provider,
            Err(error) => {
                if let Err(cleanup_error) = self.delete_provider(&provider.id).await {
                    tracing::warn!(
                        "failed to rollback oauth provider {} after provisioning error: {}",
                        provider.id,
                        cleanup_error
                    );
                }
                return Err(error.context("create oauth provider"));
            }
        };

        store.delete(session_id).await?;
        Ok(provider)
    }

    pub async fn get_provider_oauth_status(
        &self,
        id: &str,
    ) -> anyhow::Result<ProviderOAuthStatusData> {
        let provider = self.get_provider(id).await?;
        let driver_key = provider
            .vendor
            .as_deref()
            .map(auth::normalize_driver_key)
            .unwrap_or_default();

        if driver_key.is_empty() {
            return Ok(build_provider_oauth_status(&provider, "", None, None));
        }

        let unavailable = auth::build_driver(&driver_key).is_none();
        let binding = self
            .provider_auth_bindings_store()?
            .get_by_provider_and_driver(&provider.id, &driver_key)
            .await?;
        let reason = if unavailable {
            Some(format!("oauth driver is unavailable: {driver_key}"))
        } else {
            None
        };
        Ok(build_provider_oauth_status(
            &provider,
            &driver_key,
            binding.as_ref(),
            reason,
        ))
    }

    pub async fn reconnect_provider_oauth(
        &self,
        id: &str,
    ) -> anyhow::Result<ProviderOAuthStatusData> {
        let provider = self.get_provider(id).await?;
        let driver_key = provider
            .vendor
            .as_deref()
            .map(auth::normalize_driver_key)
            .unwrap_or_default();
        if driver_key.is_empty() {
            anyhow::bail!("provider does not have an oauth vendor");
        }

        let driver = auth::build_driver(&driver_key)
            .ok_or_else(|| anyhow::anyhow!("auth vendor not implemented: {driver_key}"))?;
        if !driver.metadata().supports_existing_provider {
            anyhow::bail!("auth vendor does not support reconnect: {driver_key}");
        }

        let store = self.provider_auth_bindings_store()?;
        let binding = store
            .get_by_provider_and_driver(&provider.id, &driver_key)
            .await?
            .ok_or_else(|| anyhow::anyhow!("provider oauth binding not found"))?;

        let credential = binding.stored_credential();
        let refresh_token = credential
            .refresh_token
            .as_deref()
            .unwrap_or_default()
            .trim()
            .to_string();
        if refresh_token.is_empty() {
            anyhow::bail!("provider oauth binding missing refresh token");
        }

        let client = self.gw.http_client_for_provider(provider.use_proxy).await?;
        let refreshed = match driver
            .refresh(
                &credential,
                RefreshAuthContext {
                    use_proxy: provider.use_proxy,
                    http_client: Some(client),
                    ..Default::default()
                },
            )
            .await
        {
            Ok(bundle) => bundle,
            Err(error) => {
                store
                    .upsert(UpsertProviderAuthBinding {
                        provider_id: provider.id.clone(),
                        driver_key: binding.driver_key.clone(),
                        scheme: binding.scheme.clone(),
                        status: AuthBindingStatus::Error.as_str().to_string(),
                        access_token: binding.access_token.clone(),
                        refresh_token: binding.refresh_token.clone(),
                        expires_at: binding.expires_at.clone(),
                        resource_url: binding.resource_url.clone(),
                        subject_id: binding.subject_id.clone(),
                        scopes_json: binding.scopes_json.clone(),
                        meta_json: binding.meta_json.clone(),
                        last_error: Some(error.to_string()),
                    })
                    .await?;
                return Err(error.context("reconnect provider oauth"));
            }
        };

        let refreshed_binding = store
            .upsert(UpsertProviderAuthBinding {
                provider_id: provider.id.clone(),
                driver_key: binding.driver_key.clone(),
                scheme: binding.scheme.clone(),
                status: AuthBindingStatus::Connected.as_str().to_string(),
                access_token: refreshed.access_token.clone(),
                refresh_token: refreshed
                    .refresh_token
                    .clone()
                    .or_else(|| binding.refresh_token.clone()),
                expires_at: refreshed.expires_at.clone(),
                resource_url: refreshed
                    .resource_url
                    .clone()
                    .or_else(|| binding.resource_url.clone()),
                subject_id: refreshed
                    .subject_id
                    .clone()
                    .or_else(|| binding.subject_id.clone()),
                scopes_json: Some(serde_json::to_string(if refreshed.scopes.is_empty() {
                    &credential.scopes
                } else {
                    &refreshed.scopes
                })?),
                meta_json: Some(serde_json::to_string(&refreshed.raw)?),
                last_error: None,
            })
            .await?;

        self.sync_provider_runtime_fields(&provider, &refreshed_binding.stored_credential())
            .await?;

        Ok(build_provider_oauth_status(
            &provider,
            &driver_key,
            Some(&refreshed_binding),
            None,
        ))
    }

    pub async fn logout_provider_oauth(&self, id: &str) -> anyhow::Result<ProviderOAuthStatusData> {
        let provider = self.get_provider(id).await?;
        let driver_key = provider
            .vendor
            .as_deref()
            .map(auth::normalize_driver_key)
            .unwrap_or_default();

        if driver_key.is_empty() {
            return Ok(build_provider_oauth_status(&provider, "", None, None));
        }

        let store = self.provider_auth_bindings_store()?;
        store
            .delete_by_provider_and_driver(&provider.id, &driver_key)
            .await?;

        self.gw
            .storage
            .providers()
            .update(
                &provider.id,
                UpdateProvider {
                    api_key: Some(String::new()),
                    ..Default::default()
                },
            )
            .await?;

        Ok(build_provider_oauth_status(
            &provider,
            &driver_key,
            None,
            None,
        ))
    }

    pub async fn create_provider(&self, input: CreateProvider) -> anyhow::Result<Provider> {
        let name = normalize_name(&input.name, "provider name")?;
        self.ensure_provider_name_unique(None, &name).await?;
        let vendor = normalize_vendor(input.vendor.as_deref());
        self.gw
            .storage
            .providers()
            .create(CreateProvider {
                name,
                vendor,
                protocol: input.protocol,
                base_url: input.base_url,
                default_protocol: input.default_protocol,
                protocol_endpoints: input.protocol_endpoints,
                preset_key: input.preset_key,
                channel: input.channel,
                models_source: input.models_source,
                capabilities_source: input.capabilities_source,
                static_models: input.static_models,
                api_key: input.api_key,
                use_proxy: input.use_proxy,
            })
            .await
    }

    pub async fn update_provider(
        &self,
        id: &str,
        input: UpdateProvider,
    ) -> anyhow::Result<Provider> {
        let current = self.get_provider(id).await?;
        let current_base_url = current.base_url.clone();
        let models_source_input = input.effective_models_source().map(ToString::to_string);

        let name = normalize_name(&input.name.unwrap_or(current.name), "provider name")?;
        self.ensure_provider_name_unique(Some(id), &name).await?;
        let vendor = if input.vendor.is_some() {
            normalize_vendor(input.vendor.as_deref())
        } else {
            normalize_vendor(current.vendor.as_deref())
        };
        let models_source = models_source_input
            .or_else(|| current.models_source.as_deref().map(ToString::to_string));
        let protocol = input.protocol.unwrap_or(current.protocol);
        let base_url = input.base_url.unwrap_or(current.base_url);
        let preset_key = input.preset_key.or(current.preset_key);
        let channel = input.channel.or(current.channel);
        let capabilities_source = input.capabilities_source.or(current.capabilities_source);
        let static_models = input.static_models.or(current.static_models);
        let api_key = input.api_key.unwrap_or(current.api_key);
        let use_proxy = input.use_proxy.unwrap_or(current.use_proxy);
        let is_active = input.is_active.unwrap_or(current.is_active);
        let base_url_changed = base_url != current_base_url;

        let provider = self
            .gw
            .storage
            .providers()
            .update(
                id,
                UpdateProvider {
                    name: Some(name),
                    vendor,
                    protocol: Some(protocol),
                    base_url: Some(base_url),
                    default_protocol: input.default_protocol,
                    protocol_endpoints: input.protocol_endpoints,
                    preset_key,
                    channel,
                    models_source,
                    capabilities_source,
                    static_models,
                    api_key: Some(api_key),
                    use_proxy: Some(use_proxy),
                    is_active: Some(is_active),
                },
            )
            .await?;

        if base_url_changed {
            self.gw.clear_ollama_capability_cache_for_provider(id).await;
        }

        Ok(provider)
    }

    pub async fn delete_provider(&self, id: &str) -> anyhow::Result<()> {
        self.gw.storage.providers().delete(id).await?;
        self.gw.clear_ollama_capability_cache_for_provider(id).await;
        Ok(())
    }

    pub async fn test_provider(&self, id: &str) -> anyhow::Result<TestResult> {
        let provider = self.get_provider(id).await?;
        self.gw
            .clear_ollama_capability_cache_for_provider(&provider.id)
            .await;
        let start = Instant::now();
        let mut endpoints = provider
            .parsed_protocol_endpoints()
            .into_iter()
            .collect::<Vec<_>>();
        endpoints.sort_by(|a, b| a.0.cmp(&b.0));

        let result = if endpoints.is_empty() {
            TestResult {
                success: false,
                latency_ms: 0,
                model: None,
                error: Some("Base URL is empty".to_string()),
            }
        } else {
            let mut failures: Vec<String> = Vec::new();
            for (protocol, endpoint) in endpoints {
                let base_url = endpoint.base_url.trim();
                if base_url.is_empty() {
                    failures.push(format!("{protocol}: Base URL is empty"));
                    continue;
                }
                if reqwest::Url::parse(base_url).is_err() {
                    failures.push(format!("{protocol}: Base URL format is invalid"));
                    continue;
                }

                match self
                    .gw
                    .http_client
                    .get(base_url)
                    .timeout(Duration::from_secs(10))
                    .send()
                    .await
                {
                    // Any HTTP response means the endpoint is reachable, including 4xx.
                    Ok(_) => {}
                    Err(e) => {
                        failures.push(format!("{protocol}: {}", format_connectivity_error(&e)))
                    }
                }
            }

            if failures.is_empty() {
                TestResult {
                    success: true,
                    latency_ms: start.elapsed().as_millis() as u64,
                    model: None,
                    error: None,
                }
            } else {
                TestResult {
                    success: false,
                    latency_ms: start.elapsed().as_millis() as u64,
                    model: None,
                    error: Some(format!(
                        "Connectivity check failed for protocol endpoints: {}",
                        failures.join("; ")
                    )),
                }
            }
        };
        self.record_provider_test_result(&provider.id, &result)
            .await?;
        Ok(result)
    }

    async fn record_provider_test_result(
        &self,
        provider_id: &str,
        result: &TestResult,
    ) -> anyhow::Result<()> {
        self.gw
            .storage
            .providers()
            .record_test_result(
                provider_id,
                ProviderTestResult {
                    success: result.success,
                    tested_at: String::new(),
                },
            )
            .await
    }

    pub async fn test_provider_models(&self, id: &str) -> anyhow::Result<Vec<String>> {
        let provider = self.get_provider(id).await?;
        let runtime = self.resolve_provider_runtime_for_admin(&provider).await?;
        let static_models = provider_static_models(&provider);
        let Some(endpoint) = resolve_models_endpoint_with_binding(&provider, &runtime.binding)
        else {
            if static_models.is_empty() {
                anyhow::bail!("Model Discovery URL is empty");
            }
            return Ok(static_models);
        };

        if let Some(models) = lookup_models_dev_models(&self.gw.config.data_dir, &endpoint)? {
            if models.is_empty() {
                anyhow::bail!("Model list format is invalid or empty");
            }
            return Ok(models);
        }

        let mut request = self
            .gw
            .http_client
            .get(&endpoint)
            .headers(build_model_headers(
                &provider.protocol,
                provider.vendor.as_deref(),
                &runtime.access_token,
                &runtime.binding,
            )?)
            .timeout(Duration::from_secs(10));

        if provider.protocol == "gemini" && !runtime.binding.disable_default_auth {
            let separator = if endpoint.contains('?') { '&' } else { '?' };
            request = self
                .gw
                .http_client
                .get(format!("{endpoint}{separator}key={}", runtime.access_token))
                .headers(build_model_headers(
                    &provider.protocol,
                    provider.vendor.as_deref(),
                    &runtime.access_token,
                    &runtime.binding,
                )?)
                .timeout(Duration::from_secs(10));
        }

        let resp = request
            .send()
            .await
            .map_err(|e| anyhow::anyhow!(format_connectivity_error(&e)))?;
        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            let preview = body.chars().take(200).collect::<String>();
            if !static_models.is_empty() {
                tracing::warn!(
                    "model discovery failed for provider {} with HTTP {}, falling back to static models",
                    provider.id,
                    status
                );
                return Ok(static_models);
            }
            anyhow::bail!("HTTP {status}: {preview}");
        }

        let json: Value = resp.json().await.unwrap_or_default();
        let models =
            extract_models_from_response(&provider.protocol, provider.vendor.as_deref(), &json);
        if models.is_empty() {
            if !static_models.is_empty() {
                return Ok(static_models);
            }
            anyhow::bail!("Model list format is invalid or empty");
        }

        Ok(models)
    }

    pub async fn get_provider_models(&self, id: &str) -> anyhow::Result<Vec<String>> {
        let provider = self.get_provider(id).await?;
        let runtime = self.resolve_provider_runtime_for_admin(&provider).await?;

        if let Some(endpoint) = resolve_models_endpoint_with_binding(&provider, &runtime.binding) {
            if let Some(models) = lookup_models_dev_models(&self.gw.config.data_dir, &endpoint)? {
                if !models.is_empty() {
                    return Ok(models);
                }
            }

            let mut request = self
                .gw
                .http_client
                .get(&endpoint)
                .headers(build_model_headers(
                    &provider.protocol,
                    provider.vendor.as_deref(),
                    &runtime.access_token,
                    &runtime.binding,
                )?);

            if provider.protocol == "gemini" && !runtime.binding.disable_default_auth {
                let separator = if endpoint.contains('?') { '&' } else { '?' };
                request = self
                    .gw
                    .http_client
                    .get(format!("{endpoint}{separator}key={}", runtime.access_token))
                    .headers(build_model_headers(
                        &provider.protocol,
                        provider.vendor.as_deref(),
                        &runtime.access_token,
                        &runtime.binding,
                    )?);
            }

            if let Ok(resp) = request.send().await {
                if resp.status().is_success() {
                    let json: Value = resp.json().await.unwrap_or_default();
                    let models = extract_models_from_response(
                        &provider.protocol,
                        provider.vendor.as_deref(),
                        &json,
                    );
                    if !models.is_empty() {
                        return Ok(models);
                    }
                }
            }
        }

        Ok(provider_static_models(&provider))
    }

    pub async fn get_model_capabilities(
        &self,
        provider_id: &str,
        model: &str,
    ) -> anyhow::Result<ModelCapabilities> {
        let provider = self.get_provider(provider_id).await?;
        let trimmed_model = model.trim();
        if trimmed_model.is_empty() {
            anyhow::bail!("model cannot be empty");
        }
        self.resolve_provider_model_capabilities(&provider, trimmed_model)
            .await
    }

    async fn resolve_provider_model_capabilities(
        &self,
        provider: &Provider,
        model: &str,
    ) -> anyhow::Result<ModelCapabilities> {
        let source = provider
            .capabilities_source
            .as_deref()
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .unwrap_or("");

        match parse_source(source) {
            ResolvedSource::ModelsDev(vendor_key) => {
                let matched =
                    lookup_models_dev_capability(&self.gw.config.data_dir, vendor_key, model);
                matched.ok_or_else(|| {
                    anyhow::anyhow!("no matched model capabilities found in models.dev")
                })
            }
            ResolvedSource::Http(url) => {
                if is_ollama_show_endpoint(url) {
                    self.query_ollama_show_capability(url, model).await
                } else {
                    self.query_http_capability(provider, url, model).await
                }
            }
            ResolvedSource::Auto => Ok(fuzzy_match_models_dev(&self.gw.config.data_dir, model)
                .ok_or_else(|| {
                    anyhow::anyhow!("no matched model capabilities found in auto mode")
                })?),
        }
    }

    async fn query_http_capability(
        &self,
        provider: &Provider,
        url: &str,
        model: &str,
    ) -> anyhow::Result<ModelCapabilities> {
        let runtime = self.resolve_provider_runtime_for_admin(provider).await?;
        let mut request = self
            .gw
            .http_client
            .get(url)
            .headers(build_model_headers(
                &provider.protocol,
                provider.vendor.as_deref(),
                &runtime.access_token,
                &runtime.binding,
            )?)
            .timeout(Duration::from_secs(10));

        if provider.protocol == "gemini" && !runtime.binding.disable_default_auth {
            let separator = if url.contains('?') { '&' } else { '?' };
            request = self
                .gw
                .http_client
                .get(format!("{url}{separator}key={}", runtime.access_token))
                .headers(build_model_headers(
                    &provider.protocol,
                    provider.vendor.as_deref(),
                    &runtime.access_token,
                    &runtime.binding,
                )?)
                .timeout(Duration::from_secs(10));
        }

        let resp = request
            .send()
            .await
            .map_err(|e| anyhow::anyhow!(format_connectivity_error(&e)))?;
        if !resp.status().is_success() {
            anyhow::bail!("capability source returned status {}", resp.status());
        }
        let json: Value = resp.json().await.unwrap_or_default();
        if let Some(cap) = parse_http_capability(&json, model) {
            return Ok(cap);
        }
        anyhow::bail!("no matched model capabilities found from capability source")
    }

    async fn query_ollama_show_capability(
        &self,
        url: &str,
        model: &str,
    ) -> anyhow::Result<ModelCapabilities> {
        let resp = self
            .gw
            .http_client
            .post(url)
            .json(&serde_json::json!({ "name": model }))
            .timeout(Duration::from_secs(10))
            .send()
            .await
            .map_err(|e| anyhow::anyhow!(format_connectivity_error(&e)))?;
        if !resp.status().is_success() {
            anyhow::bail!("ollama /api/show returned status {}", resp.status());
        }
        let json: Value = resp.json().await.unwrap_or_default();
        Ok(parse_ollama_capability(&json, model))
    }

    // ── Routes ──

    pub async fn list_routes(&self) -> anyhow::Result<Vec<Route>> {
        let mut routes = self.gw.storage.routes().list().await?;
        if let Some(store) = self.gw.storage.route_targets() {
            for route in &mut routes {
                route.targets = store.list_targets_by_route(&route.id).await?;
            }
        }
        Ok(routes)
    }

    pub async fn get_route(&self, id: &str) -> anyhow::Result<Route> {
        self.get_route_by_id(id).await
    }

    pub async fn create_route(&self, input: CreateRoute) -> anyhow::Result<Route> {
        let name = normalize_name(&input.name, "route name")?;
        self.ensure_route_name_unique(None, &name).await?;
        ensure_virtual_model(&input.virtual_model)?;
        self.ensure_route_unique(None, &input.virtual_model).await?;
        let strategy = normalize_route_strategy(input.strategy.as_deref())?;
        let targets = normalize_create_route_targets(&input)?;
        ensure_route_targets_valid(&targets)?;
        let primary_target = targets
            .first()
            .ok_or_else(|| anyhow::anyhow!("at least one route target is required"))?;

        let route = self
            .gw
            .storage
            .routes()
            .create(CreateRoute {
                name,
                virtual_model: input.virtual_model,
                strategy: Some(strategy),
                target_provider: primary_target.provider_id.clone(),
                target_model: primary_target.model.clone(),
                targets: vec![],
                access_control: input.access_control,
            })
            .await?;
        if let Some(store) = self.gw.storage.route_targets() {
            store.set_targets(&route.id, &targets).await?;
        }
        self.reload_route_cache().await?;
        self.get_route_by_id(&route.id).await
    }

    pub async fn update_route(&self, id: &str, input: UpdateRoute) -> anyhow::Result<Route> {
        let current = self.get_route_by_id(id).await?;

        let name = normalize_name(
            &input.name.clone().unwrap_or_else(|| current.name.clone()),
            "route name",
        )?;
        self.ensure_route_name_unique(Some(id), &name).await?;
        let virtual_model = input
            .virtual_model
            .clone()
            .unwrap_or_else(|| current.virtual_model.clone());
        let strategy =
            normalize_route_strategy(input.strategy.as_deref().or(Some(&current.strategy)))?;
        let targets = normalize_update_route_targets(&current, &input)?;
        ensure_route_targets_valid(&targets)?;
        let primary_target = targets
            .first()
            .ok_or_else(|| anyhow::anyhow!("at least one route target is required"))?;
        let access_control = input.access_control.unwrap_or(current.access_control);
        let is_active = input.is_active.unwrap_or(current.is_active);
        ensure_virtual_model(&virtual_model)?;
        self.ensure_route_unique(Some(id), &virtual_model).await?;

        self.gw
            .storage
            .routes()
            .update(
                id,
                UpdateRoute {
                    name: Some(name),
                    virtual_model: Some(virtual_model),
                    strategy: Some(strategy),
                    target_provider: Some(primary_target.provider_id.clone()),
                    target_model: Some(primary_target.model.clone()),
                    targets: None,
                    access_control: Some(access_control),
                    is_active: Some(is_active),
                },
            )
            .await?;
        if let Some(store) = self.gw.storage.route_targets() {
            store.set_targets(id, &targets).await?;
        }
        self.reload_route_cache().await?;
        self.get_route_by_id(id).await
    }

    pub async fn delete_route(&self, id: &str) -> anyhow::Result<()> {
        if let Some(store) = self.gw.storage.route_targets() {
            store.delete_targets_by_route(id).await?;
        }
        self.gw.storage.routes().delete(id).await?;
        self.reload_route_cache().await?;
        Ok(())
    }

    // ── API Keys ──

    pub async fn list_api_keys(&self) -> anyhow::Result<Vec<ApiKeyWithBindings>> {
        self.api_keys_store()?.list().await
    }

    pub async fn get_api_key(&self, id: &str) -> anyhow::Result<ApiKeyWithBindings> {
        self.api_keys_store()?
            .get(id)
            .await?
            .context("api key not found")
    }

    pub async fn create_api_key(&self, input: CreateApiKey) -> anyhow::Result<ApiKeyWithBindings> {
        let name = normalize_name(&input.name, "api key name")?;
        self.ensure_api_key_name_unique(None, &name).await?;
        self.api_keys_store()?
            .create(CreateApiKey {
                name,
                rpm: input.rpm,
                rpd: input.rpd,
                tpm: input.tpm,
                tpd: input.tpd,
                expires_at: input.expires_at,
                route_ids: input.route_ids,
            })
            .await
    }

    pub async fn update_api_key(
        &self,
        id: &str,
        input: UpdateApiKey,
    ) -> anyhow::Result<ApiKeyWithBindings> {
        let current = self
            .api_keys_store()?
            .get(id)
            .await?
            .context("api key not found")?;

        let name = normalize_name(&input.name.unwrap_or(current.name), "api key name")?;
        self.ensure_api_key_name_unique(Some(id), &name).await?;
        let rpm = input.rpm.or(current.rpm);
        let rpd = input.rpd.or(current.rpd);
        let tpm = input.tpm.or(current.tpm);
        let tpd = input.tpd.or(current.tpd);
        let status = input.status.unwrap_or(current.status);
        let expires_at = input.expires_at.or(current.expires_at);

        if status != "active" && status != "revoked" {
            anyhow::bail!("invalid key status: {status}");
        }

        self.api_keys_store()?
            .update(
                id,
                UpdateApiKey {
                    name: Some(name),
                    rpm,
                    rpd,
                    tpm,
                    tpd,
                    status: Some(status),
                    expires_at,
                    route_ids: input.route_ids,
                },
            )
            .await
    }

    pub async fn delete_api_key(&self, id: &str) -> anyhow::Result<()> {
        self.api_keys_store()?.delete(id).await?;
        Ok(())
    }

    // ── Logs ──

    pub async fn query_logs(&self, q: LogQuery) -> anyhow::Result<LogPage> {
        let mut q = q;
        q.limit = Some(q.limit.unwrap_or(50).min(500));
        q.offset = Some(q.offset.unwrap_or(0));
        self.gw.storage.logs().query(q).await
    }

    // ── Stats ──

    fn normalize_hours(hours: Option<i32>) -> Option<i32> {
        hours.and_then(|value| (value > 0).then_some(value))
    }

    pub async fn get_stats_overview(&self, hours: Option<i32>) -> anyhow::Result<StatsOverview> {
        self.gw
            .storage
            .logs()
            .stats_overview(Self::normalize_hours(hours).map(i64::from))
            .await
    }

    pub async fn get_stats_hourly(&self, hours: i32) -> anyhow::Result<Vec<StatsHourly>> {
        self.gw
            .storage
            .logs()
            .stats_hourly(i64::from(hours.max(1)))
            .await
    }

    pub async fn get_stats_by_model(&self, hours: Option<i32>) -> anyhow::Result<Vec<ModelStats>> {
        self.gw
            .storage
            .logs()
            .stats_by_model(Self::normalize_hours(hours).map(i64::from))
            .await
    }

    pub async fn get_stats_by_provider(
        &self,
        hours: Option<i32>,
    ) -> anyhow::Result<Vec<ProviderStats>> {
        self.gw
            .storage
            .logs()
            .stats_by_provider(Self::normalize_hours(hours).map(i64::from))
            .await
    }

    // ── Settings ──

    pub async fn get_setting(&self, key: &str) -> anyhow::Result<Option<String>> {
        self.gw.storage.settings().get(key).await
    }

    pub async fn set_setting(&self, key: &str, value: &str) -> anyhow::Result<()> {
        self.gw.storage.settings().set(key, value).await
    }

    pub async fn list_settings(&self) -> anyhow::Result<Vec<(String, String)>> {
        self.gw.storage.settings().list_all().await
    }

    // ── Config Import/Export ──

    pub async fn export_config(&self) -> anyhow::Result<ExportData> {
        let providers = self.list_providers().await?;
        let routes = self.list_routes().await?;
        let settings = self.gw.storage.settings().list_all().await?;

        Ok(ExportData {
            version: 1,
            providers: providers
                .into_iter()
                .map(|p| ExportProvider {
                    name: p.name,
                    vendor: p.vendor,
                    protocol: p.protocol,
                    base_url: p.base_url,
                    default_protocol: p.default_protocol,
                    protocol_endpoints: p.protocol_endpoints,
                    preset_key: p.preset_key,
                    channel: p.channel,
                    models_source: p.models_source,
                    capabilities_source: p.capabilities_source,
                    static_models: p.static_models,
                    api_key: p.api_key,
                    use_proxy: p.use_proxy,
                    is_active: p.is_active,
                })
                .collect(),
            routes: routes
                .into_iter()
                .map(|r| ExportRoute {
                    name: r.name,
                    virtual_model: r.virtual_model,
                    target_model: r.target_model,
                    access_control: r.access_control,
                    is_active: r.is_active,
                })
                .collect(),
            settings: settings.into_iter().collect(),
        })
    }

    pub async fn import_config(&self, data: ExportData) -> anyhow::Result<ImportResult> {
        let mut providers_imported = 0u32;
        let mut routes_imported = 0u32;
        let mut settings_imported = 0u32;

        for p in &data.providers {
            let exists = self
                .gw
                .storage
                .providers()
                .exists_by_name(&p.name, None)
                .await
                .unwrap_or(false);

            if !exists {
                if self
                    .create_provider(CreateProvider {
                        name: p.name.clone(),
                        vendor: p.vendor.clone(),
                        protocol: p.protocol.clone(),
                        base_url: p.base_url.clone(),
                        default_protocol: if p.default_protocol.is_empty() {
                            None
                        } else {
                            Some(p.default_protocol.clone())
                        },
                        protocol_endpoints: if p.protocol_endpoints.is_empty()
                            || p.protocol_endpoints == "{}"
                        {
                            None
                        } else {
                            Some(p.protocol_endpoints.clone())
                        },
                        preset_key: p.preset_key.clone(),
                        channel: p.channel.clone(),
                        models_source: p.models_source.clone(),
                        capabilities_source: p.capabilities_source.clone(),
                        static_models: p.static_models.clone(),
                        api_key: p.api_key.clone(),
                        use_proxy: p.use_proxy,
                    })
                    .await
                    .is_ok()
                {
                    providers_imported += 1;
                }
            }
        }

        let fallback_provider_id = self
            .list_providers()
            .await?
            .into_iter()
            .next()
            .map(|provider| provider.id);

        for r in &data.routes {
            let exists = self
                .gw
                .storage
                .routes()
                .exists_by_name(&r.name, None)
                .await
                .unwrap_or(false);

            if !exists {
                if let Some(pid) = fallback_provider_id.clone() {
                    if self
                        .create_route(CreateRoute {
                            name: r.name.clone(),
                            virtual_model: r.virtual_model.clone(),
                            strategy: Some("weighted".to_string()),
                            target_provider: pid,
                            target_model: r.target_model.clone(),
                            targets: vec![],
                            access_control: Some(r.access_control),
                        })
                        .await
                        .is_ok()
                    {
                        routes_imported += 1;
                    }
                }
            }
        }

        for (key, value) in &data.settings {
            self.set_setting(key, value).await?;
            settings_imported += 1;
        }

        Ok(ImportResult {
            providers_imported,
            routes_imported,
            settings_imported,
        })
    }

    async fn ensure_route_unique(
        &self,
        exclude_id: Option<&str>,
        virtual_model: &str,
    ) -> anyhow::Result<()> {
        if self
            .gw
            .storage
            .routes()
            .exists_by_virtual_model(virtual_model, exclude_id)
            .await?
        {
            let normalized_model = virtual_model.trim();
            anyhow::bail!("route already exists for model={normalized_model}");
        }
        Ok(())
    }

    async fn ensure_provider_name_unique(
        &self,
        exclude_id: Option<&str>,
        name: &str,
    ) -> anyhow::Result<()> {
        if self
            .gw
            .storage
            .providers()
            .exists_by_name(name, exclude_id)
            .await?
        {
            return Err(coded_error(
                "PROVIDER_NAME_CONFLICT",
                &format!("provider name already exists: {name}"),
                serde_json::json!({ "name": name }),
            ));
        }
        Ok(())
    }

    async fn ensure_route_name_unique(
        &self,
        exclude_id: Option<&str>,
        name: &str,
    ) -> anyhow::Result<()> {
        if self
            .gw
            .storage
            .routes()
            .exists_by_name(name, exclude_id)
            .await?
        {
            return Err(coded_error(
                "ROUTE_NAME_CONFLICT",
                &format!("route name already exists: {name}"),
                serde_json::json!({ "name": name }),
            ));
        }
        Ok(())
    }

    async fn ensure_api_key_name_unique(
        &self,
        exclude_id: Option<&str>,
        name: &str,
    ) -> anyhow::Result<()> {
        if self
            .api_keys_store()?
            .exists_by_name(name, exclude_id)
            .await?
        {
            return Err(coded_error(
                "API_KEY_NAME_CONFLICT",
                &format!("api key name already exists: {name}"),
                serde_json::json!({ "name": name }),
            ));
        }
        Ok(())
    }

    async fn get_route_by_id(&self, id: &str) -> anyhow::Result<Route> {
        let mut route = self
            .gw
            .storage
            .routes()
            .get(id)
            .await?
            .context("route not found")?;
        if let Some(store) = self.gw.storage.route_targets() {
            route.targets = store.list_targets_by_route(&route.id).await?;
        }
        Ok(route)
    }

    async fn reload_route_cache(&self) -> anyhow::Result<()> {
        self.gw
            .route_cache
            .write()
            .await
            .reload(self.gw.storage.snapshots())
            .await
    }

    fn auth_sessions_store(&self) -> anyhow::Result<&dyn crate::storage::traits::AuthSessionStore> {
        self.gw
            .storage
            .auth_sessions()
            .context("selected storage backend does not support auth sessions")
    }

    fn provider_auth_bindings_store(
        &self,
    ) -> anyhow::Result<&dyn crate::storage::traits::ProviderAuthBindingStore> {
        self.gw
            .storage
            .provider_auth_bindings()
            .context("selected storage backend does not support provider auth bindings")
    }

    async fn resolve_provider_runtime_for_admin(
        &self,
        provider: &Provider,
    ) -> anyhow::Result<ResolvedAdminProviderRuntime> {
        let fallback = provider.api_key.trim().to_string();
        let driver_key = provider
            .vendor
            .as_deref()
            .map(auth::normalize_driver_key)
            .unwrap_or_default();

        if driver_key.is_empty() {
            if fallback.is_empty() {
                anyhow::bail!("provider api key is empty");
            }
            return Ok(ResolvedAdminProviderRuntime {
                access_token: provider.api_key.clone(),
                binding: RuntimeBinding::default(),
            });
        }

        let Some(driver) = auth::build_driver(&driver_key) else {
            if fallback.is_empty() {
                anyhow::bail!("provider api key is empty");
            }
            return Ok(ResolvedAdminProviderRuntime {
                access_token: provider.api_key.clone(),
                binding: RuntimeBinding::default(),
            });
        };

        let Some(binding) = self
            .provider_auth_bindings_store()?
            .get_by_provider_and_driver(&provider.id, &driver_key)
            .await?
        else {
            if fallback.is_empty() {
                anyhow::bail!("provider api key is empty");
            }
            return Ok(ResolvedAdminProviderRuntime {
                access_token: provider.api_key.clone(),
                binding: RuntimeBinding::default(),
            });
        };

        let credential = binding.stored_credential();
        let access_token = credential
            .access_token
            .clone()
            .unwrap_or_default()
            .trim()
            .to_string();

        if !access_token.is_empty() && !is_expired_at(credential.expires_at.as_deref()) {
            return Ok(ResolvedAdminProviderRuntime {
                access_token,
                binding: driver.bind_runtime(provider, &credential)?,
            });
        }

        let refresh_token = credential
            .refresh_token
            .clone()
            .unwrap_or_default()
            .trim()
            .to_string();
        if refresh_token.is_empty() {
            if !access_token.is_empty() {
                return Ok(ResolvedAdminProviderRuntime {
                    access_token,
                    binding: driver.bind_runtime(provider, &credential)?,
                });
            }
            if fallback.is_empty() {
                anyhow::bail!("provider credential is empty");
            }
            return Ok(ResolvedAdminProviderRuntime {
                access_token: provider.api_key.clone(),
                binding: driver.bind_runtime(provider, &credential)?,
            });
        }

        let client = self.gw.http_client_for_provider(provider.use_proxy).await?;
        let refreshed = match driver
            .refresh(
                &credential,
                RefreshAuthContext {
                    use_proxy: provider.use_proxy,
                    http_client: Some(client),
                    ..Default::default()
                },
            )
            .await
        {
            Ok(bundle) => bundle,
            Err(error) => {
                self.provider_auth_bindings_store()?
                    .upsert(UpsertProviderAuthBinding {
                        provider_id: provider.id.clone(),
                        driver_key: binding.driver_key.clone(),
                        scheme: binding.scheme.clone(),
                        status: AuthBindingStatus::Error.as_str().to_string(),
                        access_token: binding.access_token.clone(),
                        refresh_token: binding.refresh_token.clone(),
                        expires_at: binding.expires_at.clone(),
                        resource_url: binding.resource_url.clone(),
                        subject_id: binding.subject_id.clone(),
                        scopes_json: binding.scopes_json.clone(),
                        meta_json: binding.meta_json.clone(),
                        last_error: Some(error.to_string()),
                    })
                    .await?;
                return Err(error);
            }
        };

        let refreshed_binding = self
            .provider_auth_bindings_store()?
            .upsert(UpsertProviderAuthBinding {
                provider_id: provider.id.clone(),
                driver_key: binding.driver_key.clone(),
                scheme: binding.scheme.clone(),
                status: AuthBindingStatus::Connected.as_str().to_string(),
                access_token: refreshed.access_token.clone(),
                refresh_token: refreshed
                    .refresh_token
                    .clone()
                    .or_else(|| binding.refresh_token.clone()),
                expires_at: refreshed.expires_at.clone(),
                resource_url: refreshed
                    .resource_url
                    .clone()
                    .or_else(|| binding.resource_url.clone()),
                subject_id: refreshed
                    .subject_id
                    .clone()
                    .or_else(|| binding.subject_id.clone()),
                scopes_json: Some(serde_json::to_string(if refreshed.scopes.is_empty() {
                    &credential.scopes
                } else {
                    &refreshed.scopes
                })?),
                meta_json: Some(serde_json::to_string(&refreshed.raw)?),
                last_error: None,
            })
            .await?;

        let refreshed_credential = refreshed_binding.stored_credential();
        self.sync_provider_runtime_fields(provider, &refreshed_credential)
            .await?;

        let access_token = refreshed_credential
            .access_token
            .clone()
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| {
                anyhow::anyhow!("provider credential refresh returned empty access token")
            })?;

        Ok(ResolvedAdminProviderRuntime {
            access_token,
            binding: driver.bind_runtime(provider, &refreshed_credential)?,
        })
    }

    async fn persist_provider_auth_binding(
        &self,
        provider: &Provider,
        session: &AuthSession,
        bundle: &CredentialBundle,
    ) -> anyhow::Result<auth::ProviderAuthBinding> {
        self.provider_auth_bindings_store()?
            .upsert(UpsertProviderAuthBinding {
                provider_id: provider.id.clone(),
                driver_key: session.driver_key.clone(),
                scheme: session.scheme.clone(),
                status: AuthBindingStatus::Connected.as_str().to_string(),
                access_token: bundle.access_token.clone(),
                refresh_token: bundle.refresh_token.clone(),
                expires_at: bundle.expires_at.clone(),
                resource_url: bundle.resource_url.clone(),
                subject_id: bundle.subject_id.clone(),
                scopes_json: Some(serde_json::to_string(&bundle.scopes)?),
                meta_json: Some(serde_json::to_string(&bundle.raw)?),
                last_error: None,
            })
            .await
    }

    async fn sync_provider_runtime_fields(
        &self,
        provider: &Provider,
        credential: &StoredCredential,
    ) -> anyhow::Result<Provider> {
        let Some(driver) = auth::build_driver(&credential.driver_key) else {
            return Ok(provider.clone());
        };

        let binding = driver.bind_runtime(provider, credential)?;
        let next_base_url = binding
            .base_url_override
            .clone()
            .unwrap_or_else(|| provider.base_url.clone());
        let next_protocol_endpoints = sync_protocol_endpoints_base_url(
            &provider.protocol_endpoints,
            provider.effective_default_protocol(),
            &next_base_url,
        )?;
        let next_models_source = binding
            .models_source_override
            .clone()
            .or_else(|| provider.models_source.clone());
        let next_capabilities_source = binding
            .capabilities_source_override
            .clone()
            .or_else(|| provider.capabilities_source.clone());
        let next_api_key = credential
            .access_token
            .clone()
            .unwrap_or_else(|| provider.api_key.clone());

        if next_base_url == provider.base_url
            && next_protocol_endpoints == provider.protocol_endpoints
            && next_models_source == provider.models_source
            && next_capabilities_source == provider.capabilities_source
            && next_api_key == provider.api_key
        {
            return Ok(provider.clone());
        }

        self.update_provider(
            &provider.id,
            UpdateProvider {
                base_url: Some(next_base_url),
                protocol_endpoints: Some(next_protocol_endpoints),
                models_source: next_models_source,
                capabilities_source: next_capabilities_source,
                api_key: Some(next_api_key),
                ..Default::default()
            },
        )
        .await
    }

    fn api_keys_store(&self) -> anyhow::Result<&dyn crate::storage::traits::ApiKeyStore> {
        self.gw
            .storage
            .api_keys()
            .context("selected storage backend does not support api key management")
    }
}

fn parse_auth_session_bundle(session: &AuthSession) -> anyhow::Result<CredentialBundle> {
    let raw = session
        .result_json
        .as_deref()
        .context("auth session is missing result_json")?;
    serde_json::from_str(raw).context("parse auth session credential bundle")
}

fn build_provider_oauth_status(
    provider: &Provider,
    driver_key: &str,
    binding: Option<&auth::ProviderAuthBinding>,
    fallback_error: Option<String>,
) -> ProviderOAuthStatusData {
    let status = binding
        .map(|value| value.status.clone())
        .unwrap_or_else(|| AuthBindingStatus::Disconnected.as_str().to_string());
    let has_refresh_token = binding
        .and_then(|value| value.refresh_token.as_deref())
        .map(|value| !value.trim().is_empty())
        .unwrap_or(false);

    ProviderOAuthStatusData {
        provider_id: provider.id.clone(),
        provider_name: provider.name.clone(),
        driver_key: driver_key.to_string(),
        status,
        expires_at: binding.and_then(|value| value.expires_at.clone()),
        resource_url: binding.and_then(|value| value.resource_url.clone()),
        subject_id: binding.and_then(|value| value.subject_id.clone()),
        last_error: binding
            .and_then(|value| value.last_error.clone())
            .filter(|value| !value.trim().is_empty())
            .or(fallback_error),
        updated_at: binding.map(|value| value.updated_at.clone()),
        has_refresh_token,
    }
}

fn build_auth_session_init_data(session: &AuthSession) -> anyhow::Result<AuthSessionInitData> {
    Ok(AuthSessionInitData {
        session_id: session.id.clone(),
        vendor: session.driver_key.clone(),
        scheme: session.scheme.clone(),
        auth_url: session
            .verification_uri_complete
            .clone()
            .unwrap_or_default(),
        requires_manual_code: session.scheme == AuthScheme::OAuthAuthCodePkce.as_str()
            || session.scheme == AuthScheme::SetupToken.as_str(),
        user_code: session.user_code.clone().unwrap_or_default(),
        verification_uri: session.verification_uri.clone().unwrap_or_default(),
        verification_uri_complete: session
            .verification_uri_complete
            .clone()
            .unwrap_or_default(),
        expires_in: remaining_seconds_until(session.expires_at.as_deref()),
        interval: session.poll_interval_seconds.unwrap_or(2),
    })
}

fn build_auth_session_pending_data(session: &AuthSession) -> AuthSessionStatusData {
    AuthSessionStatusData::Pending {
        scheme: session.scheme.clone(),
        auth_url: session
            .verification_uri_complete
            .clone()
            .unwrap_or_default(),
        requires_manual_code: session.scheme == AuthScheme::OAuthAuthCodePkce.as_str()
            || session.scheme == AuthScheme::SetupToken.as_str(),
        expires_in: remaining_seconds_until(session.expires_at.as_deref()),
        interval: session.poll_interval_seconds.unwrap_or(2),
        user_code: session.user_code.clone().unwrap_or_default(),
        verification_uri_complete: session
            .verification_uri_complete
            .clone()
            .unwrap_or_default(),
    }
}

fn build_auth_session_ready_data(
    session: &AuthSession,
    bundle: &CredentialBundle,
) -> AuthSessionStatusData {
    AuthSessionStatusData::Ready {
        expires_in: remaining_seconds_until(
            bundle
                .expires_at
                .as_deref()
                .or(session.expires_at.as_deref()),
        ),
        resource_url: bundle.resource_url.clone(),
    }
}

fn parse_datetime_utc(value: &str) -> Option<DateTime<Utc>> {
    if let Ok(parsed) = DateTime::parse_from_rfc3339(value) {
        return Some(parsed.with_timezone(&Utc));
    }

    NaiveDateTime::parse_from_str(value, "%Y-%m-%d %H:%M:%S")
        .ok()
        .map(|parsed| parsed.and_utc())
}

fn remaining_seconds_until(expires_at: Option<&str>) -> i64 {
    expires_at
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .and_then(parse_datetime_utc)
        .map(|value| (value - Utc::now()).num_seconds().max(0))
        .unwrap_or(0)
}

fn is_expired_at(expires_at: Option<&str>) -> bool {
    expires_at
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .and_then(parse_datetime_utc)
        .map(|value| value <= Utc::now())
        .unwrap_or(false)
}

fn sync_protocol_endpoints_base_url(
    raw: &str,
    default_protocol: &str,
    base_url: &str,
) -> anyhow::Result<String> {
    let mut endpoints = if raw.trim().is_empty() || raw.trim() == "{}" {
        HashMap::<String, ProtocolEndpointEntry>::new()
    } else {
        serde_json::from_str::<HashMap<String, ProtocolEndpointEntry>>(raw).unwrap_or_default()
    };

    let protocol = default_protocol.trim();
    if !protocol.is_empty() && !base_url.trim().is_empty() {
        endpoints.insert(
            protocol.to_string(),
            ProtocolEndpointEntry {
                base_url: base_url.trim().to_string(),
            },
        );
    }

    Ok(serde_json::to_string(&endpoints)?)
}

fn format_connectivity_error(error: &reqwest::Error) -> String {
    if error.is_timeout() {
        return "Connection timeout (10s), please check Base URL or network settings".to_string();
    }
    if error.is_connect() {
        return "Unable to connect to the host, please check DNS/network settings".to_string();
    }
    error.to_string()
}

fn coded_error(code: &str, message: &str, params: Value) -> anyhow::Error {
    anyhow::anyhow!(
        "{}",
        serde_json::json!({
            "code": code,
            "message": message,
            "params": params,
        })
    )
}

fn ensure_virtual_model(model: &str) -> anyhow::Result<()> {
    if model.trim().is_empty() {
        anyhow::bail!("virtual_model cannot be empty");
    }
    Ok(())
}

fn normalize_route_strategy(strategy: Option<&str>) -> anyhow::Result<String> {
    let normalized = strategy.unwrap_or("weighted").trim().to_ascii_lowercase();
    match normalized.as_str() {
        "weighted" | "priority" => Ok(normalized),
        _ => anyhow::bail!("unsupported route strategy: {normalized}"),
    }
}

fn normalize_create_route_targets(input: &CreateRoute) -> anyhow::Result<Vec<CreateRouteTarget>> {
    if !input.targets.is_empty() {
        return Ok(input.targets.clone());
    }
    if !input.target_provider.trim().is_empty() && !input.target_model.trim().is_empty() {
        return Ok(vec![CreateRouteTarget {
            provider_id: input.target_provider.clone(),
            model: input.target_model.clone(),
            weight: Some(100),
            priority: Some(1),
        }]);
    }
    anyhow::bail!("at least one route target is required")
}

fn normalize_update_route_targets(
    current: &Route,
    input: &UpdateRoute,
) -> anyhow::Result<Vec<CreateRouteTarget>> {
    if let Some(targets) = &input.targets {
        let mapped = targets
            .iter()
            .map(|target| CreateRouteTarget {
                provider_id: target.provider_id.clone(),
                model: target.model.clone(),
                weight: target.weight,
                priority: target.priority,
            })
            .collect();
        return Ok(mapped);
    }

    let provider = input
        .target_provider
        .clone()
        .unwrap_or_else(|| current.target_provider.clone());
    let model = input
        .target_model
        .clone()
        .unwrap_or_else(|| current.target_model.clone());
    if provider.trim().is_empty() || model.trim().is_empty() {
        anyhow::bail!("route target cannot be empty");
    }
    Ok(vec![CreateRouteTarget {
        provider_id: provider,
        model,
        weight: Some(100),
        priority: Some(1),
    }])
}

fn ensure_route_targets_valid(targets: &[CreateRouteTarget]) -> anyhow::Result<()> {
    if targets.is_empty() {
        anyhow::bail!("at least one route target is required");
    }
    for target in targets {
        if target.provider_id.trim().is_empty() {
            anyhow::bail!("target provider_id cannot be empty");
        }
        if target.model.trim().is_empty() {
            anyhow::bail!("target model cannot be empty");
        }
        let weight = target.weight.unwrap_or(100);
        if weight < 0 {
            anyhow::bail!("target weight must be >= 0");
        }
        let priority = target.priority.unwrap_or(1);
        if priority < 1 || priority > 2 {
            anyhow::bail!("target priority must be 1 or 2");
        }
    }
    Ok(())
}

fn normalize_name(name: &str, field: &str) -> anyhow::Result<String> {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        anyhow::bail!("{field} cannot be empty");
    }
    Ok(trimmed.to_string())
}

fn normalize_vendor(vendor: Option<&str>) -> Option<String> {
    vendor
        .map(str::trim)
        .filter(|v| !v.is_empty() && *v != "custom")
        .map(|v| v.to_lowercase())
}

fn resolve_models_endpoint(provider: &Provider) -> Option<String> {
    if let Some(endpoint) = provider.effective_models_source() {
        let trimmed = endpoint.trim();
        if !trimmed.is_empty() {
            return Some(trimmed.to_string());
        }
    }

    let base = provider.base_url.trim_end_matches('/');
    match provider.protocol.as_str() {
        "openai" | "anthropic" => {
            let has_base_path = reqwest::Url::parse(base)
                .ok()
                .map(|url| {
                    let pathname = url.path().trim_end_matches('/');
                    !pathname.is_empty() && pathname != "/"
                })
                .unwrap_or(false);
            if has_base_path {
                Some(format!("{base}/models"))
            } else {
                Some(format!("{base}/v1/models"))
            }
        }
        "gemini" => Some(format!("{base}/v1beta/models")),
        _ => None,
    }
}

fn resolve_models_endpoint_with_binding(
    provider: &Provider,
    binding: &RuntimeBinding,
) -> Option<String> {
    binding
        .models_source_override
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
        .or_else(|| resolve_models_endpoint(provider))
}

fn build_model_headers(
    protocol: &str,
    vendor: Option<&str>,
    api_key: &str,
    binding: &RuntimeBinding,
) -> anyhow::Result<HeaderMap> {
    let mut headers = HeaderMap::new();
    if binding.disable_default_auth {
        for (key, value) in &binding.extra_headers {
            headers.insert(
                reqwest::header::HeaderName::from_bytes(key.as_bytes())?,
                HeaderValue::from_str(value)?,
            );
        }
        return Ok(headers);
    }

    let vendor_key = vendor.map(str::trim).unwrap_or_default();
    let is_google_vendor = vendor_key.eq_ignore_ascii_case("google");
    match protocol {
        "anthropic" => {
            headers.insert("x-api-key", HeaderValue::from_str(api_key)?);
            headers.insert("anthropic-version", HeaderValue::from_static("2023-06-01"));
        }
        "gemini" => {
            // Google providers may expose OpenAI-compatible /v1/models endpoints.
            // Add Bearer auth in addition to Gemini key query param.
            if is_google_vendor {
                headers.insert(
                    AUTHORIZATION,
                    HeaderValue::from_str(&format!("Bearer {api_key}"))?,
                );
            }
        }
        _ => {
            headers.insert(
                AUTHORIZATION,
                HeaderValue::from_str(&format!("Bearer {api_key}"))?,
            );
        }
    }
    if vendor_key.eq_ignore_ascii_case("qwen-code-cli") {
        headers.insert(
            "X-DashScope-AuthType",
            HeaderValue::from_static("qwen-oauth"),
        );
    }
    for (key, value) in &binding.extra_headers {
        headers.insert(
            reqwest::header::HeaderName::from_bytes(key.as_bytes())?,
            HeaderValue::from_str(value)?,
        );
    }
    Ok(headers)
}

fn extract_models_from_response(protocol: &str, vendor: Option<&str>, json: &Value) -> Vec<String> {
    let is_google_vendor = vendor
        .map(str::trim)
        .is_some_and(|value| value.eq_ignore_ascii_case("google"));
    let is_codex_vendor = vendor
        .map(str::trim)
        .is_some_and(|value| value.eq_ignore_ascii_case("codex"));
    let mut models = json
        .get("data")
        .and_then(|value| value.as_array())
        .into_iter()
        .flatten()
        .filter_map(|item| item.get("id").and_then(|value| value.as_str()))
        .map(|id| {
            if is_google_vendor {
                id.strip_prefix("models/").unwrap_or(id).to_string()
            } else {
                id.to_string()
            }
        })
        .collect::<Vec<_>>();

    if models.is_empty() && is_codex_vendor {
        models = json
            .get("models")
            .and_then(|value| value.as_array())
            .into_iter()
            .flatten()
            .filter_map(|item| item.get("slug").and_then(|value| value.as_str()))
            .map(ToString::to_string)
            .collect::<Vec<_>>();
    }

    if models.is_empty() && protocol == "gemini" {
        models = json
            .get("models")
            .and_then(|value| value.as_array())
            .into_iter()
            .flatten()
            .filter_map(|item| item.get("name").and_then(|value| value.as_str()))
            .map(|name| {
                let normalized = name.rsplit('/').next().unwrap_or(name);
                if is_google_vendor {
                    normalized
                        .strip_prefix("models/")
                        .unwrap_or(normalized)
                        .to_string()
                } else {
                    normalized.to_string()
                }
            })
            .collect::<Vec<_>>();
    }

    models.sort();
    models.dedup();
    models
}

fn parse_static_models(raw: Option<&str>) -> Vec<String> {
    let mut models = raw
        .unwrap_or("")
        .lines()
        .flat_map(|line| line.split(','))
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    models.sort();
    models.dedup();
    models
}

fn default_static_models_for_vendor(vendor: Option<&str>) -> Vec<String> {
    match vendor.map(str::trim) {
        Some(value) if value.eq_ignore_ascii_case("cloud-code") => {
            vec!["gemini-2.5-flash".to_string(), "gemini-2.5-pro".to_string()]
        }
        _ => Vec::new(),
    }
}

fn provider_static_models(provider: &Provider) -> Vec<String> {
    let configured = parse_static_models(provider.static_models.as_deref());
    if configured.is_empty() {
        default_static_models_for_vendor(provider.vendor.as_deref())
    } else {
        configured
    }
}

#[derive(Debug, Clone, Copy)]
enum ResolvedSource<'a> {
    Http(&'a str),
    ModelsDev(&'a str),
    Auto,
}

fn parse_source(uri: &str) -> ResolvedSource<'_> {
    let trimmed = uri.trim();
    if trimmed.is_empty() {
        ResolvedSource::Auto
    } else if trimmed.eq_ignore_ascii_case("ai://models.dev") {
        ResolvedSource::ModelsDev("")
    } else if let Some(key) = trimmed.strip_prefix("ai://models.dev/") {
        ResolvedSource::ModelsDev(key)
    } else {
        ResolvedSource::Http(trimmed)
    }
}

fn is_ollama_show_endpoint(url: &str) -> bool {
    url.trim_end_matches('/').ends_with("/api/show")
}

fn parse_ollama_capability(json: &Value, model: &str) -> ModelCapabilities {
    let caps = json
        .get("capabilities")
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(Value::as_str)
                .map(ToString::to_string)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let has_vision = caps.iter().any(|c| c.eq_ignore_ascii_case("vision"));
    let context_window = json
        .get("model_info")
        .and_then(Value::as_object)
        .and_then(extract_ollama_context_window)
        .unwrap_or(8 * 1024);

    ModelCapabilities {
        provider: "ollama".to_string(),
        model_id: model.to_string(),
        context_window,
        output_max_tokens: None,
        tool_call: caps.iter().any(|c| c == "tools"),
        reasoning: caps.iter().any(|c| c == "thinking"),
        input_modalities: if has_vision {
            vec!["text".to_string(), "image".to_string()]
        } else {
            vec!["text".to_string()]
        },
        output_modalities: vec!["text".to_string()],
        input_cost: Some(0.0),
        output_cost: Some(0.0),
    }
}

fn extract_ollama_context_window(model_info: &serde_json::Map<String, Value>) -> Option<u64> {
    let arch = model_info.get("general.architecture")?.as_str()?;
    let key = format!("{arch}.context_length");
    model_info
        .get(&key)
        .and_then(Value::as_u64)
        .filter(|value| *value > 0)
}

pub async fn refresh_models_dev_runtime_cache_if_stale(
    data_dir: PathBuf,
    http_client: reqwest::Client,
) {
    if let Err(err) = refresh_models_dev_runtime_cache_inner(&data_dir, &http_client, false).await {
        tracing::warn!("models.dev runtime refresh skipped: {err}");
    }
}

pub async fn refresh_models_dev_runtime_cache_on_startup(
    data_dir: PathBuf,
    http_client: reqwest::Client,
) {
    if let Err(err) = refresh_models_dev_runtime_cache_inner(&data_dir, &http_client, true).await {
        tracing::warn!(
            "models.dev startup refresh failed, fallback to local cache/snapshot: {err}"
        );
    }
}

fn models_dev_runtime_cache_path(data_dir: &Path) -> PathBuf {
    data_dir.join(MODELS_DEV_RUNTIME_FILE)
}

async fn refresh_models_dev_runtime_cache_inner(
    data_dir: &Path,
    http_client: &reqwest::Client,
    force_refresh: bool,
) -> anyhow::Result<()> {
    let cache_path = models_dev_runtime_cache_path(data_dir);
    if !force_refresh {
        if let Ok(meta) = std::fs::metadata(&cache_path) {
            if let Ok(modified_at) = meta.modified() {
                if let Ok(elapsed) = modified_at.elapsed() {
                    if elapsed < MODELS_DEV_RUNTIME_TTL {
                        return Ok(());
                    }
                }
            }
        }
    }

    let resp = http_client
        .get(MODELS_DEV_SOURCE_URL)
        .timeout(Duration::from_secs(20))
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("request models.dev failed: {e}"))?;
    if !resp.status().is_success() {
        anyhow::bail!("models.dev returned status {}", resp.status());
    }
    let body = resp
        .text()
        .await
        .map_err(|e| anyhow::anyhow!("read models.dev body failed: {e}"))?;

    // Validate payload shape before replacing local cache.
    let _: HashMap<String, ModelsDevVendor> = serde_json::from_str(&body)
        .map_err(|e| anyhow::anyhow!("invalid models.dev payload: {e}"))?;

    std::fs::create_dir_all(data_dir)?;
    let tmp_path = data_dir.join(format!("{MODELS_DEV_RUNTIME_FILE}.tmp"));
    std::fs::write(&tmp_path, body.as_bytes())?;
    std::fs::rename(&tmp_path, &cache_path)?;
    Ok(())
}

fn parse_provider_presets_snapshot() -> anyhow::Result<Vec<Value>> {
    let parsed = serde_json::from_str::<Value>(PROVIDER_PRESETS_SNAPSHOT)
        .map_err(|e| anyhow::anyhow!("invalid providers preset snapshot: {e}"))?;
    let Some(items) = parsed.as_array() else {
        anyhow::bail!("invalid providers preset snapshot: root must be array");
    };
    Ok(items.clone())
}

fn parse_models_dev_data(data_dir: &Path) -> anyhow::Result<HashMap<String, ModelsDevVendor>> {
    let cache_path = models_dev_runtime_cache_path(data_dir);
    if let Ok(content) = std::fs::read_to_string(&cache_path) {
        if let Ok(parsed) = serde_json::from_str::<HashMap<String, ModelsDevVendor>>(&content) {
            return Ok(parsed);
        }
        tracing::warn!(
            "invalid models.dev runtime cache at {}, fallback to embedded snapshot",
            cache_path.display()
        );
    }
    parse_models_dev_snapshot()
}

fn lookup_models_dev_models(data_dir: &Path, source: &str) -> anyhow::Result<Option<Vec<String>>> {
    let ResolvedSource::ModelsDev(vendor_key) = parse_source(source) else {
        return Ok(None);
    };
    let data = parse_models_dev_data(data_dir)?;
    if vendor_key.trim().is_empty() {
        let mut models = data
            .values()
            .flat_map(|vendor| vendor.models.keys().cloned())
            .collect::<Vec<_>>();
        models.sort();
        models.dedup();
        return Ok(Some(models));
    }
    let Some(vendor) = data.get(vendor_key) else {
        return Ok(Some(Vec::new()));
    };
    let mut models = vendor.models.keys().cloned().collect::<Vec<_>>();
    models.sort();
    Ok(Some(models))
}

fn lookup_models_dev_capability(
    data_dir: &Path,
    vendor_key: &str,
    model: &str,
) -> Option<ModelCapabilities> {
    let data = parse_models_dev_data(data_dir).ok()?;
    match_models_dev_capability(&data, vendor_key, model)
}

fn fuzzy_match_models_dev(data_dir: &Path, model: &str) -> Option<ModelCapabilities> {
    let data = parse_models_dev_data(data_dir).ok()?;
    match_models_dev_capability(&data, "", model)
}

fn match_models_dev_capability(
    data: &HashMap<String, ModelsDevVendor>,
    vendor_key: &str,
    model: &str,
) -> Option<ModelCapabilities> {
    let needle = model.trim().to_lowercase();
    if needle.is_empty() {
        return None;
    }

    if vendor_key.trim().is_empty() {
        for (vk, vendor) in data {
            for (model_id, entry) in &vendor.models {
                if model_id.eq_ignore_ascii_case(model) {
                    return Some(to_models_dev_capability(vk, entry));
                }
            }
        }
        let mut best: Option<(usize, ModelCapabilities)> = None;
        for (vk, vendor) in data {
            for (model_id, entry) in &vendor.models {
                if model_id.to_lowercase().contains(&needle) {
                    let cap = to_models_dev_capability(vk, entry);
                    let len = model_id.len();
                    let replace = best
                        .as_ref()
                        .map(|(prev_len, _)| len < *prev_len)
                        .unwrap_or(true);
                    if replace {
                        best = Some((len, cap));
                    }
                }
            }
        }
        return best.map(|(_, cap)| cap);
    }

    let vendor = data.get(vendor_key)?;
    for (model_id, entry) in &vendor.models {
        if model_id.eq_ignore_ascii_case(model) {
            return Some(to_models_dev_capability(vendor_key, entry));
        }
    }
    let mut best: Option<(usize, ModelCapabilities)> = None;
    for (model_id, entry) in &vendor.models {
        if model_id.to_lowercase().contains(&needle) {
            let cap = to_models_dev_capability(vendor_key, entry);
            let len = model_id.len();
            let replace = best
                .as_ref()
                .map(|(prev_len, _)| len < *prev_len)
                .unwrap_or(true);
            if replace {
                best = Some((len, cap));
            }
        }
    }
    best.map(|(_, cap)| cap)
}

fn parse_http_capability(json: &Value, model: &str) -> Option<ModelCapabilities> {
    let arr = json.get("data").and_then(Value::as_array)?;
    let item = arr.iter().find(|entry| {
        entry
            .get("id")
            .and_then(Value::as_str)
            .is_some_and(|id| id.eq_ignore_ascii_case(model))
    })?;

    let model_id = item.get("id").and_then(Value::as_str).unwrap_or(model);
    let context_window = item
        .get("context_length")
        .and_then(Value::as_u64)
        .filter(|v| *v > 0)
        .unwrap_or(128 * 1024);
    let output_max_tokens = item
        .get("top_provider")
        .and_then(Value::as_object)
        .and_then(|obj| obj.get("max_completion_tokens"))
        .and_then(Value::as_u64)
        .filter(|v| *v > 0);
    let supported_parameters = item
        .get("supported_parameters")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let input_modalities = item
        .get("architecture")
        .and_then(Value::as_object)
        .and_then(|obj| obj.get("input_modalities"))
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(Value::as_str)
                .map(ToString::to_string)
                .collect::<Vec<_>>()
        })
        .unwrap_or_else(|| vec!["text".to_string()]);
    let output_modalities = item
        .get("architecture")
        .and_then(Value::as_object)
        .and_then(|obj| obj.get("output_modalities"))
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(Value::as_str)
                .map(ToString::to_string)
                .collect::<Vec<_>>()
        })
        .unwrap_or_else(|| vec!["text".to_string()]);
    let input_cost = item
        .get("pricing")
        .and_then(Value::as_object)
        .and_then(|obj| obj.get("prompt"))
        .and_then(parse_maybe_price_per_token);
    let output_cost = item
        .get("pricing")
        .and_then(Value::as_object)
        .and_then(|obj| obj.get("completion"))
        .and_then(parse_maybe_price_per_token);
    let tool_call = supported_parameters
        .iter()
        .any(|v| v.as_str() == Some("tools"));
    let model_lower = model_id.to_lowercase();
    let reasoning = model_lower.contains("reason")
        || model_lower.contains("thinking")
        || model_lower.contains("o1")
        || model_lower.contains("o3")
        || model_lower.contains("o4");

    Some(ModelCapabilities {
        provider: "openrouter".to_string(),
        model_id: model_id.to_string(),
        context_window,
        output_max_tokens,
        tool_call,
        reasoning,
        input_modalities,
        output_modalities,
        input_cost,
        output_cost,
    })
}

fn parse_maybe_price_per_token(value: &Value) -> Option<f64> {
    let parsed = if let Some(v) = value.as_f64() {
        Some(v)
    } else if let Some(s) = value.as_str() {
        s.parse::<f64>().ok()
    } else {
        None
    }?;
    if parsed <= 0.0 {
        return None;
    }
    Some(parsed * 1_000_000.0)
}

#[derive(Debug, Clone, serde::Deserialize)]
struct ModelsDevVendor {
    #[serde(default)]
    models: HashMap<String, ModelsDevModelEntry>,
}

#[derive(Debug, Clone, serde::Deserialize)]
struct ModelsDevModelEntry {
    id: String,
    #[serde(default)]
    reasoning: bool,
    #[serde(default)]
    tool_call: bool,
    #[serde(default)]
    modalities: ModelsDevModalities,
    #[serde(default)]
    cost: ModelsDevCost,
    #[serde(default)]
    limit: ModelsDevLimit,
}

#[derive(Debug, Clone, serde::Deserialize, Default)]
struct ModelsDevModalities {
    #[serde(default)]
    input: Vec<String>,
    #[serde(default)]
    output: Vec<String>,
}

#[derive(Debug, Clone, serde::Deserialize, Default)]
struct ModelsDevCost {
    input: Option<f64>,
    output: Option<f64>,
}

#[derive(Debug, Clone, serde::Deserialize, Default)]
struct ModelsDevLimit {
    context: Option<u64>,
    output: Option<u64>,
}

fn parse_models_dev_snapshot() -> anyhow::Result<HashMap<String, ModelsDevVendor>> {
    let parsed = serde_json::from_str::<HashMap<String, ModelsDevVendor>>(MODELS_DEV_SNAPSHOT)
        .map_err(|e| anyhow::anyhow!("failed to parse models.dev snapshot: {e}"))?;
    Ok(parsed)
}

fn to_models_dev_capability(vendor_key: &str, model: &ModelsDevModelEntry) -> ModelCapabilities {
    let input_modalities = if model.modalities.input.is_empty() {
        vec!["text".to_string()]
    } else {
        model.modalities.input.clone()
    };
    let output_modalities = if model.modalities.output.is_empty() {
        vec!["text".to_string()]
    } else {
        model.modalities.output.clone()
    };

    ModelCapabilities {
        provider: vendor_key.to_string(),
        model_id: model.id.clone(),
        context_window: model.limit.context.filter(|v| *v > 0).unwrap_or(128 * 1024),
        output_max_tokens: model.limit.output.filter(|v| *v > 0),
        tool_call: model.tool_call,
        reasoning: model.reasoning,
        input_modalities,
        output_modalities,
        input_cost: model.cost.input,
        output_cost: model.cost.output,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        build_auth_session_pending_data, default_static_models_for_vendor,
        extract_models_from_response, provider_static_models,
    };
    use crate::auth::types::{
        AuthBindingStatus, AuthScheme, AuthSessionStatus, CreateAuthSession, CredentialBundle,
        UpsertProviderAuthBinding,
    };
    use crate::config::GatewayConfig;
    use crate::db::models::CreateProvider;
    use crate::Gateway;
    use base64::Engine;
    use uuid::Uuid;

    #[test]
    fn extracts_codex_models_from_slug_field() {
        let payload = serde_json::json!({
            "models": [
                { "slug": "gpt-5.4" },
                { "slug": "gpt-5.1-codex-mini" }
            ]
        });

        assert_eq!(
            extract_models_from_response("openai", Some("codex"), &payload),
            vec!["gpt-5.1-codex-mini".to_string(), "gpt-5.4".to_string()]
        );
    }

    #[test]
    fn provides_default_static_models_for_cloud_code() {
        assert_eq!(
            default_static_models_for_vendor(Some("cloud-code")),
            vec!["gemini-2.5-flash".to_string(), "gemini-2.5-pro".to_string()]
        );
    }

    #[test]
    fn extracts_google_gemini_models_from_name_field() {
        let payload = serde_json::json!({
            "models": [
                { "name": "models/gemini-2.5-pro" },
                { "name": "publishers/google/models/gemini-2.5-flash" }
            ]
        });

        assert_eq!(
            extract_models_from_response("gemini", Some("google"), &payload),
            vec!["gemini-2.5-flash".to_string(), "gemini-2.5-pro".to_string()]
        );
    }

    #[test]
    fn configured_static_models_override_vendor_defaults() {
        let provider = crate::db::models::Provider {
            id: "provider".to_string(),
            name: "Cloud Code".to_string(),
            vendor: Some("cloud-code".to_string()),
            protocol: "gemini".to_string(),
            base_url: "https://cloudcode-pa.googleapis.com/v1internal".to_string(),
            default_protocol: "gemini".to_string(),
            protocol_endpoints: "{}".to_string(),
            preset_key: None,
            channel: None,
            models_source: None,
            capabilities_source: None,
            static_models: Some("gemini-2.5-pro, gemini-2.5-pro\n gemini-2.5-flash".to_string()),
            api_key: String::new(),
            use_proxy: false,
            last_test_success: None,
            last_test_at: None,
            is_active: true,
            created_at: String::new(),
            updated_at: String::new(),
        };

        assert_eq!(
            provider_static_models(&provider),
            vec!["gemini-2.5-flash".to_string(), "gemini-2.5-pro".to_string()]
        );
    }

    #[test]
    fn pending_auth_session_marks_pkce_flow_as_manual() {
        let session = crate::auth::types::AuthSession {
            id: "session".to_string(),
            provider_id: None,
            driver_key: "codex".to_string(),
            scheme: AuthScheme::OAuthAuthCodePkce.as_str().to_string(),
            status: AuthSessionStatus::Pending.as_str().to_string(),
            use_proxy: false,
            user_code: None,
            verification_uri: Some("https://auth.openai.com".to_string()),
            verification_uri_complete: Some("https://auth.openai.com/oauth/authorize".to_string()),
            state_json: Some("{}".to_string()),
            context_json: None,
            result_json: None,
            expires_at: Some("2099-01-01 00:00:00".to_string()),
            poll_interval_seconds: Some(2),
            last_error: None,
            created_at: String::new(),
            updated_at: String::new(),
        };

        let status = build_auth_session_pending_data(&session);
        match status {
            crate::auth::types::AuthSessionStatusData::Pending {
                requires_manual_code,
                ..
            } => assert!(requires_manual_code),
            other => panic!("expected pending status, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn oauth_status_for_codex_pending_session_returns_pending() {
        let (gateway, _tmp_dir) = test_gateway().await;
        let store = gateway.storage.auth_sessions().expect("auth session store");
        let session = store
            .create(CreateAuthSession {
                provider_id: None,
                driver_key: "codex".to_string(),
                scheme: AuthScheme::OAuthAuthCodePkce.as_str().to_string(),
                status: AuthSessionStatus::Pending.as_str().to_string(),
                use_proxy: false,
                user_code: None,
                verification_uri: Some("https://auth.openai.com".to_string()),
                verification_uri_complete: Some(
                    "https://auth.openai.com/oauth/authorize".to_string(),
                ),
                state_json: Some("{}".to_string()),
                context_json: None,
                result_json: None,
                expires_at: Some("2099-01-01 00:00:00".to_string()),
                poll_interval_seconds: Some(2),
                last_error: None,
            })
            .await
            .expect("create auth session");

        let status = gateway
            .admin()
            .get_oauth_session_status(&session.id)
            .await
            .expect("get oauth session status");

        match status {
            crate::auth::types::AuthSessionStatusData::Pending {
                requires_manual_code,
                ..
            } => assert!(requires_manual_code),
            other => panic!("expected pending status, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn create_provider_with_oauth_session_persists_binding_and_removes_session() {
        let (gateway, _tmp_dir) = test_gateway().await;
        let store = gateway.storage.auth_sessions().expect("auth session store");
        let fake_token = fake_openai_access_token("acct-test");
        let session = store
            .create(CreateAuthSession {
                provider_id: None,
                driver_key: "codex".to_string(),
                scheme: AuthScheme::OAuthAuthCodePkce.as_str().to_string(),
                status: AuthSessionStatus::Ready.as_str().to_string(),
                use_proxy: false,
                user_code: None,
                verification_uri: Some("https://auth.openai.com".to_string()),
                verification_uri_complete: Some(
                    "https://auth.openai.com/oauth/authorize".to_string(),
                ),
                state_json: Some("{}".to_string()),
                context_json: None,
                result_json: Some(
                    serde_json::to_string(&CredentialBundle {
                        access_token: Some(fake_token.clone()),
                        refresh_token: Some("refresh-token".to_string()),
                        expires_at: Some("2099-01-01T00:00:00Z".to_string()),
                        resource_url: None,
                        subject_id: Some("subject".to_string()),
                        scopes: vec!["openid".to_string()],
                        raw: serde_json::json!({}),
                    })
                    .expect("serialize credential bundle"),
                ),
                expires_at: Some("2099-01-01 00:00:00".to_string()),
                poll_interval_seconds: Some(2),
                last_error: None,
            })
            .await
            .expect("create auth session");

        let provider = gateway
            .admin()
            .create_provider_with_oauth_session(
                &session.id,
                CreateProvider {
                    name: "OAuth Provider".to_string(),
                    vendor: None,
                    protocol: "openai".to_string(),
                    base_url: "https://example.invalid/v1".to_string(),
                    default_protocol: Some("openai".to_string()),
                    protocol_endpoints: Some("{}".to_string()),
                    preset_key: None,
                    channel: None,
                    models_source: None,
                    capabilities_source: None,
                    static_models: None,
                    api_key: String::new(),
                    use_proxy: false,
                },
            )
            .await
            .expect("create provider with oauth session");

        assert_eq!(provider.vendor.as_deref(), Some("codex"));
        assert!(provider.base_url.contains("chatgpt.com/backend-api/codex"));
        assert_eq!(provider.api_key, fake_token);
        assert!(
            gateway
                .storage
                .auth_sessions()
                .expect("auth session store")
                .get(&session.id)
                .await
                .expect("get session")
                .is_none()
        );
        let binding = gateway
            .storage
            .provider_auth_bindings()
            .expect("binding store")
            .get_by_provider_and_driver(&provider.id, "codex")
            .await
            .expect("get binding")
            .expect("binding exists");
        assert_eq!(binding.status, AuthBindingStatus::Connected.as_str());
        assert_eq!(binding.access_token.as_deref(), Some(fake_token.as_str()));
    }

    #[tokio::test]
    async fn logout_provider_oauth_clears_binding_and_api_key() {
        let (gateway, _tmp_dir) = test_gateway().await;
        let provider = gateway
            .admin()
            .create_provider(CreateProvider {
                name: "Codex Provider".to_string(),
                vendor: Some("codex".to_string()),
                protocol: "openai".to_string(),
                base_url: "https://chatgpt.com/backend-api/codex".to_string(),
                default_protocol: Some("openai".to_string()),
                protocol_endpoints: Some(
                    serde_json::json!({"openai": {"base_url": "https://chatgpt.com/backend-api/codex"}})
                        .to_string(),
                ),
                preset_key: None,
                channel: None,
                models_source: None,
                capabilities_source: None,
                static_models: None,
                api_key: "access-token".to_string(),
                use_proxy: false,
            })
            .await
            .expect("create provider");

        gateway
            .storage
            .provider_auth_bindings()
            .expect("binding store")
            .upsert(UpsertProviderAuthBinding {
                provider_id: provider.id.clone(),
                driver_key: "codex".to_string(),
                scheme: AuthScheme::OAuthAuthCodePkce.as_str().to_string(),
                status: AuthBindingStatus::Connected.as_str().to_string(),
                access_token: Some("access-token".to_string()),
                refresh_token: Some("refresh-token".to_string()),
                expires_at: Some("2099-01-01T00:00:00Z".to_string()),
                resource_url: None,
                subject_id: None,
                scopes_json: Some("[]".to_string()),
                meta_json: Some("{}".to_string()),
                last_error: None,
            })
            .await
            .expect("upsert binding");

        let status = gateway
            .admin()
            .logout_provider_oauth(&provider.id)
            .await
            .expect("logout provider oauth");

        assert_eq!(status.status, AuthBindingStatus::Disconnected.as_str());
        assert!(
            gateway
                .storage
                .provider_auth_bindings()
                .expect("binding store")
                .get_by_provider_and_driver(&provider.id, "codex")
                .await
                .expect("get binding")
                .is_none()
        );
        let updated_provider = gateway
            .storage
            .providers()
            .get(&provider.id)
            .await
            .expect("get provider")
            .expect("provider exists");
        assert!(updated_provider.api_key.is_empty());
    }

    async fn test_gateway() -> (Gateway, std::path::PathBuf) {
        let data_dir = std::env::temp_dir().join(format!("nyro-admin-test-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&data_dir).expect("create temp data dir");
        let config = GatewayConfig {
            data_dir: data_dir.clone(),
            ..GatewayConfig::default()
        };
        let (gateway, _log_rx) = Gateway::new(config).await.expect("create gateway");
        (gateway, data_dir)
    }

    fn fake_openai_access_token(account_id: &str) -> String {
        let header = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(r#"{"alg":"none"}"#);
        let claims = serde_json::json!({
            "https://api.openai.com/auth": {
                "chatgpt_account_id": account_id
            }
        });
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&claims).expect("serialize claims"));
        format!("{header}.{payload}.sig")
    }
}
