use anyhow::{Context, anyhow};
use reqwest::Method;
use serde::Serialize;
use serde::de::DeserializeOwned;

#[derive(Clone, Debug)]
pub struct AdminClient {
    http: reqwest::Client,
    base_url: String,
    admin_key: Option<String>,
}

impl AdminClient {
    pub fn new(base_url: impl Into<String>, admin_key: Option<String>) -> Self {
        Self {
            http: reqwest::Client::new(),
            base_url: base_url.into().trim_end_matches('/').to_string(),
            admin_key: admin_key.filter(|value| !value.trim().is_empty()),
        }
    }

    pub async fn get<T: DeserializeOwned>(&self, path: &str) -> anyhow::Result<T> {
        self.request::<(), T>(Method::GET, path, None).await
    }

    pub async fn delete<T: DeserializeOwned>(&self, path: &str) -> anyhow::Result<T> {
        self.request::<(), T>(Method::DELETE, path, None).await
    }

    pub async fn post<B: Serialize + ?Sized, T: DeserializeOwned>(
        &self,
        path: &str,
        body: &B,
    ) -> anyhow::Result<T> {
        self.request(Method::POST, path, Some(body)).await
    }

    pub async fn put<B: Serialize + ?Sized, T: DeserializeOwned>(
        &self,
        path: &str,
        body: &B,
    ) -> anyhow::Result<T> {
        self.request(Method::PUT, path, Some(body)).await
    }

    async fn request<B: Serialize + ?Sized, T: DeserializeOwned>(
        &self,
        method: Method,
        path: &str,
        body: Option<&B>,
    ) -> anyhow::Result<T> {
        let url = format!("{}{}", self.base_url, path);
        let mut req = self.http.request(method, &url);
        if let Some(admin_key) = &self.admin_key {
            req = req.bearer_auth(admin_key);
        }
        if let Some(body) = body {
            req = req.json(body);
        }
        let resp = req.send().await.with_context(|| format!("request {url}"))?;
        let status = resp.status();
        let text = resp.text().await.context("read response body")?;
        if !status.is_success() {
            return Err(anyhow!("HTTP {}: {}", status.as_u16(), text.trim()));
        }
        if text.trim().is_empty() {
            return serde_json::from_value(serde_json::json!({})).context("decode empty response");
        }
        let value: serde_json::Value = serde_json::from_str(&text).context("parse json body")?;
        if let Some(err) = value.get("error") {
            let msg = err
                .as_str()
                .map(ToOwned::to_owned)
                .unwrap_or_else(|| err.to_string());
            return Err(anyhow!(msg));
        }
        let payload = value.get("data").cloned().unwrap_or(value);
        serde_json::from_value(payload).context("decode response payload")
    }
}

#[derive(Clone, Debug)]
pub struct ProxyClient {
    http: reqwest::Client,
    base_url: String,
    api_key: String,
}

impl ProxyClient {
    pub fn new(base_url: impl Into<String>, api_key: impl Into<String>) -> Self {
        Self {
            http: reqwest::Client::new(),
            base_url: base_url.into().trim_end_matches('/').to_string(),
            api_key: api_key.into(),
        }
    }

    pub async fn responses<B: Serialize + ?Sized, T: DeserializeOwned>(
        &self,
        body: &B,
    ) -> anyhow::Result<T> {
        self.post_proxy_json("/v1/responses", body).await
    }

    pub async fn chat_completions<B: Serialize + ?Sized, T: DeserializeOwned>(
        &self,
        body: &B,
    ) -> anyhow::Result<T> {
        self.post_proxy_json("/v1/chat/completions", body).await
    }

    pub async fn messages<B: Serialize + ?Sized, T: DeserializeOwned>(
        &self,
        body: &B,
    ) -> anyhow::Result<T> {
        self.post_proxy_json("/v1/messages", body).await
    }

    async fn post_proxy_json<B: Serialize + ?Sized, T: DeserializeOwned>(
        &self,
        path: &str,
        body: &B,
    ) -> anyhow::Result<T> {
        let url = format!("{}{}", self.base_url, path);
        let resp = self
            .http
            .post(&url)
            .bearer_auth(&self.api_key)
            .json(body)
            .send()
            .await
            .with_context(|| format!("request {url}"))?;
        let status = resp.status();
        let text = resp.text().await.context("read proxy response")?;
        if !status.is_success() {
            return Err(anyhow!("HTTP {}: {}", status.as_u16(), text.trim()));
        }
        serde_json::from_str(&text).context("parse proxy json body")
    }
}
