use std::convert::Infallible;
use std::collections::HashMap;
use std::time::Instant;

use async_trait::async_trait;
use axum::Json;
use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use chrono::{NaiveDateTime, Utc};
use futures::StreamExt;
use serde_json::Value;
use tokio_stream::wrappers::ReceiverStream;

use crate::Gateway;
use crate::auth::{self, RuntimeBinding};
use crate::db::models::{Provider, Route, RouteTarget};
use crate::logging::LogEntry;
use crate::protocol::gemini::decoder::GeminiDecoder;
use crate::protocol::types::*;
use crate::protocol::{Protocol, ProviderProtocols};
use crate::proxy::adapter::{self, ProviderAdapter};
use crate::proxy::client::ProxyClient;
use crate::router::TargetSelector;
use crate::storage::traits::{ApiKeyAccessRecord, UsageWindow};

// ── OpenAI ingress: POST /v1/chat/completions ──

pub async fn openai_proxy(
    State(gw): State<Gateway>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    universal_proxy(gw, headers, body, Protocol::OpenAI).await
}

// ── OpenAI Responses API ingress: POST /v1/responses ──

pub async fn responses_proxy(
    State(gw): State<Gateway>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    universal_proxy(gw, headers, body, Protocol::ResponsesAPI).await
}

// ── Anthropic ingress: POST /v1/messages ──

pub async fn anthropic_proxy(
    State(gw): State<Gateway>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    universal_proxy(gw, headers, body, Protocol::Anthropic).await
}

// ── Gemini ingress: POST /v1beta/models/:model_action ──

pub async fn gemini_proxy(
    State(gw): State<Gateway>,
    headers: HeaderMap,
    Path(model_action): Path<String>,
    Json(body): Json<Value>,
) -> Response {
    let (model, action) = match model_action.rsplit_once(':') {
        Some((m, a)) => (m.to_string(), a.to_string()),
        None => (model_action.clone(), "generateContent".to_string()),
    };
    let is_stream = action == "streamGenerateContent";

    let decoder = GeminiDecoder;
    let internal = match decoder.decode_with_model(body, &model, is_stream) {
        Ok(r) => r,
        Err(e) => return error_response(400, &format!("invalid Gemini request: {e}")),
    };

    proxy_pipeline(gw, headers, internal, Protocol::Gemini).await
}

// ── Universal proxy pipeline ──

async fn universal_proxy(
    gw: Gateway,
    headers: HeaderMap,
    body: Value,
    ingress: Protocol,
) -> Response {
    let decoder = crate::protocol::get_decoder(ingress);
    let internal = match decoder.decode_request(body) {
        Ok(r) => r,
        Err(e) => return error_response(400, &format!("invalid request: {e}")),
    };

    proxy_pipeline(gw, headers, internal, ingress).await
}

async fn proxy_pipeline(
    gw: Gateway,
    headers: HeaderMap,
    internal: InternalRequest,
    ingress: Protocol,
) -> Response {
    let start = Instant::now();
    let request_model = internal.model.clone();
    let is_stream = internal.stream;

    let ingress_str = ingress.to_string();
    let route = {
        let cache = gw.route_cache.read().await;
        cache.match_route(&request_model).cloned()
    };
    let route = match route {
        Some(r) => r,
        None => return error_response(404, &format!("no route for model: {request_model}")),
    };

    let access_store = GatewayProxyAccessStore::new(&gw);

    let auth_key = match authorize_route_access(&access_store, &route, &headers).await {
        Ok(v) => v,
        Err(resp) => return resp,
    };

    let targets = load_route_targets(&gw, &route).await;
    if targets.is_empty() {
        return error_response(503, "no route targets configured");
    }
    let ordered_targets = TargetSelector::select_ordered(&route.strategy, &targets);
    if ordered_targets.is_empty() {
        return error_response(503, "no route targets configured");
    }

    let mut last_response: Option<Response> = None;
    for target in ordered_targets {
        let target_key = format!("{}:{}", target.provider_id, target.model);
        if !gw.health_registry.is_healthy(&target_key) {
            continue;
        }
        let provider = match get_provider(&access_store, &target.provider_id).await {
            Ok(p) => p,
            Err(_) => continue,
        };
        let runtime = match resolve_provider_runtime(&gw, &provider).await {
            Ok(value) => value,
            Err(e) => {
                last_response = Some(error_response(
                    502,
                    &format!("provider credential error: {e}"),
                ));
                continue;
            }
        };
        let actual_model = if target.model.is_empty() || target.model == "*" {
            resolve_runtime_model_alias(&request_model, &runtime.binding, true)
        } else {
            resolve_runtime_model_alias(&target.model, &runtime.binding, false)
        };

        let mut internal_for_target = internal.clone();
        crate::protocol::semantic::tool_correlation::normalize_request_tool_results(
            &mut internal_for_target,
        );

        let provider_protocols = ProviderProtocols::from_provider(&provider);
        let resolved = provider_protocols.resolve_egress(ingress);
        let mut egress = resolved.protocol;
        let mut egress_base_url = if resolved.base_url.is_empty() {
            provider.base_url.clone()
        } else {
            resolved.base_url
        };
        if let Some(base_url_override) = runtime.binding.base_url_override.clone() {
            egress_base_url = base_url_override;
        }

        let adapter = adapter::get_adapter(&provider, egress);
        adapter
            .pre_request(&mut internal_for_target, &actual_model, &gw, &provider)
            .await;

        let use_codex_responses = is_codex_provider(&provider)
            && matches!(ingress, Protocol::OpenAI | Protocol::ResponsesAPI);

        if use_codex_responses {
            egress = Protocol::ResponsesAPI;
        }

        let (egress_body, extra_headers, egress_path, force_upstream_stream) =
            if use_codex_responses {
                match encode_codex_responses_request(&internal_for_target, &actual_model) {
                    Ok((body, headers)) => (body, headers, "/responses".to_string(), true),
                    Err(e) => {
                        last_response = Some(error_response(500, &format!("encode error: {e}")));
                        continue;
                    }
                }
            } else {
                let encoder = crate::protocol::get_encoder(egress);
                let (body, headers) = match encoder.encode_request(&internal_for_target) {
                    Ok(r) => r,
                    Err(e) => {
                        last_response = Some(error_response(500, &format!("encode error: {e}")));
                        continue;
                    }
                };
                (
                    body,
                    headers,
                    encoder.egress_path(&actual_model, is_stream),
                    false,
                )
            };

        let mut extra_headers = extra_headers;
        if let Err(e) = append_runtime_headers(&mut extra_headers, &runtime.binding) {
            last_response = Some(error_response(500, &format!("encode error: {e}")));
            continue;
        }

        let egress_body = override_model(egress_body, &actual_model, egress);
        let client = match gw.http_client_for_provider(provider.use_proxy).await {
            Ok(http_client) => ProxyClient::new(http_client),
            Err(e) => {
                let msg = format!("provider transport error: {e}");
                last_response = Some(error_response(502, &msg));
                continue;
            }
        };
        let egress_str = egress.to_string();

        let response = if is_stream || force_upstream_stream {
            if !is_stream && force_upstream_stream {
                handle_non_stream_from_upstream_stream(
                    gw.clone(),
                    client,
                    adapter.as_ref(),
                    &provider,
                    &egress_base_url,
                    egress,
                    ingress,
                    &egress_path,
                    &runtime.access_token,
                    runtime.binding.disable_default_auth,
                    egress_body,
                    extra_headers,
                    &ingress_str,
                    &egress_str,
                    &request_model,
                    &actual_model,
                    auth_key.id.as_deref(),
                    start,
                )
                .await
            } else {
                handle_stream(
                    gw.clone(),
                    client,
                    adapter.as_ref(),
                    &provider,
                    &egress_base_url,
                    egress,
                    ingress,
                    &egress_path,
                    &runtime.access_token,
                    runtime.binding.disable_default_auth,
                    egress_body,
                    extra_headers,
                    &ingress_str,
                    &egress_str,
                    &request_model,
                    &actual_model,
                    auth_key.id.as_deref(),
                    start,
                )
                .await
            }
        } else {
            handle_non_stream(
                gw.clone(),
                client,
                adapter.as_ref(),
                &provider,
                &egress_base_url,
                egress,
                ingress,
                &egress_path,
                &runtime.access_token,
                runtime.binding.disable_default_auth,
                egress_body,
                extra_headers,
                &ingress_str,
                &egress_str,
                &request_model,
                &actual_model,
                auth_key.id.as_deref(),
                start,
            )
            .await
        };

        let status = response.status().as_u16();
        if status < 400 {
            gw.health_registry.record_success(&target_key);
            return response;
        }
        gw.health_registry.record_failure(&target_key);
        if is_retryable(status) {
            last_response = Some(response);
            continue;
        }
        return response;
    }

    last_response.unwrap_or_else(|| error_response(502, "all route targets failed"))
}

#[allow(clippy::too_many_arguments)]
async fn handle_non_stream(
    gw: Gateway,
    client: ProxyClient,
    adapter: &dyn ProviderAdapter,
    provider: &Provider,
    egress_base_url: &str,
    egress: Protocol,
    ingress: Protocol,
    path: &str,
    credential: &str,
    disable_default_auth: bool,
    body: Value,
    extra_headers: reqwest::header::HeaderMap,
    ingress_str: &str,
    egress_str: &str,
    request_model: &str,
    actual_model: &str,
    api_key_id: Option<&str>,
    start: Instant,
) -> Response {
    let credential_to_use = credential.to_string();
    let call_result = match client
        .call_non_stream(
            adapter,
            egress_base_url,
            path,
            &credential_to_use,
            disable_default_auth,
            body.clone(),
            extra_headers.clone(),
        )
        .await
    {
        Ok(r) => r,
        Err(e) => {
            emit_log(
                &gw,
                ingress_str,
                egress_str,
                request_model,
                actual_model,
                api_key_id,
                &provider.name,
                502,
                start.elapsed().as_millis() as f64,
                TokenUsage::default(),
                false,
                false,
                Some(e.to_string()),
                None,
            );
            return error_response(502, &format!("upstream error: {e}"));
        }
    };

    let (resp, status) = call_result;

    if status >= 400 {
        let preview = serde_json::to_string(&resp)
            .ok()
            .map(|s| s.chars().take(500).collect());
        emit_log(
            &gw,
            ingress_str,
            egress_str,
            request_model,
            actual_model,
            api_key_id,
            &provider.name,
            status as i32,
            start.elapsed().as_millis() as f64,
            TokenUsage::default(),
            false,
            false,
            preview.clone(),
            None,
        );
        return (
            StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_GATEWAY),
            Json(resp),
        )
            .into_response();
    }

    let parser = crate::protocol::get_response_parser(egress);
    let formatter = crate::protocol::get_response_formatter(ingress);

    let mut internal_resp = match parser.parse_response(resp) {
        Ok(r) => r,
        Err(e) => return error_response(500, &format!("parse error: {e}")),
    };
    crate::protocol::semantic::reasoning::normalize_response_reasoning(&mut internal_resp);
    crate::protocol::semantic::response_items::populate_response_items(&mut internal_resp);

    let is_tool = !internal_resp.tool_calls.is_empty();
    let usage = internal_resp.usage.clone();
    let output = formatter.format_response(&internal_resp);

    let response_preview = serde_json::to_string(&output)
        .ok()
        .map(|s| s.chars().take(500).collect());

    emit_log(
        &gw,
        ingress_str,
        egress_str,
        request_model,
        actual_model,
        api_key_id,
        &provider.name,
        status as i32,
        start.elapsed().as_millis() as f64,
        usage,
        false,
        is_tool,
        None,
        response_preview,
    );

    (
        StatusCode::from_u16(status).unwrap_or(StatusCode::OK),
        Json(output),
    )
        .into_response()
}

#[allow(clippy::too_many_arguments)]
async fn handle_stream(
    gw: Gateway,
    client: ProxyClient,
    adapter: &dyn ProviderAdapter,
    provider: &Provider,
    egress_base_url: &str,
    egress: Protocol,
    ingress: Protocol,
    path: &str,
    credential: &str,
    disable_default_auth: bool,
    body: Value,
    extra_headers: reqwest::header::HeaderMap,
    ingress_str: &str,
    egress_str: &str,
    request_model: &str,
    actual_model: &str,
    api_key_id: Option<&str>,
    start: Instant,
) -> Response {
    let credential_to_use = credential.to_string();
    let call_result = match client
        .call_stream(
            adapter,
            egress_base_url,
            path,
            &credential_to_use,
            disable_default_auth,
            body.clone(),
            extra_headers.clone(),
        )
        .await
    {
        Ok(r) => r,
        Err(e) => {
            emit_log(
                &gw,
                ingress_str,
                egress_str,
                request_model,
                actual_model,
                api_key_id,
                &provider.name,
                502,
                start.elapsed().as_millis() as f64,
                TokenUsage::default(),
                true,
                false,
                Some(e.to_string()),
                None,
            );
            return error_response(502, &format!("upstream error: {e}"));
        }
    };

    let (resp, status) = call_result;

    if status >= 400 {
        let err_body: Value = resp
            .json()
            .await
            .unwrap_or_else(|_| serde_json::json!({"error": {"message": "upstream error"}}));
        emit_log(
            &gw,
            ingress_str,
            egress_str,
            request_model,
            actual_model,
            api_key_id,
            &provider.name,
            status as i32,
            start.elapsed().as_millis() as f64,
            TokenUsage::default(),
            true,
            false,
            Some(err_body.to_string()),
            None,
        );
        return (
            StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_GATEWAY),
            Json(err_body),
        )
            .into_response();
    }

    let mut stream_parser = crate::protocol::get_stream_parser(egress);
    let mut stream_formatter = crate::protocol::get_stream_formatter(ingress);

    let mut byte_stream = resp.bytes_stream();
    let (tx, rx) = tokio::sync::mpsc::channel::<Result<String, Infallible>>(64);

    let gw_log = gw.clone();
    let provider_name = provider.name.clone();
    let ingress_s = ingress_str.to_string();
    let egress_s = egress_str.to_string();
    let req_model = request_model.to_string();
    let act_model = actual_model.to_string();
    let key_id = api_key_id.map(ToString::to_string);

    tokio::spawn(async move {
        while let Some(chunk) = byte_stream.next().await {
            let bytes = match chunk {
                Ok(b) => b,
                Err(_) => break,
            };
            let text = String::from_utf8_lossy(&bytes);
            if let Ok(deltas) = stream_parser.parse_chunk(&text) {
                let events = stream_formatter.format_deltas(&deltas);
                for ev in events {
                    if tx.send(Ok(ev.to_sse_string())).await.is_err() {
                        return;
                    }
                }
            }
        }

        if let Ok(deltas) = stream_parser.finish() {
            let events = stream_formatter.format_deltas(&deltas);
            for ev in events {
                let _ = tx.send(Ok(ev.to_sse_string())).await;
            }
        }

        let done_events = stream_formatter.format_done();
        for ev in done_events {
            let _ = tx.send(Ok(ev.to_sse_string())).await;
        }

        let usage = stream_formatter.usage();
        emit_log(
            &gw_log,
            &ingress_s,
            &egress_s,
            &req_model,
            &act_model,
            key_id.as_deref(),
            &provider_name,
            200,
            start.elapsed().as_millis() as f64,
            usage,
            true,
            false,
            None,
            None,
        );
    });

    let stream = ReceiverStream::new(rx);
    let body = Body::from_stream(stream);

    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/event-stream")
        .header(header::CACHE_CONTROL, "no-cache")
        .header(header::CONNECTION, "keep-alive")
        .body(body)
        .unwrap()
}

#[allow(clippy::too_many_arguments)]
async fn handle_non_stream_from_upstream_stream(
    gw: Gateway,
    client: ProxyClient,
    adapter: &dyn ProviderAdapter,
    provider: &Provider,
    egress_base_url: &str,
    egress: Protocol,
    ingress: Protocol,
    path: &str,
    credential: &str,
    disable_default_auth: bool,
    body: Value,
    extra_headers: reqwest::header::HeaderMap,
    ingress_str: &str,
    egress_str: &str,
    request_model: &str,
    actual_model: &str,
    api_key_id: Option<&str>,
    start: Instant,
) -> Response {
    let credential_to_use = credential.to_string();
    let call_result = match client
        .call_stream(
            adapter,
            egress_base_url,
            path,
            &credential_to_use,
            disable_default_auth,
            body.clone(),
            extra_headers.clone(),
        )
        .await
    {
        Ok(r) => r,
        Err(e) => {
            emit_log(
                &gw,
                ingress_str,
                egress_str,
                request_model,
                actual_model,
                api_key_id,
                &provider.name,
                502,
                start.elapsed().as_millis() as f64,
                TokenUsage::default(),
                false,
                false,
                Some(e.to_string()),
                None,
            );
            return error_response(502, &format!("upstream error: {e}"));
        }
    };

    let (resp, status) = call_result;

    if status >= 400 {
        let err_body: Value = resp
            .json()
            .await
            .unwrap_or_else(|_| serde_json::json!({"error": {"message": "upstream error"}}));
        emit_log(
            &gw,
            ingress_str,
            egress_str,
            request_model,
            actual_model,
            api_key_id,
            &provider.name,
            status as i32,
            start.elapsed().as_millis() as f64,
            TokenUsage::default(),
            false,
            false,
            Some(err_body.to_string()),
            None,
        );
        return (
            StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_GATEWAY),
            Json(err_body),
        )
            .into_response();
    }

    let mut stream_parser = crate::protocol::get_stream_parser(egress);
    let mut byte_stream = resp.bytes_stream();
    let mut aggregate = StreamAccumulator::default();

    while let Some(chunk) = byte_stream.next().await {
        let bytes = match chunk {
            Ok(b) => b,
            Err(e) => {
                emit_log(
                    &gw,
                    ingress_str,
                    egress_str,
                    request_model,
                    actual_model,
                    api_key_id,
                    &provider.name,
                    502,
                    start.elapsed().as_millis() as f64,
                    TokenUsage::default(),
                    false,
                    false,
                    Some(e.to_string()),
                    None,
                );
                return error_response(502, &format!("upstream stream error: {e}"));
            }
        };
        let text = String::from_utf8_lossy(&bytes);
        match stream_parser.parse_chunk(&text) {
            Ok(deltas) => aggregate.apply_all(&deltas),
            Err(e) => return error_response(500, &format!("parse error: {e}")),
        }
    }

    match stream_parser.finish() {
        Ok(deltas) => aggregate.apply_all(&deltas),
        Err(e) => return error_response(500, &format!("parse error: {e}")),
    }

    let internal_resp = aggregate.into_internal_response();
    let formatter = crate::protocol::get_response_formatter(ingress);
    let output = formatter.format_response(&internal_resp);
    let response_preview = serde_json::to_string(&output)
        .ok()
        .map(|s| s.chars().take(500).collect());

    emit_log(
        &gw,
        ingress_str,
        egress_str,
        request_model,
        actual_model,
        api_key_id,
        &provider.name,
        200,
        start.elapsed().as_millis() as f64,
        internal_resp.usage.clone(),
        false,
        !internal_resp.tool_calls.is_empty(),
        None,
        response_preview,
    );

    (StatusCode::OK, Json(output)).into_response()
}

// ── Helpers ──

#[derive(Default)]
struct StreamAccumulator {
    id: String,
    model: String,
    content: String,
    usage: TokenUsage,
    stop_reason: Option<String>,
    tool_calls: Vec<ToolCall>,
}

impl StreamAccumulator {
    fn apply_all(&mut self, deltas: &[StreamDelta]) {
        for delta in deltas {
            match delta {
                StreamDelta::MessageStart { id, model } => {
                    if self.id.is_empty() {
                        self.id = id.clone();
                    }
                    if self.model.is_empty() {
                        self.model = model.clone();
                    }
                }
                StreamDelta::TextDelta(text) => self.content.push_str(text),
                StreamDelta::ToolCallStart { index, id, name } => {
                    if self.tool_calls.len() <= *index {
                        self.tool_calls.resize_with(index + 1, || ToolCall {
                            id: String::new(),
                            name: String::new(),
                            arguments: String::new(),
                        });
                    }
                    self.tool_calls[*index].id = id.clone();
                    self.tool_calls[*index].name = name.clone();
                }
                StreamDelta::ToolCallDelta { index, arguments } => {
                    if self.tool_calls.len() <= *index {
                        self.tool_calls.resize_with(index + 1, || ToolCall {
                            id: String::new(),
                            name: String::new(),
                            arguments: String::new(),
                        });
                    }
                    self.tool_calls[*index].arguments.push_str(arguments);
                }
                StreamDelta::Usage(usage) => self.usage = usage.clone(),
                StreamDelta::Done { stop_reason } => self.stop_reason = Some(stop_reason.clone()),
                StreamDelta::ReasoningDelta(_) => {}
            }
        }
    }

    fn into_internal_response(self) -> InternalResponse {
        InternalResponse {
            id: self.id,
            model: self.model,
            content: self.content,
            reasoning_content: None,
            tool_calls: self
                .tool_calls
                .into_iter()
                .filter(|tc| !tc.id.is_empty() || !tc.name.is_empty() || !tc.arguments.is_empty())
                .collect(),
            response_items: None,
            stop_reason: self.stop_reason,
            usage: self.usage,
        }
    }
}

fn is_codex_provider(provider: &Provider) -> bool {
    provider
        .vendor
        .as_deref()
        .map(auth::normalize_driver_key)
        .as_deref()
        == Some("codex")
}

fn encode_codex_responses_request(
    req: &InternalRequest,
    model: &str,
) -> anyhow::Result<(Value, reqwest::header::HeaderMap)> {
    let mut instructions = Vec::new();
    let mut input = Vec::new();

    for message in &req.messages {
        match message.role {
            Role::System => {
                let text = message.content.as_text();
                if !text.is_empty() {
                    instructions.push(text);
                }
            }
            Role::User | Role::Assistant => {
                let text = message.content.as_text();
                if !text.is_empty() {
                    input.push(serde_json::json!({
                        "type": "message",
                        "role": match message.role {
                            Role::User => "user",
                            Role::Assistant => "assistant",
                            _ => unreachable!(),
                        },
                        "content": [{
                            "type": "input_text",
                            "text": text,
                        }]
                    }));
                }
                if let Some(tool_calls) = &message.tool_calls {
                    for tool_call in tool_calls {
                        input.push(serde_json::json!({
                            "type": "function_call",
                            "call_id": tool_call.id,
                            "name": tool_call.name,
                            "arguments": tool_call.arguments,
                        }));
                    }
                }
            }
            Role::Tool => {
                input.push(serde_json::json!({
                    "type": "function_call_output",
                    "call_id": message.tool_call_id.clone().unwrap_or_default(),
                    "output": message.content.as_text(),
                }));
            }
        }
    }

    if input.is_empty() {
        anyhow::bail!("codex request requires at least one input item");
    }

    let mut body = serde_json::json!({
        "model": model,
        "store": false,
        "stream": true,
        "instructions": if instructions.is_empty() {
            "You are a helpful assistant."
        } else {
            ""
        },
        "input": input,
    });

    if !instructions.is_empty() {
        body.as_object_mut().unwrap().insert(
            "instructions".into(),
            Value::String(instructions.join("\n\n")),
        );
    }

    let obj = body.as_object_mut().unwrap();
    if let Some(t) = req.temperature {
        obj.insert("temperature".into(), t.into());
    }
    if let Some(m) = req.max_tokens {
        obj.insert("max_output_tokens".into(), m.into());
    }
    if let Some(p) = req.top_p {
        obj.insert("top_p".into(), p.into());
    }
    if let Some(ref tools) = req.tools {
        let tools_val: Vec<Value> = tools
            .iter()
            .map(|t| {
                serde_json::json!({
                    "type": "function",
                    "name": t.name,
                    "description": t.description,
                    "parameters": t.parameters,
                })
            })
            .collect();
        obj.insert("tools".into(), Value::Array(tools_val));
    }
    if let Some(ref tc) = req.tool_choice {
        obj.insert("tool_choice".into(), tc.clone());
    }
    let passthrough = req
        .extra
        .iter()
        .filter(|(k, _)| {
            !matches!(
                k.as_str(),
                "messages" | "input" | "instructions" | "stream" | "store" | "model"
            )
        })
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect::<HashMap<_, _>>();
    for (k, v) in passthrough {
        obj.entry(k).or_insert(v);
    }

    Ok((body, reqwest::header::HeaderMap::new()))
}

struct AuthenticatedKey {
    id: Option<String>,
}

#[derive(Debug, Clone)]
struct ResolvedProviderRuntime {
    access_token: String,
    binding: RuntimeBinding,
}

#[async_trait]
trait ProxyAccessStore {
    async fn get_active_provider(&self, id: &str) -> anyhow::Result<Option<Provider>>;
    async fn find_api_key(&self, raw_key: &str) -> anyhow::Result<Option<ApiKeyAccessRecord>>;
    async fn route_binding_exists(&self, api_key_id: &str, route_id: &str) -> anyhow::Result<bool>;
    async fn request_count_since(
        &self,
        api_key_id: &str,
        window: UsageWindow,
    ) -> anyhow::Result<i64>;
    async fn token_count_since(&self, api_key_id: &str, window: UsageWindow)
    -> anyhow::Result<i64>;
}

struct GatewayProxyAccessStore<'a> {
    gw: &'a Gateway,
}

impl<'a> GatewayProxyAccessStore<'a> {
    fn new(gw: &'a Gateway) -> Self {
        Self { gw }
    }
}

#[async_trait]
impl ProxyAccessStore for GatewayProxyAccessStore<'_> {
    async fn get_active_provider(&self, id: &str) -> anyhow::Result<Option<Provider>> {
        let provider = self.gw.storage.providers().get(id).await?;
        Ok(provider.filter(|p| p.is_active))
    }

    async fn find_api_key(&self, raw_key: &str) -> anyhow::Result<Option<ApiKeyAccessRecord>> {
        match self.gw.storage.auth() {
            Some(store) => store.find_api_key(raw_key).await,
            None => Ok(None),
        }
    }

    async fn route_binding_exists(&self, api_key_id: &str, route_id: &str) -> anyhow::Result<bool> {
        match self.gw.storage.auth() {
            Some(store) => store.route_binding_exists(api_key_id, route_id).await,
            None => Ok(false),
        }
    }

    async fn request_count_since(
        &self,
        api_key_id: &str,
        window: UsageWindow,
    ) -> anyhow::Result<i64> {
        match self.gw.storage.auth() {
            Some(store) => store.request_count_since(api_key_id, window).await,
            None => Ok(0),
        }
    }

    async fn token_count_since(
        &self,
        api_key_id: &str,
        window: UsageWindow,
    ) -> anyhow::Result<i64> {
        match self.gw.storage.auth() {
            Some(store) => store.token_count_since(api_key_id, window).await,
            None => Ok(0),
        }
    }
}

async fn authorize_route_access<S: ProxyAccessStore + ?Sized>(
    access_store: &S,
    route: &Route,
    headers: &HeaderMap,
) -> Result<AuthenticatedKey, Response> {
    if !route.access_control {
        return Ok(AuthenticatedKey { id: None });
    }

    let Some(raw_key) = extract_api_key(headers) else {
        return Err(error_response(401, "missing api key"));
    };

    let key_row = access_store
        .find_api_key(&raw_key)
        .await
        .map_err(|e| error_response(500, &format!("auth db error: {e}")))?;

    let Some(key_row) = key_row else {
        return Err(error_response(401, "invalid api key"));
    };

    if key_row.status != "active" {
        return Err(error_response(403, "api key revoked"));
    }

    if let Some(expires) = key_row.expires_at.as_ref() {
        if is_key_expired(expires) {
            return Err(error_response(403, "api key expired"));
        }
    }

    let allowed = access_store
        .route_binding_exists(&key_row.id, &route.id)
        .await
        .map_err(|e| error_response(500, &format!("auth db error: {e}")))?;
    if !allowed {
        return Err(error_response(403, "api key not allowed for this route"));
    }

    if let Some(limit) = key_row.rpm.filter(|v| *v > 0) {
        let req_count = access_store
            .request_count_since(&key_row.id, UsageWindow::Minute)
            .await
            .map_err(|e| error_response(500, &format!("quota db error: {e}")))?;
        if req_count >= i64::from(limit) {
            return Err(error_response(429, "api key rpm quota exceeded"));
        }
    }

    if let Some(limit) = key_row.rpd.filter(|v| *v > 0) {
        let req_count = access_store
            .request_count_since(&key_row.id, UsageWindow::Day)
            .await
            .map_err(|e| error_response(500, &format!("quota db error: {e}")))?;
        if req_count >= i64::from(limit) {
            return Err(error_response(429, "api key rpd quota exceeded"));
        }
    }

    if let Some(limit) = key_row.tpm.filter(|v| *v > 0) {
        let token_count = access_store
            .token_count_since(&key_row.id, UsageWindow::Minute)
            .await
            .map_err(|e| error_response(500, &format!("quota db error: {e}")))?;
        if token_count >= i64::from(limit) {
            return Err(error_response(429, "api key tpm quota exceeded"));
        }
    }

    if let Some(limit) = key_row.tpd.filter(|v| *v > 0) {
        let token_count = access_store
            .token_count_since(&key_row.id, UsageWindow::Day)
            .await
            .map_err(|e| error_response(500, &format!("quota db error: {e}")))?;
        if token_count >= i64::from(limit) {
            return Err(error_response(429, "api key tpd quota exceeded"));
        }
    }

    Ok(AuthenticatedKey {
        id: Some(key_row.id),
    })
}

fn is_key_expired(expires_at: &str) -> bool {
    if let Ok(parsed) = chrono::DateTime::parse_from_rfc3339(expires_at) {
        return parsed.with_timezone(&Utc) <= Utc::now();
    }

    NaiveDateTime::parse_from_str(expires_at, "%Y-%m-%d %H:%M:%S")
        .map(|parsed| parsed.and_utc() <= Utc::now())
        .unwrap_or(false)
}

fn extract_api_key(headers: &HeaderMap) -> Option<String> {
    if let Some(value) = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
    {
        if let Some(token) = value.strip_prefix("Bearer ") {
            let token = token.trim();
            if !token.is_empty() {
                return Some(token.to_string());
            }
        }
    }

    headers
        .get("x-api-key")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(ToString::to_string)
}

async fn get_provider<S: ProxyAccessStore + ?Sized>(
    access_store: &S,
    id: &str,
) -> anyhow::Result<Provider> {
    access_store
        .get_active_provider(id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("provider not found or inactive: {id}"))
}

fn override_model(mut body: Value, model: &str, protocol: Protocol) -> Value {
    match protocol {
        Protocol::Gemini => body,
        _ => {
            if let Some(obj) = body.as_object_mut() {
                obj.insert("model".into(), Value::String(model.to_string()));
            }
            body
        }
    }
}

fn error_type_for_status(status: u16) -> &'static str {
    match status {
        400 => "NYRO_BAD_REQUEST",
        401 => "NYRO_AUTH_ERROR",
        403 => "NYRO_FORBIDDEN",
        404 => "NYRO_NOT_FOUND",
        429 => "NYRO_RATE_LIMIT",
        500 => "NYRO_INTERNAL_ERROR",
        502 => "NYRO_UPSTREAM_ERROR",
        503 => "NYRO_SERVICE_UNAVAILABLE",
        _ => "NYRO_GATEWAY_ERROR",
    }
}

fn error_response(status: u16, message: &str) -> Response {
    let code = StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    (
        code,
        Json(serde_json::json!({
            "error": {
                "message": message,
                "type": error_type_for_status(status),
                "code": status
            }
        })),
    )
        .into_response()
}

async fn load_route_targets(gw: &Gateway, route: &Route) -> Vec<RouteTarget> {
    if let Some(store) = gw.storage.route_targets() {
        if let Ok(targets) = store.list_targets_by_route(&route.id).await {
            if !targets.is_empty() {
                return targets;
            }
        }
    }
    if route.target_provider.trim().is_empty() {
        return vec![];
    }
    vec![RouteTarget {
        id: String::new(),
        route_id: route.id.clone(),
        provider_id: route.target_provider.clone(),
        model: route.target_model.clone(),
        weight: 100,
        priority: 1,
        created_at: String::new(),
    }]
}

fn is_retryable(status: u16) -> bool {
    matches!(status, 408 | 429 | 500 | 502 | 503 | 529)
}

async fn resolve_provider_runtime(
    gw: &Gateway,
    provider: &Provider,
) -> anyhow::Result<ResolvedProviderRuntime> {
    let fallback = provider.api_key.trim().to_string();
    let driver_key = provider
        .vendor
        .as_deref()
        .map(auth::normalize_driver_key)
        .unwrap_or_default();

    if driver_key.is_empty() {
        return Ok(ResolvedProviderRuntime {
            access_token: provider.api_key.clone(),
            binding: RuntimeBinding::default(),
        });
    }

    let Some(driver) = auth::build_driver(&driver_key) else {
        return Ok(ResolvedProviderRuntime {
            access_token: provider.api_key.clone(),
            binding: RuntimeBinding::default(),
        });
    };

    let Some(store) = gw.storage.provider_auth_bindings() else {
        return Ok(ResolvedProviderRuntime {
            access_token: provider.api_key.clone(),
            binding: RuntimeBinding::default(),
        });
    };

    let Some(binding) = store
        .get_by_provider_and_driver(&provider.id, &driver_key)
        .await?
    else {
        return Ok(ResolvedProviderRuntime {
            access_token: provider.api_key.clone(),
            binding: RuntimeBinding::default(),
        });
    };

    let mut credential = binding.stored_credential();
    let access_token = credential
        .access_token
        .clone()
        .unwrap_or_default()
        .trim()
        .to_string();

    if access_token.is_empty() || is_token_expired(credential.expires_at.as_deref()) {
        let refresh_token = credential
            .refresh_token
            .clone()
            .unwrap_or_default()
            .trim()
            .to_string();
        if refresh_token.is_empty() {
            if access_token.is_empty() && fallback.is_empty() {
                anyhow::bail!("provider credential is empty");
            }
            let fallback_token = if access_token.is_empty() {
                provider.api_key.clone()
            } else {
                credential.access_token.clone().unwrap_or_default()
            };
            return Ok(ResolvedProviderRuntime {
                access_token: fallback_token,
                binding: driver.bind_runtime(provider, &credential)?,
            });
        }

        let client = gw.http_client_for_provider(provider.use_proxy).await?;
        let refreshed = driver
            .refresh(
                &credential,
                auth::RefreshAuthContext {
                    use_proxy: provider.use_proxy,
                    http_client: Some(client),
                    ..Default::default()
                },
            )
            .await?;

        let refreshed_binding = store
            .upsert(auth::UpsertProviderAuthBinding {
                provider_id: provider.id.clone(),
                driver_key: binding.driver_key.clone(),
                scheme: binding.scheme.clone(),
                status: "connected".to_string(),
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
        credential = refreshed_binding.stored_credential();
    }

    let access_token = credential
        .access_token
        .clone()
        .filter(|value| !value.trim().is_empty())
        .or_else(|| (!fallback.is_empty()).then_some(provider.api_key.clone()))
        .ok_or_else(|| anyhow::anyhow!("provider credential is empty"))?;

    Ok(ResolvedProviderRuntime {
        access_token,
        binding: driver.bind_runtime(provider, &credential)?,
    })
}

fn resolve_runtime_model_alias(
    model: &str,
    binding: &RuntimeBinding,
    allow_wildcard: bool,
) -> String {
    if let Some(mapped) = binding
        .model_aliases
        .get(model)
        .filter(|value| !value.trim().is_empty())
    {
        return mapped.clone();
    }

    if allow_wildcard {
        if let Some(mapped) = binding
            .model_aliases
            .get("*")
            .filter(|value| !value.trim().is_empty())
        {
            return mapped.clone();
        }
    }

    model.to_string()
}

fn append_runtime_headers(
    headers: &mut reqwest::header::HeaderMap,
    binding: &RuntimeBinding,
) -> anyhow::Result<()> {
    for (key, value) in &binding.extra_headers {
        headers.insert(
            reqwest::header::HeaderName::from_bytes(key.as_bytes())?,
            reqwest::header::HeaderValue::from_str(value)?,
        );
    }
    Ok(())
}

fn is_token_expired(expires_at: Option<&str>) -> bool {
    let Some(raw) = expires_at.map(str::trim).filter(|value| !value.is_empty()) else {
        return false;
    };

    if let Ok(parsed) = chrono::DateTime::parse_from_rfc3339(raw) {
        return parsed.with_timezone(&Utc) <= Utc::now();
    }

    NaiveDateTime::parse_from_str(raw, "%Y-%m-%d %H:%M:%S")
        .map(|parsed| parsed.and_utc() <= Utc::now())
        .unwrap_or(false)
}

fn emit_log(
    gw: &Gateway,
    ingress: &str,
    egress: &str,
    request_model: &str,
    actual_model: &str,
    api_key_id: Option<&str>,
    provider_name: &str,
    status_code: i32,
    duration_ms: f64,
    usage: TokenUsage,
    is_stream: bool,
    is_tool_call: bool,
    error_message: Option<String>,
    response_preview: Option<String>,
) {
    let _ = gw.log_tx.try_send(LogEntry {
        api_key_id: api_key_id.map(ToString::to_string),
        ingress_protocol: ingress.to_string(),
        egress_protocol: egress.to_string(),
        request_model: request_model.to_string(),
        actual_model: actual_model.to_string(),
        provider_name: provider_name.to_string(),
        status_code,
        duration_ms,
        usage,
        is_stream,
        is_tool_call,
        error_message,
        response_preview,
    });
}
