# local-logs 插件

本地日志查询插件，在 `http_log` 阶段将 Lua 层面的请求上下文（route / service / consumer）
写入 nginx 自定义变量，由 `log_format nyro_json` 输出到独立的 JSON 日志文件 `logs/access.json`。
通过 JSON API 尾读最近 N 条日志，面向个人用户 / 单节点本地观测。

---

## 启用

在 `nyro.yaml` 的插件列表中添加：

```yaml
plugins:
  - local-logs
```

---

## 运行机制

- **自动全局插件（`auto_global`）**：只要在 `nyro.yaml` 中加载，即自动对所有请求注入上下文（route / service / consumer），无需在 `config.yaml` 中配置。
- **不可在资源级配置**：routes、services、consumers 中配置此插件会被忽略，始终仅以全局模式运行。
- **条件化 nginx 生成**：仅当 `nyro.yaml` 插件列表包含 `local-logs` 时，nginx.conf 中才会生成 `log_format nyro_json`、`set $nyro_*` 变量、`access_log logs/access.json` 和 `/nyro/local/logs` location 块。未启用时不会产生额外的日志文件。
- **无配置参数**：开箱即用，不接受自定义参数。

---

## 工作原理

```
请求 → access_by_lua (路由匹配 + 插件执行)
     → ...
     → body_filter_by_lua
     │    └── ai-proxy: 从上游响应提取 usage → oak_ctx._ai_proxy.input_tokens / output_tokens
     → log_by_lua
         ├── local-logs handler: 写入 ngx.var (route/service/consumer/model/input_tokens/output_tokens)
         └── nginx log_format nyro_json: 引用这些变量输出 JSON 日志
              ├── logs/access.log      (原有 text 格式，不变)
              └── logs/access.json     (JSON 格式，local-logs 专用)
```

**原有 `logs/access.log` 不受影响**，JSON 日志写入独立文件。

---

## 日志格式

每行一条 JSON 记录：

```json
{
  "timestamp": "2026-02-12T10:30:00+08:00",
  "client_ip": "127.0.0.1",
  "method": "POST",
  "uri": "/v1/chat/completions",
  "status": 200,
  "latency_ms": 0.085,
  "request_length": 256,
  "response_length": 1024,
  "upstream_addr": "api.deepseek.com:443",
  "upstream_status": "200",
  "request_id": "abc123",
  "route": "chat-openai",
  "service": "openai",
  "consumer": "ai-app",
  "model": "deepseek-chat",
  "input_tokens": 128,
  "output_tokens": 256
}
```

**字段说明：**

| 字段 | 来源 | 说明 |
|------|------|------|
| `timestamp` | `$time_iso8601` | 请求时间 (ISO 8601) |
| `client_ip` | `$remote_addr` | 客户端 IP |
| `method` | `$request_method` | HTTP 方法 |
| `uri` | `$uri` | 请求 URI |
| `status` | `$status` | HTTP 状态码 |
| `latency_ms` | `$request_time` | 请求延迟 (秒，含小数) |
| `request_length` | `$request_length` | 请求体长度 (bytes) |
| `response_length` | `$bytes_sent` | 响应体长度 (bytes) |
| `upstream_addr` | `$upstream_addr` | 上游地址 |
| `upstream_status` | `$upstream_status` | 上游状态码 |
| `request_id` | `$request_id` | 请求唯一 ID |
| `route` | `$nyro_route` | 匹配的路由名称 (Lua 注入) |
| `service` | `$nyro_service` | 关联的服务名称 (Lua 注入) |
| `consumer` | `$nyro_consumer` | 认证的消费者名称 (Lua 注入) |
| `model` | `$nyro_model` | AI 模型名称 (Lua 注入，非 AI 请求为空) |
| `input_tokens` | `$nyro_input_tokens` | 输入 Token 数 (Lua 注入，非 AI 请求为 0) |
| `output_tokens` | `$nyro_output_tokens` | 输出 Token 数 (Lua 注入，非 AI 请求为 0) |

---

## API 端点

### GET /nyro/local/logs?limit=50

尾读日志文件，返回最近 N 条日志。

**参数：**

| 参数 | 类型 | 默认值 | 范围 | 说明 |
|------|------|--------|------|------|
| `limit` | number | 50 | 1 ~ 500 | 返回的日志条数 |

**响应示例：**

```json
{
  "total": 50,
  "items": [
    {
      "timestamp": "2026-02-12T10:29:55+08:00",
      "client_ip": "127.0.0.1",
      "method": "POST",
      "uri": "/v1/chat/completions",
      "status": 200,
      "latency_ms": 0.085,
      "request_length": 256,
      "response_length": 1024,
      "upstream_addr": "api.deepseek.com:443",
      "upstream_status": "200",
      "request_id": "abc123",
      "route": "chat-openai",
      "service": "openai",
      "consumer": "ai-app",
      "model": "deepseek-chat",
      "input_tokens": 128,
      "output_tokens": 256
    }
  ]
}
```

**端点位置：** 主 server block（代理端口），始终可用，不依赖 Admin API。

---

## nginx 模板变更

启用 local-logs 后，nginx 模板中自动包含以下配置：

**http 块 — JSON 日志格式：**

```nginx
log_format nyro_json escape=json '{'
    '"timestamp":"$time_iso8601",'
    '"client_ip":"$remote_addr",'
    ...
    '"route":"$nyro_route",'
    '"service":"$nyro_service",'
    '"consumer":"$nyro_consumer",'
    '"model":"$nyro_model",'
    '"input_tokens":$nyro_input_tokens,'
    '"output_tokens":$nyro_output_tokens'
'}';
```

**location / 块 — 自定义变量 + 双日志：**

```nginx
set $nyro_route              '';
set $nyro_service            '';
set $nyro_consumer           '';
set $nyro_model              '';
set $nyro_input_tokens   '0';
set $nyro_output_tokens  '0';

access_log logs/access.json nyro_json;
```

---

## 日志轮转

`logs/access.json` 与 `logs/access.log` 一样由 nginx 管理。
可通过 `logrotate` 或 `kill -USR1` 信号实现日志轮转。

---

## 实现文件

```
nyro/plugin/local-logs/
├── handler.lua   -- http_log 阶段赋值 ngx.var.nyro_*
├── schema.lua    -- 配置 schema
└── api.lua       -- /nyro/local/logs 尾读 JSON 日志文件
```
