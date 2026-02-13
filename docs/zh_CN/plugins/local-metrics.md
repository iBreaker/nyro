# local-metrics 插件

本地指标聚合插件，在 `http_log` 阶段将请求指标写入 `lua_shared_dict`，
通过 JSON API 暴露给 Console 或外部系统。面向个人用户 / 单节点本地观测。

---

## 启用

在 `nyro.yaml` 的插件列表中添加：

```yaml
plugins:
  - local-metrics
```

同时确保 `shared_dict` 中包含：

```yaml
nginx:
  shared_dict:
    plugin_local_metrics: 10m
```

---

## 运行机制

- **自动全局插件（`auto_global`）**：只要在 `nyro.yaml` 中加载，即自动对所有请求生效，无需在 `config.yaml` 中配置。
- **不可在资源级配置**：routes、services、consumers 中配置此插件会被忽略，始终仅以全局模式运行。
- **条件化 nginx 生成**：仅当 `nyro.yaml` 插件列表包含 `local-metrics` 时，nginx.conf 中才会生成 `/nyro/local/metrics` location 块。
- **无配置参数**：开箱即用，不接受自定义参数。

---

## 指标维度

按四个维度聚合：

| 维度 | shared_dict Key 前缀 | 说明 |
|------|----------------------|------|
| route | `m:rt:{name}:` | 按路由名称聚合 |
| service | `m:svc:{name}:` | 按服务名称聚合 |
| consumer | `m:cs:{name}:` | 按消费者名称聚合（未认证为 `anonymous`）|
| model | `m:mdl:{name}:` | 按 AI 模型名称聚合（仅 AI 请求）|

每个维度收集以下指标：

| 指标 | 类型 | 说明 |
|------|------|------|
| `requests` | counter | 请求总数 |
| `latency_sum` | counter | 累计延迟 (ms)，route/service 维度 |
| `latency_count` | counter | 延迟计数，用于计算平均值 |
| `status:2xx` | counter | 2xx 状态码请求数 |
| `status:4xx` | counter | 4xx 状态码请求数 |
| `status:5xx` | counter | 5xx 状态码请求数 |
| `input_tokens` | counter | 累计输入 Token 数（AI 请求） |
| `output_tokens` | counter | 累计输出 Token 数（AI 请求） |

全局指标：

| Key | 类型 | 说明 |
|-----|------|------|
| `m:total_requests` | counter | 所有请求总数 |
| `m:total_input_tokens` | counter | 所有 AI 请求的输入 Token 总数 |
| `m:total_output_tokens` | counter | 所有 AI 请求的输出 Token 总数 |
| `m:uptime_start` | timestamp | 进程启动时间戳 |

`active_connections` 从 nginx 内置变量 `connections_active` 实时读取。

> Token 数据来源于 ai-proxy 插件从上游响应中提取的 `usage` 字段（厂商权威值）。
> 非 AI 请求不产生 token 计数。

---

## API 端点

### GET /nyro/local/metrics

返回所有聚合指标的 JSON 快照。

**响应示例：**

```json
{
  "uptime_seconds": 86400,
  "total_requests": 125000,
  "total_input_tokens": 5200000,
  "total_output_tokens": 2800000,
  "active_connections": 15,
  "routes": [
    {
      "name": "chat-openai",
      "requests": 50000,
      "latency_avg_ms": 85.32,
      "input_tokens": 2100000,
      "output_tokens": 1200000,
      "status": {
        "2xx": 49500,
        "4xx": 400,
        "5xx": 100
      }
    }
  ],
  "services": [
    {
      "name": "openai",
      "requests": 80000,
      "latency_avg_ms": 90.15,
      "input_tokens": 3500000,
      "output_tokens": 1900000,
      "status": {
        "2xx": 79000,
        "4xx": 700,
        "5xx": 300
      }
    }
  ],
  "consumers": [
    {
      "name": "ai-app",
      "requests": 60000,
      "input_tokens": 2600000,
      "output_tokens": 1400000,
      "status": {
        "2xx": 59500,
        "4xx": 300,
        "5xx": 200
      }
    },
    {
      "name": "anonymous",
      "requests": 65000,
      "input_tokens": 2600000,
      "output_tokens": 1400000,
      "status": {
        "2xx": 64000,
        "4xx": 800,
        "5xx": 200
      }
    }
  ],
  "models": [
    {
      "name": "deepseek-chat",
      "requests": 30000,
      "latency_avg_ms": 120.50,
      "input_tokens": 1800000,
      "output_tokens": 950000,
      "status": {
        "2xx": 29800,
        "4xx": 150,
        "5xx": 50
      }
    },
    {
      "name": "gpt-4o",
      "requests": 20000,
      "latency_avg_ms": 95.30,
      "input_tokens": 1400000,
      "output_tokens": 850000,
      "status": {
        "2xx": 19700,
        "4xx": 250,
        "5xx": 50
      }
    }
  ]
}
```

**端点位置：** 主 server block（代理端口），始终可用，不依赖 Admin API。

---

## QPS 计算

本插件不计算 QPS。Console 前端可通过轮询间隔对 `total_requests` 或各维度 `requests` 做差值计算：

```
QPS = (requests_t2 - requests_t1) / (t2 - t1)
```

---

## 共享内存

使用 `plugin_local_metrics` shared_dict，在 `nyro.yaml` 中配置大小：

```yaml
nginx:
  shared_dict:
    plugin_local_metrics: 10m
```

---

## 实现文件

```
nyro/plugin/local-metrics/
├── handler.lua   -- http_log 阶段写入 shared_dict
├── schema.lua    -- 配置 schema
└── api.lua       -- /nyro/local/metrics API handler
```
