--
-- NYRO Local-Metrics Plugin
--
-- 全局插件：在 http_log 阶段将请求指标写入 lua_shared_dict，
-- 按 route / service / consumer 三个维度聚合。
-- 配合 api.lua 通过 /nyro/local/metrics 暴露 JSON 数据给 Console。
--

local ngx         = ngx
local ngx_now     = ngx.now
local ngx_var     = ngx.var
local tonumber    = tonumber

local DICT_NAME = "plugin_local_metrics"

local _M = {}

-- nyro.yaml 中加载即自动作为全局插件执行，无需在 config.yaml 中配置
_M.auto_global = true

-- init_worker: 记录启动时间戳
function _M.init_worker()
    local dict = ngx.shared[DICT_NAME]
    if not dict then
        return
    end

    -- 仅首次写入 (add 不会覆盖已有值)
    dict:add("m:uptime_start", ngx_now())
end

-- http_log: 聚合请求指标
function _M.http_log(oak_ctx, _plugin_config)
    local dict = ngx.shared[DICT_NAME]
    if not dict then
        return
    end

    local status       = ngx.status or 0
    local request_time = tonumber(ngx_var.request_time) or 0
    local latency_ms   = request_time * 1000

    -- 状态码分桶
    local status_bucket
    if status >= 200 and status < 300 then
        status_bucket = "2xx"
    elseif status >= 400 and status < 500 then
        status_bucket = "4xx"
    else
        status_bucket = "5xx"
    end

    -- ── AI 上下文 (由 ai-proxy 写入 oak_ctx._ai_proxy) ──
    local ai_ctx = oak_ctx and oak_ctx._ai_proxy
    local input_tokens  = ai_ctx and ai_ctx.input_tokens or 0
    local output_tokens = ai_ctx and ai_ctx.output_tokens or 0
    local ai_model      = ai_ctx and ai_ctx.model

    -- ── 全局 ──
    dict:incr("m:total_requests", 1, 0)
    if input_tokens > 0 then
        dict:incr("m:total_input_tokens", input_tokens, 0)
    end
    if output_tokens > 0 then
        dict:incr("m:total_output_tokens", output_tokens, 0)
    end

    -- ── route 维度 ──
    local route_name = oak_ctx and oak_ctx.config
        and oak_ctx.config.route and oak_ctx.config.route.name
    if route_name then
        local rp = "m:rt:" .. route_name
        dict:incr(rp .. ":requests", 1, 0)
        dict:incr(rp .. ":latency_sum", latency_ms, 0)
        dict:incr(rp .. ":latency_count", 1, 0)
        dict:incr(rp .. ":status:" .. status_bucket, 1, 0)
        if input_tokens > 0 then
            dict:incr(rp .. ":input_tokens", input_tokens, 0)
        end
        if output_tokens > 0 then
            dict:incr(rp .. ":output_tokens", output_tokens, 0)
        end
    end

    -- ── service 维度 ──
    local service_name = oak_ctx and oak_ctx.config
        and oak_ctx.config.service and oak_ctx.config.service.name
    if service_name then
        local sp = "m:svc:" .. service_name
        dict:incr(sp .. ":requests", 1, 0)
        dict:incr(sp .. ":latency_sum", latency_ms, 0)
        dict:incr(sp .. ":latency_count", 1, 0)
        dict:incr(sp .. ":status:" .. status_bucket, 1, 0)
        if input_tokens > 0 then
            dict:incr(sp .. ":input_tokens", input_tokens, 0)
        end
        if output_tokens > 0 then
            dict:incr(sp .. ":output_tokens", output_tokens, 0)
        end
    end

    -- ── consumer 维度 ──
    local consumer_name = oak_ctx and oak_ctx._consumer
        and oak_ctx._consumer.name or "anonymous"
    local cp = "m:cs:" .. consumer_name
    dict:incr(cp .. ":requests", 1, 0)
    dict:incr(cp .. ":status:" .. status_bucket, 1, 0)
    if input_tokens > 0 then
        dict:incr(cp .. ":input_tokens", input_tokens, 0)
    end
    if output_tokens > 0 then
        dict:incr(cp .. ":output_tokens", output_tokens, 0)
    end

    -- ── model 维度 (仅 AI 请求) ──
    if ai_model then
        local mp = "m:mdl:" .. ai_model
        dict:incr(mp .. ":requests", 1, 0)
        dict:incr(mp .. ":latency_sum", latency_ms, 0)
        dict:incr(mp .. ":latency_count", 1, 0)
        dict:incr(mp .. ":status:" .. status_bucket, 1, 0)
        if input_tokens > 0 then
            dict:incr(mp .. ":input_tokens", input_tokens, 0)
        end
        if output_tokens > 0 then
            dict:incr(mp .. ":output_tokens", output_tokens, 0)
        end
    end
end

return _M
