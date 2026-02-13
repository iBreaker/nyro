--
-- NYRO Local-Logs Plugin
--
-- 全局插件：在 http_log 阶段将 Lua 层面的上下文信息
-- (route / service / consumer) 写入 ngx.var 自定义变量，
-- 供 nginx log_format nyro_json 引用输出到 logs/access.json。
--

local ngx = ngx

local _M = {}

-- nyro.yaml 中加载即自动作为全局插件执行，无需在 config.yaml 中配置
_M.auto_global = true

function _M.http_log(oak_ctx, _plugin_config)
    -- 将 Lua 上下文信息写入 ngx.var，供 log_format nyro_json 引用
    local route_name = oak_ctx and oak_ctx.config
        and oak_ctx.config.route and oak_ctx.config.route.name
    local service_name = oak_ctx and oak_ctx.config
        and oak_ctx.config.service and oak_ctx.config.service.name
    local consumer_name = oak_ctx and oak_ctx._consumer
        and oak_ctx._consumer.name

    ngx.var.nyro_route    = route_name or ""
    ngx.var.nyro_service  = service_name or ""
    ngx.var.nyro_consumer = consumer_name or ""

    -- AI 上下文 (由 ai-proxy 写入 oak_ctx._ai_proxy)
    local ai_ctx = oak_ctx and oak_ctx._ai_proxy
    ngx.var.nyro_model         = ai_ctx and ai_ctx.model or ""
    ngx.var.nyro_input_tokens  = ai_ctx and ai_ctx.input_tokens or 0
    ngx.var.nyro_output_tokens = ai_ctx and ai_ctx.output_tokens or 0
end

return _M
