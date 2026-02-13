local ngx    = ngx
local ipairs = ipairs
local pairs  = pairs
local pcall  = pcall
local core   = require("nyro.core")

-- 加载资源模块
local store       = require("nyro.store")
local route       = require("nyro.route")
local backend     = require("nyro.backend")
local certificate = require("nyro.certificate")
local consumer    = require("nyro.consumer")
local plugin      = require("nyro.plugin")

-- ============================================================
-- 插件执行: route 级 → service 级 → 全局级
-- ============================================================

local function run_plugin(phase, oak_ctx)
    local plugin_objects = plugin.plugin_subjects()
    if not plugin_objects then
        return
    end

    local router_plugin_keys_map = {}

    -- 1. route 级 + service 级插件 (需要 oak_ctx.config)
    if oak_ctx and oak_ctx.config then
        local config = oak_ctx.config
        local service_router  = config.service_router
        local service_plugins = service_router.plugins
        local router_plugins  = service_router.router.plugins

        if #router_plugins > 0 then
            for i = 1, #router_plugins do
                repeat
                    if not plugin_objects[router_plugins[i].id] then
                        break
                    end

                    local router_plugin_object = plugin_objects[router_plugins[i].id]

                    -- auto_global 插件禁止在 route/service/consumer 级执行
                    if router_plugin_object.handler.auto_global then
                        break
                    end

                    router_plugin_keys_map[router_plugin_object.key] = true

                    if not router_plugin_object.handler[phase] then
                        break
                    end

                    router_plugin_object.handler[phase](oak_ctx, router_plugins[i].config or {})
                until true
            end
        end

        if #service_plugins > 0 then
            for j = 1, #service_plugins do
                repeat
                    if not plugin_objects[service_plugins[j].id] then
                        break
                    end

                    local service_plugin_object = plugin_objects[service_plugins[j].id]

                    -- auto_global 插件禁止在 route/service/consumer 级执行
                    if service_plugin_object.handler.auto_global then
                        break
                    end

                    if router_plugin_keys_map[service_plugin_object.key] then
                        break
                    end

                    if not service_plugin_object.handler[phase] then
                        break
                    end

                    service_plugin_object.handler[phase](oak_ctx, service_plugins[j].config or {})
                until true
            end
        end
    end

    -- 2. 全局插件 (config.yaml 顶层 plugins)
    local global_executed = {}

    if store.is_initialized() then
        local global_plugins, _ = store.get_plugins()
        if global_plugins and #global_plugins > 0 then
            for _, gp in ipairs(global_plugins) do
                repeat
                    local gp_id = gp.id or gp.name
                    if not gp_id then
                        break
                    end

                    -- 跳过已在 route/service 级执行过的插件
                    if router_plugin_keys_map[gp_id] then
                        break
                    end

                    local gp_object = plugin_objects[gp_id]
                    if not gp_object then
                        break
                    end

                    -- auto_global 插件由第 3 阶段统一处理，此处跳过
                    if gp_object.handler.auto_global then
                        break
                    end

                    if not gp_object.handler[phase] then
                        break
                    end

                    local ok, err = pcall(gp_object.handler[phase], oak_ctx, gp.config or {})
                    if not ok then
                        ngx.log(ngx.ERR, "[plugin] global plugin '", gp_id, "' error in ", phase, ": ", err)
                    end
                    global_executed[gp_id] = true
                until true
            end
        end
    end

    -- 3. 自动全局插件: nyro.yaml 中加载且标记 auto_global 的插件，
    --    即使 config.yaml 未配置也自动执行 (跳过已执行的)
    for key, obj in pairs(plugin_objects) do
        repeat
            if not obj.handler.auto_global then
                break
            end

            -- 跳过已在 route/service 或全局阶段执行过的
            if router_plugin_keys_map[key] or global_executed[key] then
                break
            end

            if not obj.handler[phase] then
                break
            end

            local ok, err = pcall(obj.handler[phase], oak_ctx, {})
            if not ok then
                ngx.log(ngx.ERR, "[plugin] auto-global plugin '", key, "' error in ", phase, ": ", err)
            end
        until true
    end
end

local function options_request_handle()
    if core.request.get_method() == "OPTIONS" then
        core.response.exit(200, {
            err_message = "Welcome to NYRO"
        })
    end
end

local function enable_cors_handle()
    core.response.set_header("Access-Control-Allow-Origin", "*")
    core.response.set_header("Access-Control-Allow-Credentials", "true")
    core.response.set_header("Access-Control-Expose-Headers", "*")
    core.response.set_header("Access-Control-Max-Age", "3600")
end

local NYRO = {}

function NYRO.init()
    require("resty.core")
    if require("ffi").os == "Linux" then
        require("ngx.re").opt("jit_stack_size", 200 * 1024)
    end

    require("jit.opt").start("minstitch=2", "maxtrace=4000",
            "maxrecord=8000", "sizemcode=64",
            "maxmcode=4000", "maxirconst=1000")

    local process = require("ngx.process")
    local ok, err = process.enable_privileged_agent()
    if not ok then
        core.log.error("failed to enable privileged process, error: ", err)
    end
end

function NYRO.init_worker()
    core.config.init_worker()
    core.cache.init_worker()
    
    -- 初始化 Store
    local store_config = core.config.query("store") or {}
    local store_mode = store_config.mode or "standalone"
    local ok, err = store.init({
        mode = store_mode,
        standalone = store_config.standalone or { config_file = "conf/config.yaml" }
    })
    if not ok then
        ngx.log(ngx.ERR, "[nyro] failed to init store: ", err or "unknown error")
    else
        ngx.log(ngx.INFO, "[nyro] store initialized, mode: ", store_mode)
    end
    
    certificate.init_worker()
    backend.init_worker()
    plugin.init_worker()
    route.init_worker()
    consumer.init_worker()

    -- 初始化已加载插件的 init_worker (如 local-metrics 记录 uptime)
    local plugin_subjects = plugin.plugin_subjects()
    if plugin_subjects then
        for _, obj in pairs(plugin_subjects) do
            if obj.handler and obj.handler.init_worker then
                obj.handler.init_worker()
            end
        end
    end
end

function NYRO.ssl_certificate()
    local ngx_ssl = require("ngx.ssl")
    local server_name = ngx_ssl.server_name()

    local oak_ctx = {
        matched = {
            host = server_name
        }
    }
    certificate.ssl_match(oak_ctx)
end

function NYRO.http_access()

    options_request_handle()

    local ngx_ctx = ngx.ctx
    local oak_ctx = ngx_ctx.oak_ctx
    if not oak_ctx then
        oak_ctx = core.pool.fetch("oak_ctx", 0, 64)
        ngx_ctx.oak_ctx = oak_ctx
    end

    route.parameter(oak_ctx)

    local match_succeed = route.router_match(oak_ctx)

    if not match_succeed then
        core.response.exit(404, { err_message = "\"URI\" Undefined" })
    end

    -- 在 access 阶段完成: 节点选择 + DNS 解析 + endpoint.headers 注入
    backend.prepare_upstream(oak_ctx)

    local matched  = oak_ctx.matched

    local upstream_uri = matched.uri

    for path_key, path_val in pairs(matched.path) do
        upstream_uri = core.string.replace(upstream_uri, "{" .. path_key .. "}", path_val)
    end

    for header_key, header_val in pairs(matched.header) do
        core.request.add_header(header_key, header_val)
    end

    local query_args = {}

    for query_key, query_val in pairs(matched.query) do
        if query_val == true then
            query_val = ""
        end
        core.table.insert(query_args, query_key .. "=" .. query_val)
    end

    if #query_args > 0 then
        upstream_uri = upstream_uri .. "?" .. core.table.concat(query_args, "&")
    end

    core.request.set_method(matched.method)

    ngx.var.upstream_uri = upstream_uri

    -- 设置上游 scheme / host (从 prepare_upstream 预计算结果中获取)
    local up = oak_ctx._upstream
    if up then
        ngx.var.upstream_scheme = up.scheme or "http"
        ngx.var.upstream_host = up.host or matched.host
    else
        ngx.var.upstream_host = matched.host
    end

    run_plugin("http_access", oak_ctx)
end

function NYRO.http_balancer()
    local oak_ctx = ngx.ctx.oak_ctx
    backend.gogogo(oak_ctx)
end

function NYRO.http_header_filter()
    local oak_ctx = ngx.ctx.oak_ctx
    run_plugin("http_header_filter", oak_ctx)
end

function NYRO.http_body_filter()
    local oak_ctx = ngx.ctx.oak_ctx
    run_plugin("http_body_filter", oak_ctx)
end

function NYRO.http_log()
    local oak_ctx = ngx.ctx.oak_ctx
    run_plugin("http_log", oak_ctx)
    if oak_ctx then
        core.pool.release("oak_ctx", oak_ctx)
    end
end

function NYRO.http_admin()
    options_request_handle()
    enable_cors_handle()

    local admin = require("nyro.admin")
    admin.dispatch()
end

function NYRO.http_local_metrics()
    enable_cors_handle()

    local api = require("nyro.plugin.local-metrics.api")
    api.serve()
end

function NYRO.http_local_logs()
    enable_cors_handle()

    local api = require("nyro.plugin.local-logs.api")
    api.serve()
end

return NYRO
