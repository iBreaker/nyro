--
-- NYRO Local-Metrics API
--
-- GET /nyro/local/metrics
-- 从 plugin_local_metrics shared_dict 读取聚合指标，返回 JSON。
--

local ngx      = ngx
local ngx_now  = ngx.now
local pairs    = pairs
local tonumber = tonumber
local json     = require("cjson.safe")

local DICT_NAME = "plugin_local_metrics"

local _M = {}

-- ── 辅助：从 shared_dict 扫描指定前缀的 key 集合 ──

local function collect_dimension_names(dict, prefix, suffix)
    -- 遍历 dict 所有 key，收集匹配 prefix{name}suffix 的 name 集合
    -- shared_dict:get_keys(max) 返回最多 max 个 key
    local keys = dict:get_keys(0) -- 0 = 不限制
    local names = {}
    local seen  = {}

    local prefix_len = #prefix
    local suffix_len = #suffix

    for _, key in pairs(keys) do
        if key:sub(1, prefix_len) == prefix then
            local rest = key:sub(prefix_len + 1)
            -- 从 rest 中找到 suffix 之前的 name
            local name_end = rest:find(suffix, 1, true)
            if name_end then
                local name = rest:sub(1, name_end - 1)
                if not seen[name] then
                    seen[name] = true
                    names[#names + 1] = name
                end
            end
        end
    end

    return names
end

-- ── 构建 route 维度 ──

local function build_routes(dict)
    local names = collect_dimension_names(dict, "m:rt:", ":requests")
    local items = {}

    for _, name in pairs(names) do
        local rp = "m:rt:" .. name
        local requests      = dict:get(rp .. ":requests") or 0
        local latency_sum   = dict:get(rp .. ":latency_sum") or 0
        local latency_count = dict:get(rp .. ":latency_count") or 0
        local latency_avg   = latency_count > 0 and (latency_sum / latency_count) or 0

        items[#items + 1] = {
            name              = name,
            requests          = requests,
            latency_avg_ms    = tonumber(string.format("%.2f", latency_avg)),
            input_tokens  = dict:get(rp .. ":input_tokens") or 0,
            output_tokens = dict:get(rp .. ":output_tokens") or 0,
            status            = {
                ["2xx"] = dict:get(rp .. ":status:2xx") or 0,
                ["4xx"] = dict:get(rp .. ":status:4xx") or 0,
                ["5xx"] = dict:get(rp .. ":status:5xx") or 0,
            },
        }
    end

    return items
end

-- ── 构建 service 维度 ──

local function build_services(dict)
    local names = collect_dimension_names(dict, "m:svc:", ":requests")
    local items = {}

    for _, name in pairs(names) do
        local sp = "m:svc:" .. name
        local requests      = dict:get(sp .. ":requests") or 0
        local latency_sum   = dict:get(sp .. ":latency_sum") or 0
        local latency_count = dict:get(sp .. ":latency_count") or 0
        local latency_avg   = latency_count > 0 and (latency_sum / latency_count) or 0

        items[#items + 1] = {
            name              = name,
            requests          = requests,
            latency_avg_ms    = tonumber(string.format("%.2f", latency_avg)),
            input_tokens  = dict:get(sp .. ":input_tokens") or 0,
            output_tokens = dict:get(sp .. ":output_tokens") or 0,
            status            = {
                ["2xx"] = dict:get(sp .. ":status:2xx") or 0,
                ["4xx"] = dict:get(sp .. ":status:4xx") or 0,
                ["5xx"] = dict:get(sp .. ":status:5xx") or 0,
            },
        }
    end

    return items
end

-- ── 构建 consumer 维度 ──

local function build_consumers(dict)
    local names = collect_dimension_names(dict, "m:cs:", ":requests")
    local items = {}

    for _, name in pairs(names) do
        local cp = "m:cs:" .. name
        local requests = dict:get(cp .. ":requests") or 0

        items[#items + 1] = {
            name              = name,
            requests          = requests,
            input_tokens  = dict:get(cp .. ":input_tokens") or 0,
            output_tokens = dict:get(cp .. ":output_tokens") or 0,
            status            = {
                ["2xx"] = dict:get(cp .. ":status:2xx") or 0,
                ["4xx"] = dict:get(cp .. ":status:4xx") or 0,
                ["5xx"] = dict:get(cp .. ":status:5xx") or 0,
            },
        }
    end

    return items
end

-- ── 构建 model 维度 ──

local function build_models(dict)
    local names = collect_dimension_names(dict, "m:mdl:", ":requests")
    local items = {}

    for _, name in pairs(names) do
        local mp = "m:mdl:" .. name
        local requests      = dict:get(mp .. ":requests") or 0
        local latency_sum   = dict:get(mp .. ":latency_sum") or 0
        local latency_count = dict:get(mp .. ":latency_count") or 0
        local latency_avg   = latency_count > 0 and (latency_sum / latency_count) or 0

        items[#items + 1] = {
            name           = name,
            requests       = requests,
            latency_avg_ms = tonumber(string.format("%.2f", latency_avg)),
            input_tokens   = dict:get(mp .. ":input_tokens") or 0,
            output_tokens  = dict:get(mp .. ":output_tokens") or 0,
            status         = {
                ["2xx"] = dict:get(mp .. ":status:2xx") or 0,
                ["4xx"] = dict:get(mp .. ":status:4xx") or 0,
                ["5xx"] = dict:get(mp .. ":status:5xx") or 0,
            },
        }
    end

    return items
end

-- ── API 入口 ──

function _M.serve()
    local dict = ngx.shared[DICT_NAME]
    if not dict then
        ngx.status = 500
        ngx.header["Content-Type"] = "application/json"
        ngx.say(json.encode({
            code    = 500,
            message = "shared dict '" .. DICT_NAME .. "' not found",
        }))
        return
    end

    local uptime_start    = dict:get("m:uptime_start") or ngx_now()
    local uptime_seconds  = ngx_now() - uptime_start
    local total_requests  = dict:get("m:total_requests") or 0
    local active_conns    = tonumber(ngx.var.connections_active) or 0

    local body = {
        uptime_seconds        = tonumber(string.format("%.0f", uptime_seconds)),
        total_requests        = total_requests,
        total_input_tokens    = dict:get("m:total_input_tokens") or 0,
        total_output_tokens   = dict:get("m:total_output_tokens") or 0,
        active_connections    = active_conns,
        routes                = build_routes(dict),
        services              = build_services(dict),
        consumers             = build_consumers(dict),
        models                = build_models(dict),
    }

    ngx.status = 200
    ngx.header["Content-Type"] = "application/json"
    ngx.say(json.encode(body))
end

return _M
