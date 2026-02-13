--
-- NYRO Local-Logs API
--
-- GET /nyro/local/logs?limit=50
-- 尾读 logs/access.json，返回最近 N 条 JSON 日志。
--

local ngx      = ngx
local io_open  = io.open
local tonumber = tonumber
local json     = require("cjson.safe")

local _M = {}

local DEFAULT_LOG_PATH = "logs/access.json"
local DEFAULT_LIMIT    = 50
local MAX_LIMIT        = 500
local READ_CHUNK_SIZE  = 65536  -- 64KB 每次回退读取量

-- ── 从文件末尾反向读取最近 N 行 ──

local function tail_lines(path, limit)
    local file, err = io_open(path, "r")
    if not file then
        return nil, "failed to open log file: " .. tostring(err)
    end

    local file_size = file:seek("end")
    if not file_size or file_size == 0 then
        file:close()
        return {}
    end

    -- 从文件末尾逐块往前读，直到收集足够行数
    local lines = {}
    local remaining = ""
    local pos = file_size

    while pos > 0 and #lines < limit do
        local read_size = READ_CHUNK_SIZE
        if read_size > pos then
            read_size = pos
        end
        pos = pos - read_size

        file:seek("set", pos)
        local chunk = file:read(read_size)
        if not chunk then
            break
        end

        chunk = chunk .. remaining
        remaining = ""

        -- 按换行分割，最前面一段可能是不完整行
        local chunk_lines = {}
        local start_idx = 1
        while true do
            local nl = chunk:find("\n", start_idx, true)
            if not nl then
                -- 剩余部分留给下一轮
                remaining = chunk:sub(start_idx)
                break
            end
            local line = chunk:sub(start_idx, nl - 1)
            if line ~= "" then
                chunk_lines[#chunk_lines + 1] = line
            end
            start_idx = nl + 1
        end

        -- chunk_lines 是正序的，要插入到 lines 前面
        for i = #chunk_lines, 1, -1 do
            if #lines >= limit then
                break
            end
            lines[#lines + 1] = chunk_lines[i]
        end
    end

    -- 处理文件开头的残留行
    if remaining ~= "" and #lines < limit then
        lines[#lines + 1] = remaining
    end

    file:close()

    -- lines 是反序的 (最新在前)，翻转为正序 (最新在后)
    local result = {}
    for i = #lines, 1, -1 do
        result[#result + 1] = lines[i]
    end

    return result
end

-- ── API 入口 ──

function _M.serve()
    local args  = ngx.req.get_uri_args()
    local limit = tonumber(args.limit) or DEFAULT_LIMIT

    if limit < 1 then
        limit = DEFAULT_LIMIT
    elseif limit > MAX_LIMIT then
        limit = MAX_LIMIT
    end

    -- 确定日志文件路径 (相对于 nginx prefix)
    local prefix   = ngx.config.prefix()
    local log_path = prefix .. DEFAULT_LOG_PATH

    local lines, err = tail_lines(log_path, limit)
    if not lines then
        ngx.status = 500
        ngx.header["Content-Type"] = "application/json"
        ngx.say(json.encode({
            code    = 500,
            message = err,
        }))
        return
    end

    -- 每行解析为 JSON 对象
    local items = {}
    for _, line in ipairs(lines) do
        local obj = json.decode(line)
        if obj then
            items[#items + 1] = obj
        end
    end

    ngx.status = 200
    ngx.header["Content-Type"] = "application/json"
    ngx.say(json.encode({
        total = #items,
        items = items,
    }))
end

return _M
