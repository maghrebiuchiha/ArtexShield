-- Test hooks for tests/nginx/harness.conf and tests/edge.py. They wrap the
-- edge module without changing it: the vector's clock comes from a header,
-- the harness's own headers are hidden from the shield, what the shield was
-- asked and what it decided are kept for /__test/report, and observe_later()
-- records its calls instead of making them, because the harness feeds the
-- vector's own observe steps (as tests/test_proxy.py does for the proxy).

local edge = require "resty.artex_shield"
local cjson = require("cjson.safe").new()
cjson.encode_empty_table_as_object(false)
cjson.encode_number_precision(16)

local test = ngx.shared.artex_test
local _M = {}

local function clock()
    return test:get("now") or ngx.now()
end

local function record(key, value)
    test:set(key, cjson.encode(value))
end

local function configure(cfg)
    for _, name in ipairs({"artex_shield", "artex_shield_blocks"}) do
        ngx.shared[name]:flush_all()
        ngx.shared[name]:flush_expired()
    end
    cfg.clock = clock
    cfg.on_event = function() end
    local s = edge.configure(cfg)
    local check = s.check
    s.check = function(self, addr, method, path, query, headers, body)
        local d = check(self, addr, method, path, query, headers, body)
        record("asked", {addr, method, path, query, headers, body and ngx.encode_base64(body) or false})
        record("decision", {action = d.action, hits = d.hits, score = d.score, retry_after = d.retry_after,
            stop = d.stop, enforced = d.enforced, induced = d.induced})
        return d
    end
    return s
end

local read_headers = edge.read_headers

function _M.init()
    configure({})
    edge.read_headers = function(raw_ok)
        local list, h = read_headers(raw_ok)
        local drop_host = h["x-test-host"] == "drop"
        local kept, map = {}, {}
        for _, pair in ipairs(list) do
            local name = pair[1]
            if name:sub(1, 7) ~= "x-test-" and not (drop_host and name == "host") then
                kept[#kept + 1] = pair
                map[name] = pair[2]
            end
        end
        return kept, map
    end
    edge.observe_later = function(addr, path, status, induced, content_type)
        local list = cjson.decode(test:get("reported") or "[]")
        list[#list + 1] = {addr, path, status, induced, content_type}
        record("reported", list)
    end
end

local function json_body()
    ngx.req.read_body()
    return assert(cjson.decode(ngx.req.get_body_data() or "null"), "a JSON body")
end

local function answer(value)
    ngx.header["Content-Type"] = "application/json"
    ngx.print(cjson.encode(value))
    return ngx.exit(ngx.HTTP_OK)
end

-- POST {"config": {...}, "now": t}: a fresh shield for the next case.
function _M.case()
    local job = json_body()
    test:set("now", job.now)
    local ok, err = pcall(configure, job.config)
    return answer({ok = ok, error = not ok and tostring(err) or nil})
end

local function null(v)
    return v == nil or v == cjson.null
end

-- POST {"now": t, "step": {...}}: a step run on the shield directly.
function _M.step()
    local job = json_body()
    test:set("now", job.now)
    local s, step = edge.shield(), job.step
    if not null(step.request) then
        local r = step.request
        local body = not null(r.body_base64) and ngx.decode_base64(r.body_base64) or (not null(r.body) and r.body or nil)
        local d = s:check(r.ip, null(r.method) and "GET" or r.method, r.path, null(r.query) and "" or r.query,
            null(r.headers) and {} or r.headers, body)
        return answer({action = d.action, hits = d.hits, score = d.score, retry_after = d.retry_after})
    elseif not null(step.observe) then
        local o = step.observe
        s:observe(o.ip, o.path, o.status, o.induced == true, null(o.content_type) and "" or o.content_type)
        return answer({})
    elseif not null(step.client_check) then
        local c = step.client_check
        local r = s:client_check_reply(c.ip, c.query, null(c.headers) and {} or c.headers, c.secure == true)
        return answer({status = r.status, headers = r.headers})
    elseif not null(step.unblock) then
        return answer({unblocked = s:unblock(step.unblock)})
    elseif not null(step.route) then
        return answer({route = s:client_check_route(step.route) or cjson.null})
    end
    local networks = {}
    for network in pairs(s:blocklist()) do
        networks[#networks + 1] = network
    end
    table.sort(networks)
    return answer({blocklist = networks})
end

-- What the last request asked and got, and the statuses passed on since; then forget them.
function _M.report()
    local out = {asked = cjson.decode(test:get("asked") or "null"), decision = cjson.decode(test:get("decision") or "null"),
        reported = cjson.decode(test:get("reported") or "[]")}
    test:delete("asked")
    test:delete("decision")
    test:delete("reported")
    return answer(out)
end

function _M.access()
    local now = tonumber(ngx.var.http_x_test_clock or "")
    if now then
        test:set("now", now)
    end
    return edge.access()
end

function _M.log()
    return edge.log()
end

return _M
