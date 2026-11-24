-- artex-shield at the nginx edge (OpenResty): every request is decided on in
-- the access phase, before it reaches any app behind nginx, with scores and
-- blocks shared by all workers through lua_shared_dict.
--
--   http {
--       lua_shared_dict artex_shield        32m;   # client scores
--       lua_shared_dict artex_shield_blocks 16m;   # blocks and locks
--       lua_package_path "/opt/artex-shield/lib/?.lua;;";
--       init_by_lua_block {
--           require("resty.artex_shield").configure({mode = "monitor", trusted_proxies = {"10.0.0.0/8"}})
--       }
--       server {
--           access_by_lua_block { require("resty.artex_shield").access() }
--           log_by_lua_block    { require("resty.artex_shield").log() }
--           location / { proxy_pass http://app; }
--       }
--   }
--
-- See ports/openresty/README.md.

local core = require "resty.artex_shield.core"
local decoys = require "resty.artex_shield.decoys"
local py = require "resty.artex_shield.py"
local util = require "resty.artex_shield.util"

local find, sub, lower, gsub, concat, sort = string.find, string.sub, string.lower, string.gsub, table.concat,
    table.sort

local _M = {_VERSION = "1.0.0"}

local shield, honeytoken_set

-- Settings the edge adds to the shield's own, as artex-shield-proxy does.
local EDGE = {tracks_dict = true, blocks_dict = true, clock = true, canary_secret = true, canary_count = true,
    honeytoken_secret = true, honeytoken_count = true}

-- PCRE's JIT keeps its backtracking on a stack that is 32 KB unless told
-- otherwise, and several patterns need more on a long header or URL: 1 MB
-- holds every pattern on the 30 KB hostile inputs of tests/cost.lua. It can
-- only be set before any regex runs, in init_by_lua.
local JIT_STACK = 1024 * 1024

local function grow_jit_stack()
    if ngx.get_phase() ~= "init" then
        return
    end
    local ok, ngx_re = pcall(require, "ngx.re")
    if ok and type(ngx_re) == "table" and ngx_re.opt then
        pcall(ngx_re.opt, "jit_stack_size", JIT_STACK)
    end
end

-- Build the shield. Call it in init_by_lua; it raises an error on any
-- setting the reference refuses, so nginx will not start with one.
-- settings: the shield's (spec/SPEC.md, "Configuration"), plus
--   canary_secret, canary_count (3)          derive canary_paths from a secret you keep
--   honeytoken_secret, honeytoken_count (2)  derive honeytokens from a secret you keep
--   tracks_dict, blocks_dict                 lua_shared_dict names (artex_shield, artex_shield_blocks)
function _M.configure(settings)
    settings = settings or {}
    grow_jit_stack()
    local options, edge = {}, {}
    for k, v in pairs(settings) do
        if EDGE[k] then
            edge[k] = v
        else
            options[k] = v
        end
    end
    if edge.canary_secret and options.canary_paths == nil then
        options.canary_paths = decoys.canaries(tostring(edge.canary_secret), edge.canary_count or 3)
    end
    honeytoken_set = nil
    if edge.honeytoken_secret then
        honeytoken_set = decoys.honeytokens(tostring(edge.honeytoken_secret), edge.honeytoken_count or 2)
        local list = {}
        for _, v in ipairs(options.honeytokens or {}) do
            list[#list + 1] = v
        end
        for _, v in ipairs(decoys.watched(honeytoken_set)) do
            list[#list + 1] = v
        end
        options.honeytokens = list
    end
    shield = core.new(options, {tracks = edge.tracks_dict, blocks = edge.blocks_dict, clock = edge.clock})
    return shield
end

-- The shield configure() built: for unblock(), blocklist() and the like.
function _M.shield()
    if not shield then
        error("artex-shield: call require('resty.artex_shield').configure(...) in init_by_lua first", 2)
    end
    return shield
end

-- ---- reading the request -----------------------------------------------------------------
local HIGH = "[\128-\255]"
local OWS_CR = {[32] = true, [9] = true, [13] = true}

-- A header name as the reference keys it: Latin-1, lower-cased.
local function header_name(name)
    if find(name, HIGH) then
        return py.lower(py.latin1(name))
    end
    return lower(name)
end

-- Headers in the order they came, as {{lower-case name, value}, ...}: repeats
-- joined (Cookie with "; ", the rest with ", "), every byte read as Latin-1,
-- as Python's servers read them. HTTP/1 requests are read from the raw head,
-- which keeps the order, in one linear pass; nginx keeps no order for
-- HTTP/2 and 3, so there the names are taken in sorted order.
function _M.read_headers(raw_ok)
    local names, values, n = {}, {}, 0
    local function put(name, value)
        local list = values[name]
        if list == nil then
            n = n + 1
            names[n] = name
            values[name] = {value}
        else
            list[#list + 1] = value
        end
    end
    local raw = raw_ok and ngx.req.http_version() < 2 and ngx.req.raw_header(true)
    if raw then
        local pos, len = 1, #raw
        while pos <= len do
            local eol = find(raw, "\n", pos, true) or len + 1
            local colon = find(raw, ":", pos, true)
            if colon and colon < eol and colon > pos then
                local name = py.trim_bytes(sub(raw, pos, colon - 1), OWS_CR)
                if name ~= "" then
                    put(header_name(name), py.trim_bytes(sub(raw, colon + 1, eol - 1), OWS_CR))
                end
            end
            pos = eol + 1
        end
    else
        local all = ngx.req.get_headers(0, true)
        local sorted = {}
        for name in pairs(all) do
            sorted[#sorted + 1] = name
        end
        sort(sorted, function(a, b)
            return lower(a) < lower(b)
        end)
        for _, name in ipairs(sorted) do
            local v = all[name]
            if type(v) == "table" then
                for _, x in ipairs(v) do
                    put(header_name(name), x)
                end
            else
                put(header_name(name), v)
            end
        end
    end
    local list, h = {}, {}
    for k = 1, n do
        local name = names[k]
        local parts = values[name]
        local value = py.latin1(parts[2] and concat(parts, name == "cookie" and "; " or ", ") or parts[1])
        list[k] = {name, value}
        h[name] = value
    end
    return list, h
end

-- The path (percent-decoded once, as the reference's servers do) and the
-- query (as sent), from the request line as the client sent it: nginx's own
-- $uri has already resolved "..", which would hide a traversal.
local function target()
    local raw = ngx.var.request_uri or "/"
    if find(raw, "^[Hh][Tt][Tt][Pp][Ss]?://") then
        raw = gsub(raw, "^[^:]+://[^/?#]*", "")
        if sub(raw, 1, 1) ~= "/" then
            raw = "/" .. raw
        end
    end
    local q = find(raw, "?", 1, true)
    local path = q and sub(raw, 1, q - 1) or raw
    local query = q and sub(raw, q + 1) or ""
    return py.unquote(py.latin1(path)), py.latin1(query)
end

-- The first limit bytes of the body, for the honeytokens. nginx keeps the
-- body it read for the upstream; one too big for memory is read back from
-- its temporary file.
local function read_body(limit)
    ngx.req.read_body()
    local data = ngx.req.get_body_data()
    if data then
        return sub(data, 1, limit)
    end
    local file = ngx.req.get_body_file()
    if file then
        local f = io.open(file, "rb")
        if f then
            local start = f:read(limit)
            f:close()
            return start
        end
    end
    return nil
end

local function first_token(value)
    return lower(py.strip(((value or "") .. ","):match("^([^,]*),")))
end

-- ---- answering ----------------------------------------------------------------------------
-- What a stopped request gets: 403 or 429, plain text, a reference to quote.
function _M.reply(d)
    if d.action == "block" or d.action == "refuse" then
        local body = "Request " .. (d.action == "block" and "blocked" or "refused") .. ". Reference: " .. d.ref .. "\n"
        return {status = 403, headers = {{"Content-Type", "text/plain; charset=utf-8"},
            {"Content-Length", tostring(#body)}, {"Cache-Control", "no-store"}}, body = body}
    end
    local body = "Too many requests. Reference: " .. d.ref .. "\n"
    return {status = 429, headers = {{"Content-Type", "text/plain; charset=utf-8"},
        {"Content-Length", tostring(#body)}, {"Retry-After", tostring(d.retry_after)}, {"Cache-Control", "no-store"}},
        body = body}
end

local function respond(r)
    ngx.status = r.status
    for _, pair in ipairs(r.headers) do
        ngx.header[pair[1]] = pair[2]
    end
    if r.body ~= "" then
        ngx.print(r.body)
    end
    return ngx.exit(ngx.HTTP_OK)
end

-- ---- the phases ---------------------------------------------------------------------------
-- access_by_lua: decide, and answer the request here when it is stopped or is
-- the client check's own.
function _M.access()
    local s = _M.shield()
    if ngx.req.is_internal() then
        return                                         -- try_files, error_page and the like: decided already
    end
    local peer = ngx.var.remote_addr or ""
    local headers, h = _M.read_headers(true)
    local addr = s:client_ip(peer, h["x-forwarded-for"])
    local method = ngx.req.get_method()
    local path, query = target()
    local body
    local limit = s.cfg.honeytoken_body_limit
    if s.cfg.honeytokens[1] and limit > 0 then
        body = read_body(limit)
    end
    local d = s:check(addr, method, path, query, headers, body)
    local ctx = {ip = addr, path = path, induced = d.induced}
    ngx.ctx.artex_shield = ctx
    if d.stop then
        ctx.answered = true
        return respond(_M.reply(d))
    end
    local route = s:client_check_route(path)
    if route then
        ctx.answered = true
        if route == "script" then
            return respond(s:client_check_asset())
        end
        local secure = ngx.var.https == "on" or (first_token(h["x-forwarded-proto"]) == "https" and s:trusted_peer(peer))
        return respond(s:client_check_reply(addr, query, headers, secure))
    end
end

-- Hand a status to the shield after the response has gone. The log phase
-- cannot wait for a lock, so this runs in a timer straight after it.
function _M.observe_later(addr, path, status, induced, content_type)
    local ok, err = ngx.timer.at(0, function(premature)
        if premature then
            return
        end
        local fine, why = pcall(shield.observe, shield, addr, path, status, induced, content_type)
        if not fine then
            ngx.log(ngx.ERR, "artex-shield: observe failed: ", why)
        end
    end)
    if not ok then
        ngx.log(ngx.WARN, "artex-shield: status not scored: ", err)
    end
end

-- log_by_lua: feed back what the site answered. Only a 404, or with the
-- client check on a 2xx page, can matter, so nothing else is passed on.
function _M.log()
    local s = _M.shield()
    local status = ngx.status
    if status ~= 404 and not (s.cfg.client_check and status >= 200 and status < 300) then
        return
    end
    local ctx = ngx.ctx.artex_shield
    if ctx and ctx.answered then
        return
    end
    if not ctx then
        -- An internal redirect (try_files, error_page) empties ngx.ctx: read the request again.
        local _, h = _M.read_headers(false)
        local path = target()
        ctx = {ip = s:client_ip(ngx.var.remote_addr or "", h["x-forwarded-for"]), path = path,
            induced = not s.cfg.score_induced and util.induced(h)}
    end
    _M.observe_later(ctx.ip, ctx.path, status, ctx.induced, py.latin1(ngx.var.sent_http_content_type or ""))
end

-- ---- for the site owner ------------------------------------------------------------------------
-- What to plant on the site for the decoys these settings watch for, as
-- artex-shield-proxy --print-decoys prints it.
function _M.decoys()
    local cfg, out = _M.shield().cfg, {}
    local canaries = cfg.canary_paths
    if canaries[1] then
        out[#out + 1] = "# robots.txt: add these lines"
        out[#out + 1] = decoys.robots_txt_block(canaries)
        out[#out + 1] = "# HTML: a link no visitor sees, for your page template"
        out[#out + 1] = decoys.html_trap(canaries[1])
        out[#out + 1] = ""
        out[#out + 1] = "# JavaScript: a dead constant, for your bundle"
        out[#out + 1] = decoys.js_trap(canaries[#canaries])
        out[#out + 1] = ""
    end
    if honeytoken_set then
        out[#out + 1] = "# JavaScript: fake credentials, for your bundle"
        out[#out + 1] = decoys.honeytoken_js(honeytoken_set, 0)
        out[#out + 1] = ""
        out[#out + 1] = "# HTML: a comment with fake credentials, for your page template"
        out[#out + 1] = decoys.honeytoken_html(honeytoken_set, 1)
        out[#out + 1] = ""
    end
    if cfg.client_check then
        out[#out + 1] = "# HTML: the client check, on every page"
        out[#out + 1] = shield:client_check_tag()
        out[#out + 1] = ""
    end
    if not out[1] then
        return "# Nothing to plant. Set canary_secret, honeytoken_secret or client_check."
    end
    return (gsub(concat(out, "\n"), "%s+$", ""))
end

-- content_by_lua for an admin location you protect (allow/deny, auth):
-- GET lists the active blocks as JSON; POST ip=<address> lifts a block.
function _M.admin()
    local s = _M.shield()
    local cjson = require("cjson.safe").new()
    ngx.header["Content-Type"] = "application/json"
    ngx.header["Cache-Control"] = "no-store"
    local method = ngx.req.get_method()
    if method == "POST" then
        ngx.req.read_body()
        local args = ngx.req.get_post_args(10) or {}
        local addr = type(args.ip) == "string" and args.ip or ""
        if addr == "" then
            ngx.status = 400
            ngx.say(cjson.encode({error = "send ip=<address>"}))
            return ngx.exit(ngx.HTTP_OK)
        end
        ngx.say(cjson.encode({ip = addr, unblocked = s:unblock(addr)}))
        return ngx.exit(ngx.HTTP_OK)
    end
    if method ~= "GET" and method ~= "HEAD" then
        ngx.status = 405
        ngx.header["Allow"] = "GET, HEAD, POST"
        return ngx.exit(ngx.HTTP_OK)
    end
    local blocks = {}
    for network, expiry in pairs(s:blocklist()) do
        blocks[#blocks + 1] = {network = network, ["until"] = expiry}
    end
    sort(blocks, function(a, b)
        return a.network < b.network
    end)
    ngx.say(cjson.encode({mode = s.cfg.mode, blocks = blocks}))
    return ngx.exit(ngx.HTTP_OK)
end

return _M
