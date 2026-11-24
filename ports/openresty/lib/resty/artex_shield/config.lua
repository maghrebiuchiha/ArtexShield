-- Settings, with the defaults and checks of the Python reference's Config,
-- under the same snake_case names. See spec/SPEC.md for what each means.

local decoys = require "resty.artex_shield.decoys"
local ip = require "resty.artex_shield.ip"
local py = require "resty.artex_shield.py"
local util = require "resty.artex_shield.util"

local floor, find = math.floor, string.find

local _M = {}

local function list(...)
    return {...}
end

local DEFAULTS = {
    mode = "monitor",
    throttle_score = 50,
    block_score = 100,
    half_life = 600,
    block_ttl = 3600,
    max_block_ttl = 86400,
    retry_after = 120,
    ignored_throttle_points = 5,
    trusted_proxies = list(),
    allow_cidrs = list(),
    exempt_paths = list(),
    engagements = list(),
    canary_paths = list(),
    enum_404_threshold = 15,
    enum_window = 60,
    rate_limit = 240,
    rate_window = 60,
    cadence_samples = 30,
    cadence_min_mean = 0.15,
    cadence_max_mean = 2.0,
    cadence_max_cv = 0.35,
    tls_denylist = list(),
    max_tracks = 50000,
    enum_ignore_prefixes = list(),
    enum_ignore_extensions = list("js", "mjs", "css", "map", "png", "jpg", "jpeg", "gif", "svg", "webp", "avif", "ico",
        "woff", "woff2", "ttf", "otf", "eot", "mp3", "mp4", "webm"),
    score_induced = false,
    max_blocks = 100000,
    v6_escalate_after = 0,
    slow_enum_budget = 60,
    slow_enum_window = 3600,
    slow_enum_points = 10,
    client_check = false,
    client_check_path = "/_artex/check",
    client_check_cookie = "artex_check",
    client_check_api_prefixes = list("/api"),
    client_check_grace = 30,
    client_check_ttl = 86400,
    client_check_points = 20,
    honeytokens = list(),
    honeytoken_body_limit = 65536,
}
-- Settings whose default is "none" (Lua tables cannot hold nil). on_event is
-- wiring, not behaviour: called with each event table.
local OPTIONAL = {tls_header = true, soft_cap = true, client_check_secret = true, on_event = true}

local NUMBERS = {"throttle_score", "block_score", "half_life", "block_ttl", "max_block_ttl", "ignored_throttle_points",
    "enum_window", "rate_window", "cadence_min_mean", "cadence_max_mean", "cadence_max_cv", "slow_enum_window",
    "slow_enum_points", "client_check_grace", "client_check_ttl", "client_check_points"}
local WHOLE = {"retry_after", "enum_404_threshold", "rate_limit", "cadence_samples", "max_tracks", "max_blocks",
    "v6_escalate_after", "slow_enum_budget", "honeytoken_body_limit"}
local LEAST = {rate_limit = 1, cadence_samples = 2, enum_404_threshold = 1, max_tracks = 1, max_blocks = 1,
    v6_escalate_after = 0, slow_enum_budget = 0}

_M.DEFAULTS = DEFAULTS

local function copy(v)
    if type(v) ~= "table" then
        return v
    end
    local out = {}
    for k, x in pairs(v) do
        out[k] = copy(x)
    end
    return out
end

local function fail(message)
    error(message, 0)
end

local function check_list(c, name)
    if type(c[name]) == "string" then
        fail(name .. " must be a list, not one string")
    end
    if type(c[name]) ~= "table" then
        fail(name .. " must be a list")
    end
end

local function prefixes(v, field)
    local out, err = util.prefixes(v, field)
    if not out then
        fail(err)
    end
    return out
end

-- Unix seconds from a number, or an ISO 8601 time with a timezone (UTC "Z" or an offset).
local function seconds(v)
    if type(v) == "number" then
        return v
    end
    if type(v) == "string" then
        local y, mo, d, h, mi, s, zone = v:match("^%s*(%d%d%d%d)-(%d%d)-(%d%d)[Tt ](%d%d):(%d%d):?(%d*%.?%d*)%s*(.-)%s*$")
        if y and zone ~= "" then
            local offset
            if zone == "Z" or zone == "z" then
                offset = 0
            else
                local sign, oh, om = zone:match("^([+-])(%d%d):?(%d%d)$")
                if sign then
                    offset = (tonumber(oh) * 3600 + tonumber(om) * 60) * (sign == "-" and -1 or 1)
                end
            end
            if offset then
                -- days from the civil date (proleptic Gregorian), then seconds
                y, mo, d = tonumber(y), tonumber(mo), tonumber(d)
                local yy = mo <= 2 and y - 1 or y
                local era = floor(yy / 400)
                local yoe = yy - era * 400
                local doy = floor((153 * (mo + (mo > 2 and -3 or 9)) + 2) / 5) + d - 1
                local doe = yoe * 365 + floor(yoe / 4) - floor(yoe / 100) + doy
                local days = era * 146097 + doe - 719468
                return days * 86400 + tonumber(h) * 3600 + tonumber(mi) * 60 + (tonumber(s) or 0) - offset
            end
        end
    end
    fail("engagement times must be Unix seconds or an ISO time with a timezone")
end

local function is_null(v)
    return v == nil or v == ngx.null
end

-- A complete, checked config. Raises an error on anything the reference refuses.
function _M.make(options)
    options = options or {}
    local unknown = {}
    for k in pairs(options) do
        if DEFAULTS[k] == nil and not OPTIONAL[k] then
            unknown[#unknown + 1] = tostring(k)
        end
    end
    if unknown[1] then
        table.sort(unknown)
        fail("unknown settings: " .. table.concat(unknown, ", "))
    end
    local c = copy(DEFAULTS)
    for k, v in pairs(options) do
        if is_null(v) then
            c[k] = DEFAULTS[k] ~= nil and copy(DEFAULTS[k]) or nil
        else
            c[k] = k == "on_event" and v or copy(v)
        end
    end
    for _, k in ipairs(NUMBERS) do
        if type(c[k]) ~= "number" then
            fail(k .. " must be a number")
        end
    end
    for _, k in ipairs(WHOLE) do
        if type(c[k]) ~= "number" or floor(c[k]) ~= c[k] then
            fail(k .. " must be a whole number")
        end
    end
    if c.mode ~= "monitor" and c.mode ~= "enforce" then
        fail("mode must be 'monitor' or 'enforce'")
    end
    for name, least in pairs(LEAST) do
        if c[name] < least then
            fail(name .. " must be at least " .. least)
        end
    end
    if c.v6_escalate_after == 1 then
        fail("v6_escalate_after must be 0 (off) or at least 2")
    end
    for _, name in ipairs({"half_life", "rate_window", "enum_window", "slow_enum_window", "block_ttl"}) do
        if not (c[name] > 0) then
            fail(name .. " must be positive")
        end
    end
    c.exempt_paths = prefixes(c.exempt_paths, "exempt_paths")
    c.enum_ignore_prefixes = prefixes(c.enum_ignore_prefixes, "enum_ignore_prefixes")
    local tokens = c.honeytokens
    if type(tokens) == "string" then
        fail("honeytokens must be a list of values (or make_honeytokens(...)), not one string")
    end
    if type(tokens) ~= "table" then
        fail("honeytokens must be a list of values")
    end
    if tokens.api_keys then
        tokens = decoys.watched(tokens)                -- straight from decoys.honeytokens()
    end
    local seen, unique = {}, {}
    for _, t in ipairs(tokens) do
        t = tostring(t)
        if not seen[t] then
            seen[t] = true
            unique[#unique + 1] = t
        end
    end
    for _, t in ipairs(unique) do
        if py.length(t) < 12 or py.has_space(t) then
            fail("honeytoken " .. py.slice(t, 4) .. "... must be at least 12 characters with no whitespace: "
                .. "anything shorter could turn up in ordinary requests")
        end
    end
    c.honeytokens = unique
    if c.honeytoken_body_limit < 0 then
        fail("honeytoken_body_limit must not be negative")
    end
    c.client_check_api_prefixes = prefixes(c.client_check_api_prefixes, "client_check_api_prefixes")
    prefixes({c.client_check_path}, "client_check_path")
    if type(c.client_check_cookie) ~= "string" or not find(c.client_check_cookie, "^[A-Za-z0-9_-]+$")
        or #c.client_check_cookie > 64 then
        fail("client_check_cookie must be 1 to 64 letters, digits, - or _")
    end
    for _, name in ipairs({"client_check_ttl", "client_check_points"}) do
        if not (c[name] > 0) then
            fail(name .. " must be positive")
        end
    end
    if c.client_check_grace < 0 then
        fail("client_check_grace must not be negative")
    end
    if not (c.throttle_score > 0 and c.throttle_score <= c.block_score) then
        fail("need 0 < throttle_score <= block_score")
    end
    if c.soft_cap == nil then
        c.soft_cap = 0.8 * c.throttle_score
    elseif type(c.soft_cap) ~= "number" then
        fail("soft_cap must be a number")
    end
    if not (c.soft_cap >= 0 and c.soft_cap < c.throttle_score) then
        fail("need 0 <= soft_cap < throttle_score")
    end
    for _, name in ipairs({"trusted_proxies", "allow_cidrs", "canary_paths", "tls_denylist", "enum_ignore_extensions"}) do
        check_list(c, name)
    end
    for _, name in ipairs({"trusted_proxies", "allow_cidrs"}) do
        local _, err = ip.networks(c[name])
        if err then
            fail(name .. ": " .. err)
        end
    end
    check_list(c, "engagements")
    local engagements = {}
    for k, e in ipairs(c.engagements) do
        if type(e) ~= "table" or is_null(e.reference) or is_null(e.cidrs) or is_null(e.start) or is_null(e["end"]) then
            fail("an engagement needs reference, cidrs, start and end")
        end
        local cidrs = type(e.cidrs) == "table" and e.cidrs or {e.cidrs}
        local nets, err = ip.networks(cidrs)
        if not nets then
            fail("engagement " .. tostring(e.reference) .. ": " .. err)
        end
        engagements[k] = {reference = tostring(e.reference), cidrs = cidrs, nets = nets, start = seconds(e.start),
            ["end"] = seconds(e["end"])}
    end
    c.engagements = engagements
    for _, name in ipairs({"score_induced", "client_check"}) do
        c[name] = c[name] == true
    end
    if c.tls_header ~= nil and type(c.tls_header) ~= "string" then
        fail("tls_header must be a header name")
    end
    if c.client_check_secret ~= nil and type(c.client_check_secret) ~= "string" then
        fail("client_check_secret must be a string")
    end
    if c.on_event ~= nil and type(c.on_event) ~= "function" then
        fail("on_event must be a function")
    end
    return c
end

return _M
