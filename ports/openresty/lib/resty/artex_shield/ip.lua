-- IP addresses and networks as Python's ipaddress module reads and writes
-- them: strict IPv4, IPv6 with "::", an IPv4 tail and an optional %scope,
-- RFC 5952 text. IPv4 is held as a number, IPv6 as eight 16-bit groups.
-- (LuaJIT's bit operations are signed 32-bit, so masks are arithmetic.)

local py = require "resty.artex_shield.py"

local find, sub, gsub, format, concat, floor = string.find, string.sub, string.gsub, string.format, table.concat,
    math.floor

local _M = {}

local function split(s, sep)
    local out, n, start = {}, 0, 1
    while true do
        local at = find(s, sep, start, true)
        n = n + 1
        if not at then
            out[n] = sub(s, start)
            return out, n
        end
        out[n] = sub(s, start, at - 1)
        start = at + #sep
    end
end

local function parse_v4(s)
    local parts, count = split(s, ".")
    if count ~= 4 then
        return nil
    end
    local value = 0
    for k = 1, 4 do
        local part = parts[k]
        if not find(part, "^[0-9][0-9]?[0-9]?$") or (part ~= "0" and sub(part, 1, 1) == "0") then
            return nil
        end
        local n = tonumber(part)
        if n > 255 then
            return nil
        end
        value = value * 256 + n
    end
    return value
end

local function hex_group(part)
    if not find(part, "^[0-9A-Fa-f][0-9A-Fa-f]?[0-9A-Fa-f]?[0-9A-Fa-f]?$") then
        return nil
    end
    return tonumber(part, 16)
end

local function parse_v6(s)
    local addr, scope = s, nil
    local pct = find(s, "%", 1, true)
    if pct then
        addr, scope = sub(s, 1, pct - 1), sub(s, pct + 1)
        if scope == "" or find(scope, "%", 1, true) then
            return nil
        end
    end
    if addr == "" then
        return nil
    end
    local parts, count = split(addr, ":")
    if count < 3 then
        return nil
    end
    if find(parts[count], ".", 1, true) then
        local v4 = parse_v4(parts[count])
        if not v4 then
            return nil
        end
        parts[count] = format("%x", floor(v4 / 65536))
        parts[count + 1] = format("%x", v4 % 65536)
        count = count + 1
    end
    if count > 9 then
        return nil
    end
    local skip
    for k = 2, count - 1 do
        if parts[k] == "" then
            if skip then
                return nil
            end
            skip = k
        end
    end
    local hi, lo, skipped
    if skip then
        hi, lo = skip - 1, count - skip
        if parts[1] == "" then
            hi = hi - 1
            if hi ~= 0 then
                return nil
            end
        end
        if parts[count] == "" then
            lo = lo - 1
            if lo ~= 0 then
                return nil
            end
        end
        skipped = 8 - (hi + lo)
        if skipped < 1 then
            return nil
        end
    else
        if count ~= 8 or parts[1] == "" or parts[count] == "" then
            return nil
        end
        hi, lo, skipped = count, 0, 0
    end
    local groups, n = {}, 0
    for k = 1, hi do
        local g = hex_group(parts[k])
        if not g then
            return nil
        end
        n = n + 1
        groups[n] = g
    end
    for _ = 1, skipped do
        n = n + 1
        groups[n] = 0
    end
    for k = count - lo + 1, count do
        local g = hex_group(parts[k])
        if not g then
            return nil
        end
        n = n + 1
        groups[n] = g
    end
    return {version = 6, v6 = groups, scope = scope}
end

-- {version = 4, v4 = n} or {version = 6, v6 = {8 groups}, scope = s|nil}, or nil.
function _M.parse(s)
    local v4 = parse_v4(s)
    if v4 then
        return {version = 4, v4 = v4}
    end
    return parse_v6(s)
end

-- The IPv4 address inside ::ffff:a.b.c.d, or the address itself.
local function unmapped(a)
    if a.version == 6 then
        local g = a.v6
        if g[1] == 0 and g[2] == 0 and g[3] == 0 and g[4] == 0 and g[5] == 0 and g[6] == 0xFFFF then
            return {version = 4, v4 = g[7] * 65536 + g[8]}
        end
    end
    return a
end

local function format_v4(v)
    return format("%d.%d.%d.%d", floor(v / 16777216), floor(v / 65536) % 256, floor(v / 256) % 256, v % 256)
end

local function format_v6(groups)
    local hex = {}
    for k = 1, 8 do
        hex[k] = format("%x", groups[k])
    end
    local best_start, best_len, start, len = -1, 0, -1, 0
    for k = 1, 8 do
        if hex[k] == "0" then
            len = len + 1
            if start == -1 then
                start = k
            end
            if len > best_len then
                best_len, best_start = len, start
            end
        else
            len, start = 0, -1
        end
    end
    if best_len > 1 then
        local out = {}
        for k = 1, best_start - 1 do
            out[#out + 1] = hex[k]
        end
        if best_start == 1 then
            out[#out + 1] = ""
        end
        out[#out + 1] = ""
        if best_start + best_len - 1 == 8 then
            out[#out + 1] = ""
        end
        for k = best_start + best_len, 8 do
            out[#out + 1] = hex[k]
        end
        return concat(out, ":")
    end
    return concat(hex, ":")
end

-- Address bits under a prefix.
local function masked(a, prefix)
    if a.version == 4 then
        local size = 2 ^ (32 - prefix)
        return {version = 4, v4 = a.v4 - a.v4 % size, prefix = prefix}
    end
    local groups = {}
    for k = 1, 8 do
        local bits = math.max(0, math.min(16, prefix - 16 * (k - 1)))
        local size = 2 ^ (16 - bits)
        groups[k] = a.v6[k] - a.v6[k] % size
    end
    return {version = 6, v6 = groups, prefix = prefix}
end

local function same_net(a, b)
    if a.version ~= b.version or a.prefix ~= b.prefix then
        return false
    end
    if a.version == 4 then
        return a.v4 == b.v4
    end
    for k = 1, 8 do
        if a.v6[k] ~= b.v6[k] then
            return false
        end
    end
    return true
end

-- ip_network(text, strict=False), or nil and an error.
function _M.network(text)
    local pieces, count = split(text, "/")
    if count > 2 then
        return nil, "not a network: " .. text
    end
    local a = _M.parse(pieces[1])
    if not a then
        return nil, "not a network: " .. text
    end
    local max = a.version == 4 and 32 or 128
    local prefix = max
    if count == 2 then
        local arg = pieces[2]
        if find(arg, "^[0-9]+$") and tonumber(arg) <= max then
            prefix = tonumber(arg)
        elseif a.version == 4 and parse_v4(arg) then
            local m = parse_v4(arg)
            prefix = -1
            for _, candidate in ipairs({m, 4294967295 - m}) do
                for p = 0, 32 do
                    if prefix < 0 and masked({version = 4, v4 = 4294967295}, p).v4 == candidate then
                        prefix = p
                    end
                end
            end
            if prefix < 0 then
                return nil, "bad netmask in " .. text
            end
        else
            return nil, "bad prefix in " .. text
        end
    end
    return masked(a, prefix)
end

function _M.format_network(n)
    return (n.version == 4 and format_v4(n.v4) or format_v6(n.v6)) .. "/" .. n.prefix
end

-- Networks from CIDR texts, or nil and the first error.
function _M.networks(list)
    local out = {}
    for k, text in ipairs(list) do
        local n, err = _M.network(tostring(text))
        if not n then
            return nil, err
        end
        out[k] = n
    end
    return out
end

-- Is ip inside any of nets (from network())? IPv4-mapped IPv6 counts as IPv4.
function _M.in_nets(ip, nets)
    if not nets[1] then
        return false
    end
    local parsed = _M.parse(ip)
    if not parsed then
        return false
    end
    local a = unmapped(parsed)
    for _, n in ipairs(nets) do
        if n.version == a.version and same_net(masked(a, n.prefix), n) then
            return true
        end
    end
    return false
end

-- An address that can stand for one client: parseable and not unspecified.
function _M.usable(ip)
    local parsed = _M.parse(ip)
    if not parsed then
        return false
    end
    local a = unmapped(parsed)
    if a.version == 4 then
        return a.v4 ~= 0
    end
    for k = 1, 8 do
        if a.v6[k] ~= 0 then
            return true
        end
    end
    return false
end

-- One score per client: an IPv4 address, or an IPv6 /64.
function _M.track_key(ip)
    local parsed = _M.parse(ip)
    if not parsed then
        return "invalid"
    end
    local a = unmapped(parsed)
    if a.version == 4 then
        return format_v4(a.v4)
    end
    return _M.format_network(masked(a, 64))
end

local STEP = {[64] = 56, [56] = 48}

-- /64 -> /56 -> /48 for IPv6 block keys; nil otherwise.
function _M.wider(key)
    if not find(key, ":", 1, true) then
        return nil
    end
    local n = _M.network(key)
    local step = n and STEP[n.prefix]
    if not step then
        return nil
    end
    return _M.format_network(masked(n, step))
end

-- The keys a block on an IPv6 parent (/56 or /48) can have below it: every
-- /64 in a /56, every /56 in a /48.
function _M.children(parent)
    local n = _M.network(parent)
    local below = n and ({[56] = 64, [48] = 56})[n.prefix]
    if not below then
        return {}
    end
    local out, step = {}, below == 64 and 1 or 256
    for k = 0, 255 do
        local groups = {n.v6[1], n.v6[2], n.v6[3], n.v6[4] + k * step, 0, 0, 0, 0}
        out[k + 1] = _M.format_network({version = 6, v6 = groups, prefix = below})
    end
    return out
end

-- The address in one X-Forwarded-For entry, or nil. Ports are dropped.
function _M.hop_ip(hop)
    local h = py.trim_bytes(py.strip(hop), py.QUOTE)
    if sub(h, 1, 1) == "[" then
        local close = find(h, "]", 1, true)
        if close and close > 1 then
            h = sub(h, 2, close - 1)
        end
    else
        local _, colons = gsub(h, ":", "")
        if colons == 1 then
            h = sub(h, 1, find(h, ":", 1, true) - 1)
        end
    end
    return _M.parse(h) and h or nil
end

return _M
