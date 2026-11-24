-- HMAC-SHA256 (OpenResty ships SHA-256 but only HMAC-SHA1), hex, URL-safe
-- base64 and a constant-time comparison.

local bit = require "bit"
local sha256 = require "resty.sha256"

local byte, char, rep, format, concat, gsub = string.byte, string.char, string.rep, string.format, table.concat,
    string.gsub
local bxor, bor = bit.bxor, bit.bor

local _M = {}

function _M.sha256(s)
    local h = sha256:new()
    h:update(s)
    return h:final()
end

local pads = setmetatable({}, {__mode = "k"})

local function keyed(key)
    local p = pads[key]
    if p then
        return p
    end
    local k = #key > 64 and _M.sha256(key) or key
    k = k .. rep("\0", 64 - #k)
    local inner, outer = {}, {}
    for i = 1, 64 do
        local b = byte(k, i)
        inner[i] = char(bxor(b, 0x36))
        outer[i] = char(bxor(b, 0x5c))
    end
    p = {concat(inner), concat(outer)}
    if #pads < 64 then
        pads[key] = p
    end
    return p
end

-- HMAC-SHA256(key, msg), raw bytes.
function _M.hmac(key, msg)
    local p = keyed(key)
    return _M.sha256(p[2] .. _M.sha256(p[1] .. msg))
end

function _M.hex(raw)
    return (gsub(raw, ".", function(c)
        return format("%02x", byte(c))
    end))
end

-- URL-safe base64 without padding.
function _M.b64url(raw)
    return (gsub(gsub(ngx.encode_base64(raw, true), "+", "-"), "/", "_"))
end

-- a == b, in time that depends only on their lengths.
function _M.equal(a, b)
    if #a ~= #b then
        return false
    end
    local diff = 0
    for i = 1, #a do
        diff = bor(diff, bxor(byte(a, i), byte(b, i)))
    end
    return diff == 0
end

-- n random bytes from OpenSSL.
function _M.random(n)
    local random = require "resty.random"
    return random.bytes(n, true) or random.bytes(n)
end

return _M
