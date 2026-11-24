-- Canary paths and credential honeytokens, derived from a secret exactly as
-- the Python reference does, and the snippets that plant them.

local crypto = require "resty.artex_shield.crypto"
local py = require "resty.artex_shield.py"

local byte, sub, gsub, concat, floor = string.byte, string.sub, string.gsub, table.concat, math.floor

local _M = {}

local SHAPES = {"/api/v1/internal/audit-{}", "/admin/legacy-{}/export", "/api/v2/debug/session-{}",
    "/backend/ops-{}/config", "/api/v1/staff/reports-{}"}
local BASE62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
local USERS = {"svc-deploy", "admin-legacy", "ops-backup", "staging-admin"}
local MARKS = "!@#$*"

-- Stable, unguessable decoy paths derived from a secret.
function _M.canaries(secret, count)
    local out = {}
    for i = 0, (count or 3) - 1 do
        local tag = sub(crypto.hex(crypto.hmac(secret, "canary-" .. i)), 1, 10)
        out[i + 1] = (gsub(SHAPES[i % #SHAPES + 1], "{}", tag))
    end
    return out
end

-- The bytes as a big-endian number, written as length base-62 digits, least significant first.
local function base62(bytes, length)
    local digits = {byte(bytes, 1, -1)}
    local out = {}
    for k = 1, length do
        local rem = 0
        for i = 1, #digits do                          -- long division by 62
            local cur = rem * 256 + digits[i]
            digits[i] = floor(cur / 62)
            rem = cur % 62
        end
        out[k] = sub(BASE62, rem + 1, rem + 1)
    end
    return concat(out)
end

-- Fake credentials from a secret: {api_keys = {}, users = {}, passwords = {}}.
function _M.honeytokens(secret, count)
    count = count or 2
    if count < 1 then
        error("count must be at least 1", 0)
    end
    local keys, users, passwords = {}, {}, {}
    for i = 0, count - 1 do
        keys[i + 1] = "api_live_" .. base62(crypto.hmac(secret, "honeytoken-key-" .. i), 32)
        local d = crypto.hmac(secret, "honeytoken-password-" .. i)
        local body = base62(d, 14)
        local at = byte(d, 2) % 14
        local mark = byte(d, 1) % 5 + 1
        passwords[i + 1] = sub(body, 1, at) .. sub(MARKS, mark, mark) .. sub(body, at + 1) .. (byte(d, 3) % 10)
        users[i + 1] = USERS[i % #USERS + 1]
    end
    return {api_keys = keys, users = users, passwords = passwords}
end

-- The values the shield watches for: the API keys, then the passwords.
function _M.watched(tokens)
    local out = {}
    for _, v in ipairs(tokens.api_keys) do
        out[#out + 1] = v
    end
    for _, v in ipairs(tokens.passwords) do
        out[#out + 1] = v
    end
    return out
end

-- Disallow lines for robots.txt.
function _M.robots_txt_block(canaries)
    local out = {"User-agent: *\n"}
    for _, p in ipairs(canaries) do
        out[#out + 1] = "Disallow: " .. p .. "\n"
    end
    return concat(out)
end

-- A link no person can see or reach by keyboard.
function _M.html_trap(canary)
    return '<a href="' .. canary .. '" rel="nofollow" tabindex="-1" aria-hidden="true" '
        .. 'style="position:absolute;left:-9999px">.</a>'
end

-- A dead constant for a JS bundle.
function _M.js_trap(canary, name)
    return "var " .. (name or "__legacyApi") .. ' = "' .. canary .. '";'
end

-- A dead config object for a JS bundle, with a key and a login.
function _M.honeytoken_js(tokens, index, name)
    local i = (index or 0) % #tokens.api_keys + 1
    local fields = {{"apiBase", "/api/v1"}, {"apiKey", tokens.api_keys[i]}, {"adminUser", tokens.users[i]},
        {"adminPassword", tokens.passwords[i]}}
    local pairs_ = {}
    for k, f in ipairs(fields) do
        pairs_[k] = py.json_string(f[1]) .. ": " .. py.json_string(f[2])
    end
    return "var " .. (name or "__stagingConfig") .. " = {" .. concat(pairs_, ", ") .. "};"
end

-- An HTML comment with credentials someone meant to remove.
function _M.honeytoken_html(tokens, index)
    local i = (index or 1) % #tokens.api_keys + 1
    return "<!-- TODO(ops): remove before release. Staging admin login " .. tokens.users[i] .. " / "
        .. tokens.passwords[i] .. " ; reporting API key " .. tokens.api_keys[i] .. " -->"
end

return _M
