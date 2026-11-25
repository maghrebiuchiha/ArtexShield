-- A JSON decoder for the tests that remembers the order of each object's
-- keys: SPEC.md has the honeytoken check read headers in the order they came,
-- and cjson, like any Lua table, forgets it. keys(object) gives the order;
-- carry(from, to) gives a copy the same order. JSON null is cjson.null.

local cjson = require "cjson.safe"

local byte, sub, find, char, concat = string.byte, string.sub, string.find, string.char, table.concat
local tonumber = tonumber

local _M = {}
local ORDER = setmetatable({}, {__mode = "k"})

local function utf8(cp)
    if cp < 0x80 then
        return char(cp)
    elseif cp < 0x800 then
        return char(0xC0 + math.floor(cp / 0x40), 0x80 + cp % 0x40)
    elseif cp < 0x10000 then
        return char(0xE0 + math.floor(cp / 0x1000), 0x80 + math.floor(cp / 0x40) % 0x40, 0x80 + cp % 0x40)
    end
    return char(0xF0 + math.floor(cp / 0x40000), 0x80 + math.floor(cp / 0x1000) % 0x40,
        0x80 + math.floor(cp / 0x40) % 0x40, 0x80 + cp % 0x40)
end

local ESCAPES = {[34] = '"', [92] = "\\", [47] = "/", [98] = "\b", [102] = "\f", [110] = "\n", [114] = "\r", [116] = "\t"}

local value

local function skip(s, i)
    return find(s, "[^ \n\r\t]", i) or #s + 1
end

local function str(s, i)                         -- s[i] is the opening quote
    local out, n, j = {}, 0, i + 1
    while true do
        local k = find(s, '["\\]', j)
        if not k then
            error("unterminated string at " .. i)
        end
        if k > j then
            n = n + 1
            out[n] = sub(s, j, k - 1)
        end
        if byte(s, k) == 34 then
            return concat(out), k + 1
        end
        local e = byte(s, k + 1)
        if e == 117 then                         -- \uXXXX, with surrogate pairs
            local cp = tonumber(sub(s, k + 2, k + 5), 16)
            local nxt = k + 6
            if cp >= 0xD800 and cp <= 0xDBFF and sub(s, nxt, nxt + 1) == "\\u" then
                local lo = tonumber(sub(s, nxt + 2, nxt + 5), 16)
                if lo >= 0xDC00 and lo <= 0xDFFF then
                    cp = 0x10000 + (cp - 0xD800) * 0x400 + (lo - 0xDC00)
                    nxt = nxt + 6
                end
            end
            n = n + 1
            out[n] = utf8(cp)
            j = nxt
        else
            n = n + 1
            out[n] = ESCAPES[e] or error("bad escape at " .. k)
            j = k + 2
        end
    end
end

value = function(s, i)
    i = skip(s, i)
    local c = byte(s, i)
    if c == 123 then                             -- {
        local obj, keys = {}, {}
        i = skip(s, i + 1)
        if byte(s, i) == 125 then
            ORDER[obj] = keys
            return obj, i + 1
        end
        while true do
            local k
            k, i = str(s, skip(s, i))
            i = skip(s, i)
            if byte(s, i) ~= 58 then
                error("expected : at " .. i)
            end
            local v
            v, i = value(s, i + 1)
            obj[k] = v
            keys[#keys + 1] = k
            i = skip(s, i)
            local d = byte(s, i)
            if d == 125 then
                ORDER[obj] = keys
                return obj, i + 1
            end
            if d ~= 44 then
                error("expected , or } at " .. i)
            end
            i = i + 1
        end
    elseif c == 91 then                          -- [
        local arr, n = {}, 0
        i = skip(s, i + 1)
        if byte(s, i) == 93 then
            return arr, i + 1
        end
        while true do
            local v
            v, i = value(s, i)
            n = n + 1
            arr[n] = v
            i = skip(s, i)
            local d = byte(s, i)
            if d == 93 then
                return arr, i + 1
            end
            if d ~= 44 then
                error("expected , or ] at " .. i)
            end
            i = i + 1
        end
    elseif c == 34 then
        return str(s, i)
    elseif sub(s, i, i + 3) == "true" then
        return true, i + 4
    elseif sub(s, i, i + 4) == "false" then
        return false, i + 5
    elseif sub(s, i, i + 3) == "null" then
        return cjson.null, i + 4
    end
    local a, b = find(s, "^-?%d+%.?%d*[eE]?[-+]?%d*", i)
    if not a then
        error("unexpected character at " .. i)
    end
    return tonumber(sub(s, a, b)), b + 1
end

function _M.decode(s)
    local v, i = value(s, 1)
    if skip(s, i) <= #s then
        error("trailing data at " .. i)
    end
    return v
end

-- The object's keys in the order the JSON had them (nil for a table this did not decode).
function _M.keys(obj)
    return ORDER[obj]
end

-- Give copy the key order of original.
function _M.carry(original, copy)
    ORDER[copy] = ORDER[original]
    return copy
end

-- An object as {{key, value}, ...} in its JSON order.
function _M.pairs_of(obj)
    local keys, out = ORDER[obj], {}
    if not keys then
        return obj
    end
    for k, name in ipairs(keys) do
        out[k] = {name, obj[name]}
    end
    return out
end

return _M
