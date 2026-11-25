-- What the Python reference does with text, done the same way in Lua: its
-- whitespace, case mapping and code-point slicing, URL decoding, urlsplit's
-- netloc, base64 decoding and math.fsum. Text is UTF-8 throughout; the nginx
-- adapter turns raw header bytes into UTF-8 first (as Latin-1, the way
-- Python's servers read them).

local bit = require "bit"
local unicode = require "resty.artex_shield.unicode"
local ip -- required lazily: ip.lua needs this module

local byte, char, sub, find, gsub, lower, upper, concat, abs =
    string.byte, string.char, string.sub, string.find, string.gsub, string.lower, string.upper, table.concat,
    math.abs
local band, bor, rshift, lshift = bit.band, bit.bor, bit.rshift, bit.lshift
local re_find = ngx.re.find

local _M = {}

-- Python's \s for str patterns, as a PCRE class body (UTF mode).
_M.SPACE = [[\t\n\x{0b}\f\r\x{1c}-\x{1f} \x{85}\x{a0}\x{1680}\x{2000}-\x{200a}\x{2028}\x{2029}\x{202f}\x{205f}\x{3000}]]
-- Python's \w for str patterns.
_M.WORD = [[\p{L}\p{N}_]]

local HIGH = "[\128-\255]"

-- Length in bytes of the whitespace character (str.isspace) at byte i of s, or 0.
local function space_at(s, i)
    local b = byte(s, i)
    if not b then
        return 0
    end
    if b == 32 or (b >= 9 and b <= 13) or (b >= 28 and b <= 31) then
        return 1
    end
    if b == 0xC2 then
        local c = byte(s, i + 1)
        return (c == 0x85 or c == 0xA0) and 2 or 0
    end
    if b == 0xE1 then
        return (byte(s, i + 1) == 0x9A and byte(s, i + 2) == 0x80) and 3 or 0
    end
    if b == 0xE2 then
        local c, d = byte(s, i + 1, i + 2)
        if c == 0x80 then
            return ((d and d >= 0x80 and d <= 0x8A) or d == 0xA8 or d == 0xA9 or d == 0xAF) and 3 or 0
        end
        return (c == 0x81 and d == 0x9F) and 3 or 0
    end
    if b == 0xE3 then
        return (byte(s, i + 1) == 0x80 and byte(s, i + 2) == 0x80) and 3 or 0
    end
    return 0
end

-- Length in bytes of a whitespace character ending at byte j, or 0.
local function space_before(s, j)
    for n = 1, 3 do
        local i = j - n + 1
        if i >= 1 and space_at(s, i) == n then
            return n
        end
    end
    return 0
end

-- str.strip() with no argument.
function _M.strip(s)
    local i, j = 1, #s
    while i <= j do
        local n = space_at(s, i)
        if n == 0 then
            break
        end
        i = i + n
    end
    while j >= i do
        local n = space_before(s, j)
        if n == 0 then
            break
        end
        j = j - n
    end
    return sub(s, i, j)
end

-- s without the bytes in set (byte -> true) at either end: str.strip(chars)
-- for ASCII chars, in linear time. (An end-anchored Lua pattern such as
-- '"+$' rescans each run it fails on, which is quadratic on hostile input.)
function _M.trim_bytes(s, set)
    local i, j = 1, #s
    while i <= j and set[byte(s, i)] do
        i = i + 1
    end
    while j >= i and set[byte(s, j)] do
        j = j - 1
    end
    return sub(s, i, j)
end

-- s without the bytes in set at its end: str.rstrip(chars), in linear time.
function _M.rtrim_bytes(s, set)
    local j = #s
    while j > 0 and set[byte(s, j)] do
        j = j - 1
    end
    return sub(s, 1, j)
end

-- What follows the last c in s (s itself without one), and where that c is:
-- s.rsplit(c, 1)[-1], in linear time.
function _M.after_last(s, c)
    local at, nxt = nil, find(s, c, 1, true)
    while nxt do
        at = nxt
        nxt = find(s, c, nxt + 1, true)
    end
    if not at then
        return s, nil
    end
    return sub(s, at + 1), at
end

_M.QUOTE = {[34] = true}
_M.OWS = {[32] = true, [9] = true}
_M.SLASH = {[47] = true}

-- Is any character of s whitespace?
function _M.has_space(s)
    local i, n = 1, #s
    while i <= n do
        if space_at(s, i) > 0 then
            return true
        end
        i = i + 1
    end
    return false
end

-- len(s) in code points.
function _M.length(s)
    local _, count = gsub(s, "[^\128-\191]", "")
    return count
end

-- s[:n] by code point.
function _M.slice(s, n)
    if #s <= n then
        return s
    end
    if not find(s, HIGH) then
        return sub(s, 1, n)
    end
    local at, count = 1, 0
    while true do
        at = find(s, "[^\128-\191]", at)
        if not at then
            return s
        end
        if count == n then
            return sub(s, 1, at - 1)
        end
        count = count + 1
        at = at + 1
    end
end

-- The code point at byte i of valid UTF-8, and its length in bytes.
local function decode_at(s, i)
    local b = byte(s, i)
    if b < 0x80 then
        return b, 1
    elseif b < 0xE0 then
        return lshift(band(b, 0x1F), 6) + band(byte(s, i + 1), 0x3F), 2
    elseif b < 0xF0 then
        local c, d = byte(s, i + 1, i + 2)
        return lshift(band(b, 0x0F), 12) + lshift(band(c, 0x3F), 6) + band(d, 0x3F), 3
    end
    local c, d, e = byte(s, i + 1, i + 3)
    return lshift(band(b, 0x07), 18) + lshift(band(c, 0x3F), 12) + lshift(band(d, 0x3F), 6) + band(e, 0x3F), 4
end
_M.decode_at = decode_at

local function encode(cp)
    if cp < 0x80 then
        return char(cp)
    elseif cp < 0x800 then
        return char(0xC0 + rshift(cp, 6), 0x80 + band(cp, 0x3F))
    elseif cp < 0x10000 then
        return char(0xE0 + rshift(cp, 12), 0x80 + band(rshift(cp, 6), 0x3F), 0x80 + band(cp, 0x3F))
    end
    return char(0xF0 + rshift(cp, 18), 0x80 + band(rshift(cp, 12), 0x3F), 0x80 + band(rshift(cp, 6), 0x3F),
        0x80 + band(cp, 0x3F))
end
_M.encode = encode

local function mapped(s, ascii, map)
    if not find(s, HIGH) then
        return ascii(s)
    end
    local out, n, i, len = {}, 0, 1, #s
    while i <= len do
        local cp, size = decode_at(s, i)
        n = n + 1
        if cp < 0x80 then
            out[n] = ascii(char(cp))
        else
            out[n] = map[cp] or sub(s, i, i + size - 1)
        end
        i = i + size
    end
    return concat(out)
end

-- str.lower() / str.upper(): Unicode case mapping, from Python's own data
-- (unicode.lua). Not applied: the final-sigma rule, the one place where
-- Python looks at a character's neighbours; nothing the shield lowers is Greek.
function _M.lower(s)
    return mapped(s, lower, unicode.lower)
end

function _M.upper(s)
    return mapped(s, upper, unicode.upper)
end

-- Bytes read as Latin-1 (one character per byte), as UTF-8.
function _M.latin1(bytes)
    if not find(bytes, HIGH) then
        return bytes
    end
    return (gsub(bytes, HIGH, function(c)
        local b = byte(c)
        return char(0xC0 + rshift(b, 6), 0x80 + band(b, 0x3F))
    end))
end

-- Bytes decoded as UTF-8 with U+FFFD for each maximal invalid subpart, as
-- Python's bytes.decode("utf-8", "replace") does.
local REPLACEMENT = "\239\191\189"
function _M.utf8(bytes)
    if not find(bytes, HIGH) then
        return bytes
    end
    local _, _, err = re_find(bytes, "^", "u")
    if not err then
        return bytes                                   -- already valid
    end
    local out, n, i, len = {}, 0, 1, #bytes
    while i <= len do
        local b = byte(bytes, i)
        local need, lo, hi
        if b < 0x80 then
            need = 0
        elseif b >= 0xC2 and b <= 0xDF then
            need, lo, hi = 1, 0x80, 0xBF
        elseif b == 0xE0 then
            need, lo, hi = 2, 0xA0, 0xBF
        elseif (b >= 0xE1 and b <= 0xEC) or b == 0xEE or b == 0xEF then
            need, lo, hi = 2, 0x80, 0xBF
        elseif b == 0xED then
            need, lo, hi = 2, 0x80, 0x9F
        elseif b == 0xF0 then
            need, lo, hi = 3, 0x90, 0xBF
        elseif b >= 0xF1 and b <= 0xF3 then
            need, lo, hi = 3, 0x80, 0xBF
        elseif b == 0xF4 then
            need, lo, hi = 3, 0x80, 0x8F
        else
            need = -1
        end
        n = n + 1
        if need == 0 then
            out[n] = char(b)
            i = i + 1
        elseif need < 0 then
            out[n] = REPLACEMENT
            i = i + 1
        else
            local k = 1
            while k <= need and i + k <= len do
                local c = byte(bytes, i + k)
                if c < (k == 1 and lo or 0x80) or c > (k == 1 and hi or 0xBF) then
                    break
                end
                k = k + 1
            end
            out[n] = k == need + 1 and sub(bytes, i, i + need) or REPLACEMENT
            i = i + k
        end
    end
    return concat(out)
end

local function unhex(h)
    return char(tonumber(h, 16))
end

-- urllib.parse.unquote(s): %XX runs inside each stretch of ASCII text are
-- bytes decoded as UTF-8 (with replacement); other text is kept.
function _M.unquote(s)
    if not find(s, "%", 1, true) then
        return s
    end
    return (gsub(s, "[%z\1-\127]+", function(run)
        if not find(run, "%", 1, true) then
            return run
        end
        return _M.utf8((gsub(run, "%%(%x%x)", unhex)))
    end))
end

-- urllib.parse.unquote_plus(s).
function _M.unquote_plus(s)
    if find(s, "+", 1, true) then
        s = gsub(s, "%+", " ")
    end
    return _M.unquote(s)
end

local function check_bracketed_host(host)
    if sub(host, 1, 1) == "v" then
        if not re_find(host, [[\Av[a-fA-F0-9]+\..+\z]], "jsu") then
            return "IPvFuture address is invalid"
        end
        return nil
    end
    ip = ip or require "resty.artex_shield.ip"
    local parsed = ip.parse(host)
    if not parsed then
        return "not an IP address"
    end
    if parsed.version == 4 then
        return "An IPv4 address cannot be in brackets"
    end
    return nil
end

-- urllib.parse.urlsplit(url).netloc, or nil and the reason where urlsplit raises.
function _M.netloc(url)
    url = gsub(url, "^[%z\1- ]+", "")
    url = gsub(url, "[\t\r\n]", "")
    local colon = find(url, ":", 1, true)
    if colon and colon > 1 and find(url, "^[A-Za-z]") and not find(sub(url, 1, colon - 1), "[^A-Za-z0-9+%-.]") then
        url = sub(url, colon + 1)
    end
    if sub(url, 1, 2) ~= "//" then
        return ""
    end
    local stop = find(url, "[/?#]", 3) or #url + 1
    local net = sub(url, 3, stop - 1)
    local open, close = find(net, "[", 1, true), find(net, "]", 1, true)
    if (open ~= nil) ~= (close ~= nil) then
        return nil, "Invalid IPv6 URL"
    end
    if open then
        local after = sub(net, open + 1)
        local cut = find(after, "]", 1, true)
        local err = check_bracketed_host(cut and sub(after, 1, cut - 1) or after)
        if err then
            return nil, err
        end
    end
    if find(net, HIGH) then
        -- urlsplit refuses a netloc whose NFKC form gains one of / ? # @ :
        local i, len = 1, #net
        while i <= len do
            local cp, size = decode_at(net, i)
            if unicode.nfkc_unsafe[cp] then
                return nil, "netloc contains invalid characters under NFKC normalization"
            end
            i = i + size
        end
    end
    return net
end

local B64 = {}
do
    local alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    for k = 1, 64 do
        B64[byte(alphabet, k)] = k - 1
    end
end

-- base64.b64decode(s) as binascii does it without validation; nil and the
-- reason on an impossible length or missing padding.
function _M.b64decode(s)
    local out, n, quad, left, pads = {}, 0, 0, 0, 0
    for k = 1, #s do
        local c = byte(s, k)
        if c == 61 then                                  -- "="
            if quad >= 2 then
                pads = pads + 1
                if quad + pads >= 4 then
                    return concat(out)
                end
            end
        else
            local v = B64[c]
            if v then
                pads = 0
                if quad == 0 then
                    quad, left = 1, v
                elseif quad == 1 then
                    n = n + 1
                    out[n] = char(band(bor(lshift(left, 2), rshift(v, 4)), 0xFF))
                    quad, left = 2, band(v, 0x0F)
                elseif quad == 2 then
                    n = n + 1
                    out[n] = char(band(bor(lshift(left, 4), rshift(v, 2)), 0xFF))
                    quad, left = 3, band(v, 0x03)
                else
                    n = n + 1
                    out[n] = char(band(bor(lshift(left, 6), v), 0xFF))
                    quad, left = 0, 0
                end
            end
        end
    end
    if quad ~= 0 then
        return nil, quad == 1 and "invalid base64 length" or "Incorrect padding"
    end
    return concat(out)
end

-- The correctly rounded sum of finite floats, as math.fsum.
function _M.fsum(xs)
    local p, count = {}, 0
    for _, x in ipairs(xs) do
        local i = 0
        for j = 1, count do
            local y = p[j]
            if abs(x) < abs(y) then
                x, y = y, x
            end
            local hi = x + y
            local lo = y - (hi - x)
            if lo ~= 0 then
                i = i + 1
                p[i] = lo
            end
            x = hi
        end
        for j = i + 1, count do
            p[j] = nil
        end
        count = i
        if x ~= 0 then
            count = count + 1
            p[count] = x
        end
    end
    local n, hi, lo = count, 0.0, 0.0
    if n > 0 then
        hi = p[n]
        n = n - 1
        while n > 0 do
            local x, y = hi, p[n]
            n = n - 1
            hi = x + y
            lo = y - (hi - x)
            if lo ~= 0 then
                break
            end
        end
        if n > 0 and ((lo < 0 and p[n] < 0) or (lo > 0 and p[n] > 0)) then
            local y = lo * 2
            local x = hi + y
            if y == x - hi then
                hi = x
            end
        end
    end
    return hi
end

local SHORT = {[8] = "\\b", [9] = "\\t", [10] = "\\n", [12] = "\\f", [13] = "\\r", [34] = '\\"', [92] = "\\\\"}

-- json.dumps(str) as Python writes it (ensure_ascii).
function _M.json_string(s)
    local out, n, i, len = {'"'}, 1, 1, #s
    while i <= len do
        local cp, size = decode_at(s, i)
        n = n + 1
        if SHORT[cp] then
            out[n] = SHORT[cp]
        elseif cp < 0x20 or cp >= 0x7F then
            if cp >= 0x10000 then
                local v = cp - 0x10000
                out[n] = string.format("\\u%04x\\u%04x", 0xD800 + rshift(v, 10), 0xDC00 + band(v, 0x3FF))
            else
                out[n] = string.format("\\u%04x", cp)
            end
        else
            out[n] = char(cp)
        end
        i = i + size
    end
    out[n + 1] = '"'
    return concat(out)
end

-- str.isdigit() for ASCII digits; other scripts' digits count as not digits.
function _M.is_digits(s)
    return s ~= "" and not find(s, "[^0-9]")
end


return _M
