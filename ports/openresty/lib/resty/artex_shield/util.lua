-- Paths, decoding and the "did a page make the browser send this" test, as util.py does them.

local py = require "resty.artex_shield.py"

local find, sub, gsub, concat = string.find, string.sub, string.gsub, table.concat

local _M = {}

-- Undo up to two layers of URL encoding (with + as a space).
function _M.decode(text)
    for _ = 1, 2 do
        local nxt = py.unquote_plus(text)
        if nxt == text then
            break
        end
        text = nxt
    end
    return text
end

local function collapse(p)
    return (gsub(p, "//+", "/"))
end

-- The path as the shield compares it: percent-decoded, // collapsed, rooted.
function _M.norm_path(path)
    local p = collapse(py.unquote(path == "" and "/" or path))
    return sub(p, 1, 1) == "/" and p or "/" .. p
end

local function json_repr(v)
    if type(v) == "string" then
        return py.json_string(v)
    end
    return tostring(v)
end

-- Validated path prefixes with trailing slashes dropped, or nil and an error.
function _M.prefixes(entries, field)
    if type(entries) == "string" then
        return nil, field .. " must be a list of paths, not one string"
    end
    if type(entries) ~= "table" then
        return nil, field .. " must be a list of paths"
    end
    local out = {}
    for k, entry in ipairs(entries) do
        if type(entry) ~= "string" or sub(entry, 1, 1) ~= "/" or gsub(entry, "/", "") == "" then
            return nil, field .. ": " .. json_repr(entry) .. " must start with '/' and name a path below it"
        end
        out[k] = py.rtrim_bytes(collapse(entry), py.SLASH)
    end
    return out
end

-- Is this path segment a step up, as some server reads it? "..", and also
-- "..;param" (Tomcat, Jetty and Spring drop the parameter), ".." cut short by
-- a NUL, and dots and spaces after it, which some servers trim away.
local function climbs(segment)
    for _, stop in ipairs({";", "\0"}) do
        local cut = find(segment, stop, 1, true)
        if cut then
            segment = sub(segment, 1, cut - 1)
        end
    end
    return sub(segment, 1, 2) == ".." and not find(segment, "[^. ]")
end

local function segments_climb(p)
    local text = gsub(_M.decode(p), "\\", "/")
    for segment in (text .. "/"):gmatch("([^/]*)/") do
        if climbs(segment) then
            return true
        end
    end
    return false
end

-- path is one of list or below one, by whole segments, never when it climbs (see climbs).
function _M.under(path, list)
    if not list[1] then
        return false
    end
    local p = collapse(path == "" and "/" or path)
    if segments_climb(p) then
        return false
    end
    for _, prefix in ipairs(list) do
        if p == prefix or sub(p, 1, #prefix + 1) == prefix .. "/" then
            return true
        end
    end
    return false
end

-- Lower-case extension of the last path segment, without the dot.
function _M.extension(path)
    local name = py.after_last(path, "/")
    local ext, dot = py.after_last(name, ".")
    return dot and py.lower(ext) or ""
end

local EMBEDDED_NOT = {[""] = true, document = true, empty = true, websocket = true}

-- Did a web page, not the person, make the browser send this request? h: lower-case names.
function _M.induced(h)
    local site = py.lower(py.strip(h["sec-fetch-site"] or ""))
    if site == "cross-site" or site == "same-site" then
        return true
    end
    if site == "same-origin" then
        return not EMBEDDED_NOT[py.lower(py.strip(h["sec-fetch-dest"] or ""))]
    end
    if site ~= "" then
        return false
    end
    local referer = h["referer"] or ""
    local host = py.lower(py.strip(h["host"] or ""))
    if referer == "" or host == "" then
        return false
    end
    local origin = py.netloc(py.strip(referer))
    if not origin then
        return false
    end
    origin = py.lower((py.after_last(origin, "@")))
    return origin ~= "" and origin ~= host
end

-- UNION/**/SELECT with comments turned into spaces; MySQL's /*!50000 ... */
-- keeps its contents. nil when there is nothing to strip.
function _M.strip_sql_comments(text)
    if not find(text, "/*", 1, true) then
        return nil
    end
    local out, n, i = {}, 0, 1
    while true do
        local a = find(text, "/*", i, true)
        if not a then
            n = n + 1
            out[n] = sub(text, i)
            break
        end
        n = n + 1
        out[n] = sub(text, i, a - 1) .. " "
        local b = find(text, "*/", a + 2, true)
        if not b then
            break
        end
        if sub(text, a + 2, a + 2) == "!" then
            n = n + 1
            out[n] = gsub(sub(text, a + 3, b - 1), "^[0-9]+", "") .. " "
        end
        i = b + 2
    end
    return concat(out)
end

-- The decoded path, then each decoded query name and value, joined by NUL.
function _M.url_text(path, query)
    local parts, n = {_M.decode(path)}, 1
    for pair in (query .. "&"):gmatch("([^&]*)&") do
        if pair ~= "" then
            local eq = find(pair, "=", 1, true)
            parts[n + 1] = _M.decode(eq and sub(pair, 1, eq - 1) or pair)
            parts[n + 2] = _M.decode(eq and sub(pair, eq + 1) or "")
            n = n + 2
        end
    end
    return concat(parts, "\0")
end

-- Split a query string into name -> value (the last one wins), undecoded.
function _M.params(query)
    local out = {}
    for pair in (query .. "&"):gmatch("([^&]*)&") do
        if pair ~= "" then
            local eq = find(pair, "=", 1, true)
            out[eq and sub(pair, 1, eq - 1) or pair] = eq and sub(pair, eq + 1) or ""
        end
    end
    return out
end

return _M
