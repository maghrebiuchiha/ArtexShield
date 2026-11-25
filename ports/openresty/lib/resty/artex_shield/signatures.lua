-- The signature patterns, from patterns.lua (spec/patterns.json, generated
-- from the Python reference's signatures.py), translated from Python's regex
-- dialect to PCRE for ngx.re.

local py = require "resty.artex_shield.py"

local byte, sub, find, concat = string.byte, string.sub, string.find, table.concat
local re_find, re_match = ngx.re.find, ngx.re.match

local _M = {}

local WORD, SPACE = py.WORD, py.SPACE

local function escape_length(src, i)
    local n = sub(src, i + 1, i + 1)
    return n == "x" and 4 or (n == "u" and 6 or 2)
end

-- One escape at src[i]: a string, or {negated = body} inside a class.
local function escape(src, i, in_class)
    local n = sub(src, i + 1, i + 1)
    if n == "w" then return in_class and WORD or "[" .. WORD .. "]" end
    if n == "s" then return in_class and SPACE or "[" .. SPACE .. "]" end
    if n == "d" then return [[\p{Nd}]] end
    if n == "W" then return in_class and {negated = WORD} or "[^" .. WORD .. "]" end
    if n == "S" then return in_class and {negated = SPACE} or "[^" .. SPACE .. "]" end
    if n == "D" then return in_class and {negated = [[\p{Nd}]]} or [[\P{Nd}]] end
    if n == "b" then
        return in_class and [[\x{08}]] or "(?:(?<=[" .. WORD .. "])(?![" .. WORD .. "])|(?<![" .. WORD .. "])(?=["
            .. WORD .. "]))"
    end
    if n == "B" then
        return "(?:(?<=[" .. WORD .. "])(?=[" .. WORD .. "])|(?<![" .. WORD .. "])(?![" .. WORD .. "]))"
    end
    if n == "A" then return [[\A]] end
    if n == "Z" then return [[\z]] end
    if n == "x" then return [[\x{]] .. sub(src, i + 2, i + 3) .. "}" end
    if n == "u" then return [[\x{]] .. sub(src, i + 2, i + 5) .. "}" end
    if n == "v" then return [[\x{0b}]] end
    if n == "n" or n == "r" or n == "t" or n == "f" then return "\\" .. n end
    if n == "" then
        error("pattern ends in a backslash", 0)
    end
    if find(n, "^[A-Za-z0-9]") then
        error("unsupported escape \\" .. n, 0)
    end
    return "\\" .. n                         -- a literal: \. \" \' \- and the like
end

-- A character class from src[i] ("["), and the index after it. One holding
-- \S, \W or \D becomes an alternation, as for the other ports, so its meaning
-- stays exact.
local function char_class(src, i)
    local n = #src
    local j = i + 1
    local negate = false
    if sub(src, j, j) == "^" then
        negate = true
        j = j + 1
    end
    local items, negated, first = {}, {}, true
    while j <= n do
        local c = sub(src, j, j)
        if c == "]" and not first then
            break
        end
        first = false
        if c == "\\" then
            local piece = escape(src, j, true)
            if type(piece) == "table" then
                negated[#negated + 1] = piece.negated
            else
                items[#items + 1] = piece
            end
            j = j + escape_length(src, j)
        else
            items[#items + 1] = (c == "[" or c == "]") and "\\" .. c or c
            j = j + 1
        end
    end
    if sub(src, j, j) ~= "]" then
        error("unterminated character class", 0)
    end
    local body = concat(items)
    if body ~= "" and re_find("i", "(*LF)[" .. body .. "]", "iu") then
        if find(body, "^%-$") or find(body, "[^\\]%-$") then
            body = sub(body, 1, -2) .. "\\-"       -- a final "-" is literal; keep it so
        end
        body = body .. [[\x{131}\x{130}]]
    end
    if not negated[1] then
        return "[" .. (negate and "^" or "") .. body .. "]", j + 1
    end
    if negate then
        error([[a negated class holding \S, \W or \D is not supported]], 0)
    end
    local alternatives = {}
    if body ~= "" then
        alternatives[1] = "[" .. body .. "]"
    end
    for _, b in ipairs(negated) do
        alternatives[#alternatives + 1] = "[^" .. b .. "]"
    end
    return "(?:" .. concat(alternatives, "|") .. ")", j + 1
end

-- Python re to PCRE in UTF mode with the meanings SPEC.md gives: \w \s \d \b
-- by Python's Unicode classes, and Python's one case equivalence PCRE's
-- folding lacks (i, I, dotless ı, dotted İ). PCRE already reads (?P<name>),
-- (?P=name), \A, $ and "." as Python does (with LF newlines).
function _M.translate(src)
    local out, n, i = {}, #src, 1
    while i <= n do
        local c = sub(src, i, i)
        if c == "\\" then
            out[#out + 1] = escape(src, i, false)
            i = i + escape_length(src, i)
        elseif c == "[" then
            local piece
            piece, i = char_class(src, i)
            out[#out + 1] = piece
        elseif c == "(" and (sub(src, i, i + 3) == "(?P<" or sub(src, i, i + 3) == "(?P=") then
            local stop = find(src, "[>)]", i + 4) or n
            out[#out + 1] = sub(src, i, stop)      -- the group's name, copied as it is
            i = stop + 1
        elseif c == "i" or c == "I" then
            out[#out + 1] = [=[[iI\x{131}\x{130}]]=]
            i = i + 1
        else
            out[#out + 1] = c
            i = i + 1
        end
    end
    return concat(out)
end

-- A Python pattern as a PCRE pattern for ngx.re (options: OPTIONS).
function _M.compile(src)
    return "(*LF)" .. _M.translate(src)
end

local OPTIONS, NO_JIT = "ijou", "iou"

-- Is nginx built with PCRE1? Its matcher without the JIT backtracks by C
-- recursion, and on a long text that overflows the worker's stack. The two
-- report invalid UTF-8 differently: PCRE1 -10, PCRE2 -23.
local pcre1
local function is_pcre1()
    if pcre1 == nil then
        local _, _, err = re_find("\255", ".", "u")
        pcre1 = type(err) == "string" and find(err, "%-10$") ~= nil
    end
    return pcre1
end
_M.is_pcre1 = is_pcre1

local function failed(err, rx)
    ngx.log(ngx.ERR, "artex-shield: pattern failed (", err, "), counted as a match: ", sub(rx, 1, 60))
end

-- Does rx match anywhere in text? PCRE's JIT keeps its backtracking on a
-- fixed stack (the edge module makes it 1 MB), and a repeated group over a
-- very long text can run it out. Then, with PCRE2, the same pattern runs
-- again without the JIT, which backtracks on the heap; with PCRE1 that would
-- crash the worker, so the failure is logged and counts as a match, as any
-- other failure (the match limit, say) does: as no match, text built to
-- exhaust PCRE would carry a payload past the pattern. The patterns scan in
-- linear time (tests/cost.lua), so text a visitor sends does not get here.
-- text must be valid UTF-8.
function _M.search(rx, text)
    local from, _, err = re_find(text, rx, OPTIONS)
    if err then
        if is_pcre1() then
            failed(err, rx)
            return true
        end
        from, _, err = re_find(text, rx, NO_JIT)
        if err then
            failed(err, rx)
            return true
        end
    end
    return from ~= nil
end

-- The first capture of rx in text, "" when it matched without one (or when
-- PCRE failed on it: see search()), or nil.
function _M.capture(rx, text)
    local m, err = re_match(text, rx, OPTIONS)
    if err then
        if is_pcre1() then
            failed(err, rx)
            return ""
        end
        m, err = re_match(text, rx, NO_JIT)
        if err then
            failed(err, rx)
            return ""
        end
    end
    if not m then
        return nil
    end
    return m[1] or ""
end

local compiled

-- Every table, compiled: hard_ua and soft_ua as {rx, points, label}, payloads
-- and oob as {rx, label}, the rest as one pattern, and the method sets.
function _M.get()
    if compiled then
        return compiled
    end
    local p = require "resty.artex_shield.patterns"
    local c = {}
    for _, name in ipairs({"hard_ua", "soft_ua"}) do
        c[name] = {}
        for k, r in ipairs(p[name]) do
            c[name][k] = {_M.compile(r[1]), r[2], r[3]}
        end
    end
    for _, name in ipairs({"payloads", "oob"}) do
        c[name] = {}
        for k, r in ipairs(p[name]) do
            c[name][k] = {_M.compile(r[1]), r[2]}
        end
    end
    for _, name in ipairs({"assessment_ua", "browser_ua", "crawler_ua", "sensitive_paths", "missing_sensitive",
                           "recon_paths"}) do
        c[name] = _M.compile(p[name])
    end
    for _, name in ipairs({"odd_methods", "soft_methods"}) do
        c[name] = {}
        for _, m in ipairs(p[name]) do
            c[name][m] = true
        end
    end
    compiled = c
    return c
end

return _M
