-- A small test harness: check(name, fn) runs fn and reports it; same() and
-- truthy() fail the check they are called in.

local _M = {passed = 0, failed = 0}

local cjson = require("cjson.safe").new()

local function show(v)
    if type(v) == "table" then
        return cjson.encode(v) or tostring(v)
    end
    return tostring(v)
end
_M.show = show

local function equal(a, b)
    if a == b then
        return true
    end
    if type(a) ~= "table" or type(b) ~= "table" then
        return false
    end
    for k, v in pairs(a) do
        if not equal(v, b[k]) then
            return false
        end
    end
    for k in pairs(b) do
        if a[k] == nil then
            return false
        end
    end
    return true
end
_M.equal = equal

local Failure = {}

function _M.same(want, got, what)
    if not equal(want, got) then
        error(setmetatable({message = (what and what .. ": " or "") .. "expected " .. show(want) .. ", got "
            .. show(got)}, Failure), 0)
    end
end

function _M.truthy(got, what)
    if not got then
        error(setmetatable({message = (what or "expected a true value") .. ", got " .. show(got)}, Failure), 0)
    end
end

function _M.check(name, fn)
    ngx.update_time()
    local started = ngx.now()
    local ok, err = xpcall(fn, function(e)
        if getmetatable(e) == Failure then
            return e.message
        end
        return tostring(e) .. "\n" .. debug.traceback()
    end)
    ngx.update_time()
    local ms = (ngx.now() - started) * 1000
    if ok then
        _M.passed = _M.passed + 1
        print(string.format("ok    %s (%d ms)", name, ms))
    else
        _M.failed = _M.failed + 1
        print(string.format("FAIL  %s\n      %s", name, (tostring(err):gsub("\n", "\n      "))))
    end
end

function _M.report()
    print(string.format("%d passed, %d failed", _M.passed, _M.failed))
    return _M.failed == 0 and 0 or 1
end

-- The text of a file, or an error.
function _M.read(path)
    local f = assert(io.open(path, "rb"))
    local text = f:read("*a")
    f:close()
    return text
end

-- This file's directory, for paths relative to the tests.
function _M.here()
    local source = debug.getinfo(2, "S").source
    return (source:sub(2):match("^(.*)/[^/]*$") or ".")
end

return _M
