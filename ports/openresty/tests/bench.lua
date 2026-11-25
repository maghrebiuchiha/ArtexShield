-- What one decision costs, with state in lua_shared_dicts as in nginx: a
-- first-seen visitor, a returning one with a full request history, one
-- already blocked, and a 404 fed back. Prints microseconds per call.
--
--   resty --shdict 'artex_shield 64m' --shdict 'artex_shield_blocks 8m' -I lib -I tests tests/bench.lua

local core = require "resty.artex_shield.core"

local N = tonumber(os.getenv("N") or "") or 20000
local BROWSER = {{"Host", "shop.example"},
    {"User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0 Safari/537.36"},
    {"Accept", "text/html,application/xhtml+xml"}, {"Accept-Language", "en-GB,en;q=0.9"},
    {"Accept-Encoding", "gzip, br"}, {"Cookie", "session=0123456789abcdef; theme=dark"}}

local function fresh()
    for _, name in ipairs({"artex_shield", "artex_shield_blocks"}) do
        ngx.shared[name]:flush_all()
        ngx.shared[name]:flush_expired()
    end
end

local function timed(name, fn)
    collectgarbage()
    ngx.update_time()
    local started = ngx.now()
    for i = 1, N do
        fn(i)
    end
    ngx.update_time()
    print(string.format("%-46s %6.1f µs", name, (ngx.now() - started) / N * 1e6))
end

fresh()
local s = core.new({mode = "enforce", on_event = function() end})
local now = 1800000000.0
s.clock = function()
    return now
end
local function ip(i)
    return string.format("10.%d.%d.%d", math.floor(i / 65536) % 256, math.floor(i / 256) % 256, i % 256)
end

timed("a first-seen visitor, browser headers", function(i)
    now = now + 0.001
    s:check(ip(i), "GET", "/products/item-" .. i, "ref=home", BROWSER)
end)
timed("the same visitors again", function(i)
    now = now + 0.001
    s:check(ip(i), "GET", "/products/item-" .. i, "ref=home", BROWSER)
end)
fresh()
s = core.new({mode = "enforce", rate_limit = 100000, on_event = function() end})
s.clock = function()
    return now
end
timed("one visitor with 240 requests of history", function(i)
    now = now + 1
    s:check("192.0.2.1", "GET", "/page-" .. (i % 50), "", BROWSER)
end)
s:check("192.0.2.66", "GET", "/", "", {{"User-Agent", "sqlmap/1.8"}})
timed("a blocked client", function()
    now = now + 0.001
    s:check("192.0.2.66", "GET", "/", "", BROWSER)
end)
timed("a 404 fed back", function(i)
    now = now + 0.5
    s:observe("192.0.2.1", "/missing-" .. i, 404, false, "text/html")
end)
fresh()
s = core.new({mode = "enforce", honeytokens = {"api_live_0123456789abcdefghij"}, on_event = function() end})
s.clock = function()
    return now
end
local body = string.rep("field=value&", 340)                  -- about 4 KB
timed("a first-seen visitor posting 4 KB, honeytokens set", function(i)
    now = now + 0.001
    s:check(ip(i), "POST", "/login", "", BROWSER, body)
end)
