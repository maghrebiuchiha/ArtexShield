-- The shield reads attacker-controlled text on every request, so no input may
-- make that slow: the same budgets and hostile inputs as the Python
-- reference's Cost tests and the PHP port's, for PCRE in ngx.re.
--
--   resty --shdict 'artex_shield 64m' --shdict 'artex_shield_blocks 8m' -I lib -I tests tests/cost.lua

local t = require "check"
local core = require "resty.artex_shield.core"
local signatures = require "resty.artex_shield.signatures"

local BUDGET = 0.25
local BROWSER = {{"User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0 Safari/537.36"},
    {"Accept", "text/html"}, {"Accept-Language", "en-US"}}

local function timed(fn)
    local best = math.huge
    for _ = 1, 2 do                                           -- best of two: ignore a scheduling hiccup
        ngx.update_time()
        local started = ngx.now()
        fn()
        ngx.update_time()
        best = math.min(best, ngx.now() - started)
        if best < BUDGET then
            break
        end
    end
    return best
end

local function fresh()
    for _, name in ipairs({"artex_shield", "artex_shield_blocks"}) do
        ngx.shared[name]:flush_all()
        ngx.shared[name]:flush_expired()
    end
end

t.check("every pattern scans in linear time, and none fails", function()
    local result = require("patterns_matrix").run(BUDGET)
    t.truthy(result.count >= 26, "patterns: " .. result.count)
    t.same({}, result.slow)
    if signatures.is_pcre1() then
        -- resty keeps init_by_lua for itself, so the JIT stack cannot be raised here as configure()
        -- raises it in nginx; tests/smoke.py has nginx run this matrix with the edge's stack.
        print(string.format("      PCRE1: %d searches ran out of resty's JIT stack; smoke.py checks them in nginx",
            result.jit_stack))
    else
        t.same({}, result.failed)
    end
end)

t.check("oversized requests are checked quickly", function()
    fresh()
    local s = core.new({mode = "enforce", on_event = function() end})
    local padded = {}
    for k, v in ipairs(BROWSER) do
        padded[k] = v
    end
    for i = 1, 60 do
        padded[#padded + 1] = {"X-Pad-" .. i, string.rep("a", 8000)}
    end
    local with = function(extra)
        local out = {}
        for k, v in ipairs(BROWSER) do
            out[k] = v
        end
        for _, v in ipairs(extra) do
            out[#out + 1] = v
        end
        return out
    end
    local cases = {
        {"60 padded headers", function() s:check("192.0.2.90", "GET", "/", "", padded) end},
        {"8000-character path", function() s:check("192.0.2.91", "GET", "/" .. string.rep("db", 4000) .. "!", "", BROWSER) end},
        {"60000-character query", function() s:check("192.0.2.92", "GET", "/", string.rep("a", 60000), BROWSER) end},
        {"20000 query parameters", function() s:check("192.0.2.93", "GET", "/", string.rep("a=b&", 20000), BROWSER) end},
        {"8000-character user agent", function()
            s:check("192.0.2.94", "GET", "/", "", {{"User-Agent", string.rep("Mozilla/5.0 ", 660)}})
        end},
        {"8000-character referer", function()
            s:check("192.0.2.95", "GET", "/", "", with({{"Host", "shop.example"}, {"Referer", "https://" .. string.rep("a.", 4000)}}))
        end},
        {"a quote, then 60000 spaces", function()
            s:check("192.0.2.89", "GET", "/", "q='+or" .. string.rep("+", 60000), BROWSER)
        end},
        {"a 64 KB body with honeytokens set", function()
            fresh()
            core.new({honeytokens = {"api_live_0123456789abcdef"}, on_event = function() end})
                :check("192.0.2.96", "POST", "/", "", BROWSER, string.rep("%", 65536))
        end},
        {"240 requests of one client's history", function()
            for i = 1, 240 do
                s:check("192.0.2.97", "GET", "/page-" .. i, "", BROWSER)
            end
        end},
    }
    for _, c in ipairs(cases) do
        local took = timed(c[2])
        t.truthy(took < BUDGET, string.format("%s: %.2f s", c[1], took))
    end
end)

t.check("hostile header text is trimmed and split in linear time", function()
    -- Runs that an end-anchored Lua pattern ('"+$', "[ \t]+$", "[^@]*$") would rescan
    -- once per character: 64 KiB of each, where a quadratic pass takes seconds.
    local py = require "resty.artex_shield.py"
    local ip = require "resty.artex_shield.ip"
    local util = require "resty.artex_shield.util"
    local client_check = require "resty.artex_shield.client_check"
    local big = 65536
    fresh()
    local s = core.new({client_check = true, client_check_secret = "a key for the cost test", on_event = function() end})
    local cases = {
        {"header value: spaces inside", function() py.trim_bytes("a" .. string.rep(" ", big) .. "x", py.OWS) end},
        {"cookie value: quotes inside", function()
            client_check.cookie("artex_check=a" .. string.rep('"', big) .. "x", "artex_check")
        end},
        {"X-Forwarded-For hop: quotes inside", function() ip.hop_ip("a" .. string.rep('"', big) .. "x") end},
        {"X-Forwarded-For: many hops", function()
            s:client_ip("127.0.0.1", string.rep("a" .. string.rep('"', 64) .. "b,", 1000))
        end},
        {"a 404 path: one long segment", function()
            s:observe("192.0.2.98", "/" .. string.rep("a", big) .. "/x", 404, false, "")
            util.extension("/" .. string.rep("a", big) .. ".")
        end},
        {"a referer: a long host before @", function()
            util.induced({host = "shop.example", referer = "https://" .. string.rep("a", big) .. "@x/"})
        end},
        {"a request with all of them", function()
            s:check("192.0.2.99", "GET", "/api/" .. string.rep("a", 8000) .. "/x", "", {
                {"Cookie", "artex_check=a" .. string.rep('"', 16000) .. "x"},
                {"Referer", "https://" .. string.rep("a", 8000) .. "@x/"},
                {"Accept", "application/json"}, {"X-Pad", "a" .. string.rep(" ", 8000) .. "x"}})
        end},
    }
    for _, c in ipairs(cases) do
        local took = timed(c[2])
        t.truthy(took < BUDGET, string.format("%s: %.2f s", c[1], took))
    end
end)

os.exit(t.report())
