-- The edge module's own settings and answers, outside nginx's phases.
--
--   resty --shdict 'artex_shield 64m' --shdict 'artex_shield_blocks 8m' -I lib -I tests tests/adapter.lua

local t = require "check"
local edge = require "resty.artex_shield"
local decoys = require "resty.artex_shield.decoys"

local function fresh()
    for _, name in ipairs({"artex_shield", "artex_shield_blocks"}) do
        ngx.shared[name]:flush_all()
    end
end

t.check("secrets become canary paths and honeytokens, as the proxy derives them", function()
    fresh()
    local s = edge.configure({canary_secret = "c-secret", canary_count = 4, honeytoken_secret = "h-secret",
        honeytokens = {"api_live_my_own_value_1"}, on_event = function() end})
    t.same(decoys.canaries("c-secret", 4), s.cfg.canary_paths)
    local made = decoys.honeytokens("h-secret", 2)
    t.same({"api_live_my_own_value_1", made.api_keys[1], made.api_keys[2], made.passwords[1], made.passwords[2]},
        s.cfg.honeytokens)
    t.same(s, edge.shield())
    t.same("monitor", s.cfg.mode)                              -- the default stays monitor
end)

t.check("canary_paths given outright win over canary_secret", function()
    fresh()
    local s = edge.configure({canary_secret = "c-secret", canary_paths = {"/mine"}, on_event = function() end})
    t.same({"/mine"}, s.cfg.canary_paths)
end)

t.check("what to plant is printed as artex-shield-proxy --print-decoys prints it", function()
    fresh()
    edge.configure({canary_secret = "c-secret", honeytoken_secret = "h-secret", client_check = true,
        on_event = function() end})
    local text = edge.decoys()
    local made, paths = decoys.honeytokens("h-secret", 2), decoys.canaries("c-secret", 3)
    t.truthy(text:find("Disallow: " .. paths[1], 1, true), text)
    t.truthy(text:find(decoys.html_trap(paths[1]), 1, true), "the HTML trap")
    t.truthy(text:find(decoys.js_trap(paths[3]), 1, true), "the JS trap")
    t.truthy(text:find(" login " .. made.users[2] .. " / " .. made.passwords[2] .. " ;", 1, true), "the HTML comment")
    t.truthy(text:find('<script src="/_artex/check.js" async></script>', 1, true), "the client check tag")
    fresh()
    edge.configure({on_event = function() end})
    t.truthy(edge.decoys():find("^# Nothing to plant"), edge.decoys())
end)

t.check("a setting the reference refuses stops start-up, naming it", function()
    fresh()
    for _, bad in ipairs({{mode = "block-everyone"}, {exempt_paths = {"/"}}, {trusted_proxies = {"not-a-network"}},
                          {honeytokens = {"short"}}, {no_such_setting = 1}, {rate_limit = 1.5}}) do
        local ok, err = pcall(edge.configure, bad)
        t.truthy(not ok, "accepted " .. t.show(bad))
        t.truthy(type(err) == "string" and #err > 10, "a reason: " .. tostring(err))
    end
end)

t.check("stopped requests get the reference's answers", function()
    local r = edge.reply({action = "block", ref = "0123abcd", retry_after = 0})
    t.same({403, "Request blocked. Reference: 0123abcd\n"}, {r.status, r.body})
    t.same({{"Content-Type", "text/plain; charset=utf-8"}, {"Content-Length", "37"}, {"Cache-Control", "no-store"}},
        r.headers)
    r = edge.reply({action = "refuse", ref = "0123abcd", retry_after = 0})
    t.same({403, "Request refused. Reference: 0123abcd\n"}, {r.status, r.body})
    r = edge.reply({action = "throttle", ref = "0123abcd", retry_after = 121})
    t.same({429, "Too many requests. Reference: 0123abcd\n"}, {r.status, r.body})
    t.same({"Retry-After", "121"}, r.headers[3])
end)

os.exit(t.report())
