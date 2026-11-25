-- The OpenResty shield against spec/vectors.json, every case the Python
-- reference passes, replayed as spec/SPEC.md says a runner must, with state
-- in lua_shared_dicts as in nginx.
--
--   resty --shdict 'artex_shield 64m' --shdict 'artex_shield_blocks 8m' -I lib tests/vectors.lua
--   (ARTEX_SPEC=dir names another spec/ directory)

local t = require "check"
local cjson = require("cjson.safe").new()
local ojson = require "ordered_json"     -- keeps header order, which cjson loses
local client_check = require "resty.artex_shield.client_check"
local config = require "resty.artex_shield.config"
local core = require "resty.artex_shield.core"
local decoys = require "resty.artex_shield.decoys"
local ip = require "resty.artex_shield.ip"
local signatures = require "resty.artex_shield.signatures"

local spec = os.getenv("ARTEX_SPEC") or (t.here() .. "/../../../spec")
local data = ojson.decode(t.read(spec .. "/vectors.json"))
local NULL = cjson.null
local TOLERANCE = 1e-6

local function null(v)
    return v == nil or v == NULL
end

local function options(cfg, t0)
    local out = {on_event = function() end}
    for k, v in pairs(null(cfg) and {} or cfg) do
        if k == "engagements" then
            local list = {}
            for i, e in ipairs(v) do
                list[i] = {reference = e.reference, cidrs = e.cidrs, start = t0 + e.start, ["end"] = t0 + e["end"]}
            end
            out[k] = list
        else
            out[k] = v
        end
    end
    return out
end

local function body(r)
    if not null(r.body_base64) then
        return ngx.decode_base64(r.body_base64)
    end
    return not null(r.body) and r.body or nil
end

local function fill(template, i)
    if type(template) == "string" then
        return (template:gsub("{i}", tostring(i)))
    end
    if type(template) == "table" then
        local out = {}
        for k, v in pairs(template) do
            out[k] = fill(v, i)
        end
        return ojson.carry(template, out)
    end
    return template
end

local function fresh()
    for _, name in ipairs({"artex_shield", "artex_shield_blocks"}) do
        ngx.shared[name]:flush_all()
        ngx.shared[name]:flush_expired()
    end
end

local Runner = {}
Runner.__index = Runner

local function runner(case, t0)
    fresh()
    local self = setmetatable({case = case, t0 = t0, now = t0, failures = {}}, Runner)
    self.shield = core.new(options(case.config, t0), {clock = function()
        return self.now
    end})
    return self
end

function Runner:fail(where, message)
    self.failures[#self.failures + 1] = self.case.id .. " step " .. where .. ": " .. message
end

function Runner:compare(where, got, want, full)
    local hits = {}
    for k, v in ipairs(got.hits) do
        hits[k] = v
    end
    table.sort(hits)
    if got.action ~= want.action then
        self:fail(where, "action " .. got.action .. ", expected " .. want.action .. " (hits " .. table.concat(hits, ",") .. ")")
    end
    if not t.equal(hits, want.hits) then
        self:fail(where, "hits " .. t.show(hits) .. ", expected " .. t.show(want.hits))
    end
    if full and math.abs(got.score - want.score) > TOLERANCE then
        self:fail(where, "score " .. string.format("%.17g", got.score) .. ", expected " .. want.score)
    end
    if full and not null(want.retry_after) and got.retry_after ~= want.retry_after then
        self:fail(where, "retry_after " .. got.retry_after .. ", expected " .. want.retry_after)
    end
end

function Runner:step(where, step, expect, full)
    local s = self.shield
    if not null(step.request) then
        local r = step.request
        local d = s:check(r.ip, null(r.method) and "GET" or r.method, r.path, null(r.query) and "" or r.query,
            null(r.headers) and {} or ojson.pairs_of(r.headers), body(r))
        if not null(expect) then
            self:compare(where, d, expect, full)
        end
    elseif not null(step.observe) then
        local o = step.observe
        s:observe(o.ip, o.path, o.status, o.induced == true, null(o.content_type) and "" or o.content_type)
    elseif not null(step.client_check) then
        local c = step.client_check
        local r = s:client_check_reply(c.ip, c.query, null(c.headers) and {} or c.headers, c.secure == true)
        local got = {status = r.status, headers = r.headers}
        if not t.equal(got, step.expect) then
            self:fail(where, "client check answered " .. t.show(got) .. ", expected " .. t.show(step.expect))
        end
    elseif step.unblock ~= nil then
        local got = s:unblock(step.unblock)
        if got ~= step.expect then
            self:fail(where, "unblock returned " .. tostring(got) .. ", expected " .. tostring(step.expect))
        end
    elseif step.expect_blocklist ~= nil then
        local got = {}
        for network in pairs(s:blocklist()) do
            got[#got + 1] = network
        end
        table.sort(got)
        if not t.equal(got, step.expect_blocklist) then
            self:fail(where, "blocklist " .. t.show(got) .. ", expected " .. t.show(step.expect_blocklist))
        end
    else
        local keys = {}
        for k in pairs(step) do
            keys[#keys + 1] = k
        end
        self:fail(where, "unknown step " .. table.concat(keys, ","))
    end
end

function Runner:run()
    for n, step in ipairs(self.case.steps) do
        local at = tostring(n - 1)
        if not null(step["repeat"]) then
            local now = self.t0 + step.at
            local started, iteration = false, 0
            for _, run in ipairs(step.expect) do
                for k = 0, run.times - 1 do
                    local final = k == run.times - 1
                    for j, template in ipairs(step.steps) do
                        if started then
                            now = now + step.dt[j]
                        end
                        started = true
                        self.now = now
                        local want = (final and run.last or run.each)[j]
                        self:step(at .. " (repeat " .. iteration .. ", part " .. (j - 1) .. ")",
                            fill(template, step.i_from + iteration), want, final)
                    end
                    iteration = iteration + 1
                end
            end
            if iteration ~= step["repeat"] then
                self:fail(at, "repeat block runs " .. iteration .. " times, declares " .. step["repeat"])
            end
        else
            self.now = self.t0 + step.at
            self:step(at, step, step.expect, true)
        end
    end
    return self.failures
end

t.check("the file is the version this runner reads", function()
    t.same({2, 1800000000}, {data.version, data.t0})
end)

t.check("every case, state in lua_shared_dicts", function()
    local failures, steps = {}, 0
    for _, case in ipairs(data.cases) do
        local r = runner(case, data.t0)
        for _, f in ipairs(r:run()) do
            failures[#failures + 1] = f
        end
    end
    local shown = {}
    for k = 1, math.min(25, #failures) do
        shown[k] = failures[k]
    end
    t.same({}, shown, #failures .. " failures in " .. #data.cases .. " cases")
end)

t.check("client addresses", function()
    for _, item in ipairs(data.client_ip) do
        fresh()
        local s = core.new({trusted_proxies = item.trusted_proxies, on_event = function() end})
        t.same(item.expect, s:client_ip(item.remote, not null(item.forwarded_for) and item.forwarded_for or nil),
            t.show(item))
    end
end)

t.check("client check routes", function()
    for _, item in ipairs(data.client_check_routes) do
        fresh()
        local s = core.new(options(item.config, data.t0))
        local want = not null(item.expect) and item.expect or nil
        t.same(want, s:client_check_route(item.path), t.show(item))
    end
end)

t.check("configs the reference refuses are refused", function()
    for _, item in ipairs(data.config_errors) do
        local ok = pcall(config.make, options(item.config, data.t0))
        t.truthy(not ok, "accepted " .. t.show(item.config))
    end
end)

t.check("canary and honeytoken derivations", function()
    for _, item in ipairs(data.canaries) do
        t.same(item.paths, decoys.canaries(item.secret, item.count))
    end
    for _, item in ipairs(data.honeytokens) do
        local tokens = decoys.honeytokens(item.secret, item.count)
        t.same({item.api_keys, item.users, item.passwords}, {tokens.api_keys, tokens.users, tokens.passwords})
    end
end)

t.check("the client check script", function()
    t.same((data.client_check_script:gsub("PATH", '"/_artex/check"')), client_check.script("/_artex/check"))
end)

t.check("every pattern reads the probe texts as Python does", function()
    local sig = signatures.get()
    local tbl = {}
    for _, r in ipairs(sig.hard_ua) do tbl["hard_ua:" .. r[3]] = r[1] end
    for _, r in ipairs(sig.soft_ua) do tbl["soft_ua:" .. r[3]] = r[1] end
    for _, r in ipairs(sig.payloads) do tbl["payloads:" .. r[2]] = r[1] end
    for _, r in ipairs(sig.oob) do tbl["oob:" .. r[2]] = r[1] end
    for _, name in ipairs({"assessment_ua", "browser_ua", "crawler_ua", "sensitive_paths", "missing_sensitive",
                           "recon_paths"}) do
        tbl[name] = sig[name]
    end
    local wrong, texts = {}, data.pattern_probes.texts
    for name, want in pairs(data.pattern_probes.matches) do
        t.truthy(tbl[name], "a pattern named " .. name)
        for i, text in ipairs(texts) do
            local got = signatures.search(tbl[name], text) and "1" or "0"
            if got ~= want:sub(i, i) then
                wrong[#wrong + 1] = name .. " on " .. t.show({text}) .. ": " .. got .. ", Python " .. want:sub(i, i)
            end
        end
    end
    table.sort(wrong)
    t.same({}, wrong)
end)

t.check("patterns.lua is spec/patterns.json (python ports/openresty/build.py)", function()
    t.same(cjson.decode(t.read(spec .. "/patterns.json")), require "resty.artex_shield.patterns")
end)

t.check("addresses are read and written as Python's ipaddress does", function()
    local cases = {{"2001:db8:6:002::1", "2001:db8:6:2::/64"}, {"::ffff:1.2.3.4", "1.2.3.4"}, {"1.2.3.4", "1.2.3.4"},
        {"fe80::1%eth0", "fe80::/64"}, {"2001:0:0:1::1", "2001:0:0:1::/64"}, {"::1", "::/64"}, {"01.2.3.4", "invalid"},
        {"1:2:3:4:5:6:7:8", "1:2:3:4::/64"}, {"1::2:3:4:5:6:7", "1:0:2:3::/64"}, {"::", "::/64"}, {"1.2.3", "invalid"},
        {"1:2:3:4:5:6:1.2.3.4", "1:2:3:4::/64"}, {":1:2::", "invalid"}, {"1:::2", "invalid"}}
    for _, c in ipairs(cases) do
        t.same(c[2], ip.track_key(c[1]), c[1])
    end
    t.same("2001:db8:5::/56", ip.wider("2001:db8:5:ff::/64"))
    t.same("2001:db8:5::/48", ip.wider("2001:db8:5::/56"))
    t.same(nil, ip.wider("2001:db8::/48"))
    t.same("10.0.0.0/8", ip.format_network(ip.network("10.1.2.3/255.0.0.0")))
    local kids = ip.children("2001:db8:5:100::/56")
    t.same({256, "2001:db8:5:100::/64", "2001:db8:5:1ff::/64"}, {#kids, kids[1], kids[256]})
    for _, kid in ipairs(kids) do
        t.same("2001:db8:5:100::/56", ip.wider(kid), kid)
    end
end)

os.exit(t.report())
