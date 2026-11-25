-- What the vectors cannot see: how this port keeps state in lua_shared_dicts.
-- The track's text form, the block table's entries, count, pruning and
-- capacity, the locks, and the key the client check signs with.
--
--   resty --shdict 'artex_shield 64m' --shdict 'artex_shield_blocks 8m' -I lib -I tests tests/store.lua

local t = require "check"
local core = require "resty.artex_shield.core"
local track = require "resty.artex_shield.track"

local T0 = 1800000000.0
local SCANNER = {["User-Agent"] = "sqlmap/1.8.4#stable"}
local tracks, blocks = ngx.shared.artex_shield, ngx.shared.artex_shield_blocks

local function fresh()
    for _, d in ipairs({tracks, blocks}) do
        d:flush_all()
        d:flush_expired()
    end
end

-- A shield on a clock the test moves.
local function shield(options)
    fresh()
    local clock = {now = T0}
    options = options or {}
    options.on_event = options.on_event or function() end
    local s = core.new(options, {clock = function()
        return clock.now
    end})
    return s, clock
end

local function block_keys()
    local out = {}
    for _, name in ipairs(blocks:get_keys(0)) do
        if name:sub(1, 2) == "b:" then
            out[#out + 1] = name:sub(3)
        end
    end
    table.sort(out)
    return out
end

t.check("a track comes back from its text exactly", function()
    local tr = track.new(T0 + 0.1)
    tr.hard, tr.soft_points, tr.strikes, tr.throttled_until = 12.345678901234567, 1 / 3, 2, T0 + 120.000001
    tr.page_at, tr.automation_at = T0 + 1e-7, T0 + 0.30000000000000004
    for i = 1, 40 do
        tr.times[i] = T0 + i * 0.1 + i * 1e-9                 -- gaps that only 17 digits keep
    end
    tr.not_found, tr.slow = {T0 + 0.5, T0 + 0.75}, {T0}
    tr.missing = {{"0123456789abcdef", T0 + 1.5}, {"fedcba9876543210", T0 + 2.25}}
    tr.soft = {["ua:http-library"] = T0 + 3, ["odd|label;with=sep,and%"] = T0 + 4}
    local back = track.decode(track.encode(tr, T0 + 4, 60, 30))
    t.same(tr, back)
    t.same(nil, track.decode("not a track"))
    t.same(nil, track.decode("2|0|0"))
end)

t.check("request times that can change no decision are not kept", function()
    local tr = track.new(T0)
    for i = 1, 100 do
        tr.times[i] = T0 + i
    end
    -- at T0 + 200 with a 60 s window: only the last 30 (cadence) are needed
    local back = track.decode(track.encode(tr, T0 + 200, 60, 30))
    t.same(30, #back.times)
    t.same(T0 + 71, back.times[1])
    -- at T0 + 101, everything since T0 + 41 is inside the window
    back = track.decode(track.encode(tr, T0 + 101, 60, 30))
    t.same(60, #back.times)
end)

t.check("a block is one entry, counted, kept past its end for pruning", function()
    local s, clock = shield({mode = "enforce"})
    t.same("block", s:check("192.0.2.1", "GET", "/", "", SCANNER).action)
    t.same({"192.0.2.1"}, block_keys())
    t.same(T0 + 3600, blocks:get("b:192.0.2.1"))
    t.same(1, blocks:get("bn"))
    local ttl = blocks:ttl("b:192.0.2.1")
    t.truthy(ttl > 3600 + 3500 and ttl <= 3600 + 3600, "the entry outlives the block by an hour: " .. ttl)
    local kept = tracks:ttl("t:192.0.2.1")
    t.truthy(kept > 7 * 86400 - 10, "the track is kept a week: " .. kept)
    clock.now = T0 + 10
    t.same(true, s:unblock("192.0.2.1"))
    t.same({}, block_keys())
    t.same(0, blocks:get("bn"))
    t.same(nil, tracks:get("t:192.0.2.1"))
end)

t.check("an expired block is dropped when its client comes back, unless it was renewed", function()
    local s, clock = shield({mode = "enforce"})
    s:check("192.0.2.2", "GET", "/", "", SCANNER)
    clock.now = T0 + 3601
    local d = s:check("192.0.2.2", "GET", "/", "", {["User-Agent"] = "curl/8"})
    t.truthy(d.action ~= "block", "not blocked once the block has ended: " .. d.action)
    t.same({}, block_keys())
    t.same(0, blocks:get("bn"))
    s:check("192.0.2.3", "GET", "/", "", SCANNER)            -- renewed by another worker meanwhile:
    blocks:set("b:192.0.2.3", T0 + 99999)
    t.same("block", s:check("192.0.2.3", "GET", "/", "", {}).action)
    t.same({"192.0.2.3"}, block_keys())
end)

t.check("blocking prunes expired entries at most once a minute, as the reference does", function()
    local s, clock = shield({mode = "enforce", block_ttl = 100, max_block_ttl = 100})
    s:check("192.0.2.10", "GET", "/", "", SCANNER)           -- prunes (the table was stamped at T0)
    clock.now = T0 + 30
    s:check("192.0.2.11", "GET", "/", "", SCANNER)           -- 30 s since: no prune
    clock.now = T0 + 101
    s:check("192.0.2.12", "GET", "/", "", SCANNER)           -- prunes: .10 has expired, .11 is live
    t.same({"192.0.2.11", "192.0.2.12"}, block_keys())
    t.same(T0 + 101, blocks:get("bp"))
    clock.now = T0 + 140
    s:check("192.0.2.13", "GET", "/", "", SCANNER)           -- .11 expired, but 39 s since the prune
    t.same({"192.0.2.11", "192.0.2.12", "192.0.2.13"}, block_keys())
    t.same(3, blocks:get("bn"))
    t.same({["192.0.2.12"] = T0 + 201, ["192.0.2.13"] = T0 + 240}, s:blocklist())   -- lists the live ones,
    t.same({"192.0.2.12", "192.0.2.13"}, block_keys())                              -- dropping the rest
    t.same(2, blocks:get("bn"))
end)

t.check("a full table drops the blocks nearest their end, the earliest set first among equals", function()
    local s, clock = shield({mode = "enforce", max_blocks = 4})
    for i = 1, 4 do
        clock.now = T0 + (i <= 2 and 1 or i)                  -- .1 and .2 end at the same instant
        s:check("198.51.100." .. i, "GET", "/", "", SCANNER)
    end
    t.same(4, blocks:get("bn"))
    clock.now = T0 + 10
    s:check("198.51.100.5", "GET", "/", "", SCANNER)          -- full: one goes, the first of the two nearest
    t.same({"198.51.100.2", "198.51.100.3", "198.51.100.4", "198.51.100.5"}, block_keys())
    t.same(4, blocks:get("bn"))
end)

t.check("a count that drifted is put right by the next prune", function()
    local s, clock = shield({mode = "enforce"})
    s:check("203.0.113.1", "GET", "/", "", SCANNER)
    blocks:set("bn", 99999)                                   -- entries nginx dropped without telling
    clock.now = T0 + 61
    s:check("203.0.113.2", "GET", "/", "", SCANNER)
    t.same(2, blocks:get("bn"))
end)

t.check("rotating /64s inside one /56 escalate to the /56, found by its children", function()
    local s = shield({mode = "enforce", v6_escalate_after = 2})
    s:check("2001:db8:5:101::1", "GET", "/", "", SCANNER)
    t.same({"2001:db8:5:101::/64"}, block_keys())
    s:check("2001:db8:5:1ff::1", "GET", "/", "", SCANNER)
    t.same({"2001:db8:5:100::/56"}, block_keys())
    t.same(1, blocks:get("bn"))
    t.same("block", s:check("2001:db8:5:1aa::9", "GET", "/", "", {}).action)
end)

t.check("a call waits for its client's lock, and goes on without it after a second", function()
    local s, clock = shield({mode = "enforce"})
    blocks:set("l:t:192.0.2.50", true, 5)                     -- another worker holds this client
    local started = ngx.now()
    local th = ngx.thread.spawn(function()
        return s:check("192.0.2.50", "GET", "/", "", SCANNER).action
    end)
    ngx.sleep(0.05)
    blocks:delete("l:t:192.0.2.50")                           -- it lets go
    local _, action = ngx.thread.wait(th)
    ngx.update_time()
    t.same("block", action)
    t.truthy(ngx.now() - started >= 0.04, "it waited")
    t.same(nil, blocks:get("l:t:192.0.2.50"))                 -- and let go of its own
    t.same(nil, blocks:get("l:blocks"))
    blocks:set("l:t:192.0.2.51", true, 30)                    -- never let go
    ngx.update_time()
    started = ngx.now()
    t.same("block", s:check("192.0.2.51", "GET", "/", "", SCANNER).action)
    ngx.update_time()
    local waited = ngx.now() - started
    t.truthy(waited >= 0.9 and waited < 2, "it gave up after about a second: " .. waited)
    t.same(true, blocks:get("l:t:192.0.2.51"))                -- not someone else's to release
    clock.now = T0
end)

t.check("updates from interleaved calls for one client are all kept", function()
    local s = shield({rate_limit = 1000})
    local threads = {}
    for i = 1, 50 do
        threads[i] = ngx.thread.spawn(function()
            return s:check("192.0.2.60", "GET", "/page-" .. i, "", {["User-Agent"] = "curl/8"})
        end)
    end
    for _, th in ipairs(threads) do
        ngx.thread.wait(th)
    end
    local tr = track.decode(tracks:get("t:192.0.2.60"))
    t.same(50, #tr.times)
end)

t.check("without a secret, every shield on the same dicts signs with one key", function()
    fresh()
    local a = core.new({client_check = true, on_event = function() end})
    local b = core.new({client_check = true, on_event = function() end})
    t.truthy(#a.check_key == 32, "a 32-byte key")
    t.same(a.check_key, b.check_key)
    local set = core.new({client_check = true, client_check_secret = "a secret of our own", on_event = function() end})
    t.same("a secret of our own", set.check_key)
end)

t.check("a block renewed while a call waited for the table's lock is kept, not dropped as expired", function()
    local s, clock = shield({mode = "enforce"})
    s:check("192.0.2.4", "GET", "/", "", SCANNER)            -- blocked until T0 + 3600
    clock.now = T0 + 3601                                     -- ended, as this call first reads it
    blocks:set("l:blocks", true, 5)                           -- but another worker holds the table
    local th = ngx.thread.spawn(function()
        return s:check("192.0.2.4", "GET", "/", "", {["User-Agent"] = "curl/8"}).action
    end)
    ngx.sleep(0.02)
    blocks:set("b:192.0.2.4", T0 + 9999)                      -- and renews the block meanwhile
    blocks:delete("l:blocks")
    local _, action = ngx.thread.wait(th)
    t.same("block", action)
    t.same(T0 + 9999, blocks:get("b:192.0.2.4"))
end)

t.check("a blocks dict too small for max_blocks makes room for the newest block", function()
    local tiny = ngx.shared.artex_shield_tiny
    tiny:flush_all()
    tiny:flush_expired()
    tracks:flush_all()
    local now = T0
    local s = core.new({mode = "enforce", on_event = function() end}, {blocks = "artex_shield_tiny", clock = function()
        return now
    end})
    for i = 1, 400 do
        now = T0 + i
        s:check("198.51.100." .. (i % 250) .. "", "GET", "/", "", SCANNER)
        s:check("203.0.113." .. (i % 250) .. "", "GET", "/", "", SCANNER)
    end
    now = T0 + 401
    t.same("block", s:check("192.0.2.200", "GET", "/", "", SCANNER).action)
    t.truthy(tiny:get("b:192.0.2.200"), "the newest block is kept")
    local kept = 0
    for _, name in ipairs(tiny:get_keys(0)) do
        if name:sub(1, 2) == "b:" then
            kept = kept + 1
        end
    end
    t.truthy(kept > 10 and kept < 400, "older blocks made room: " .. kept .. " kept")
    t.same(kept, tiny:get("bn"))
end)

t.check("a missing dict is named at start-up", function()
    local ok, err = pcall(core.new, {}, {tracks = "no_such_dict"})
    t.same(false, ok)
    t.truthy(tostring(err):find("no_such_dict", 1, true), err)
end)

os.exit(t.report())
