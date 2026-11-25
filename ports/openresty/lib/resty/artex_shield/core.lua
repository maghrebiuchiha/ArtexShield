-- Per-client scoring, sensors and fire control: a port of the Python
-- reference's core.py, held to the same decisions by spec/vectors.json.
--
-- State lives in two lua_shared_dicts, so every nginx worker sees the same
-- scores and blocks:
--   tracks  each client's track ("t:<key>"); when the dict is full, nginx
--           drops the least recently used, which is the reference's
--           max_tracks done by size
--   blocks  one entry per blocked network ("b:<net>" -> expiry), the time of
--           the last prune, a count, and the locks; never evicted
--
-- A call holds its client's lock while it reads and writes that client's
-- track, and the blocks lock while it changes the block table. Calls keep
-- their working state in a local context, never on the shield: a call can
-- wait for a lock, and another request in the same worker runs meanwhile.

local client_check = require "resty.artex_shield.client_check"
local config = require "resty.artex_shield.config"
local crypto = require "resty.artex_shield.crypto"
local ip = require "resty.artex_shield.ip"
local py = require "resty.artex_shield.py"
local signatures = require "resty.artex_shield.signatures"
local track_ = require "resty.artex_shield.track"
local util = require "resty.artex_shield.util"

local sub, find, gsub, format, concat, sort = string.sub, string.find, string.gsub, string.format, table.concat,
    table.sort
local floor, ceil, max, min, sqrt, log = math.floor, math.ceil, math.max, math.min, math.sqrt, math.log
local insert, remove = table.insert, table.remove
local push, score_of = track_.push, track_.score

local MISSING_MEMORY = 128
local LOCK_TTL, LOCK_WAIT = 2, 1          -- seconds a lock lives, and the longest a call waits for one
local BLOCK_GRACE = 3600                  -- an expired block's entry is kept this long for pruning to find

local _M = {}
local Shield = {}
Shield.__index = Shield

local function dict(d, default)
    if type(d) == "table" then
        return d
    end
    local shared = ngx.shared[d or default]
    if not shared then
        error("lua_shared_dict " .. (d or default) .. " is not defined", 0)
    end
    return shared
end

-- ---- locks --------------------------------------------------------------------------
local function can_sleep()
    local phase = ngx.get_phase()
    return phase == "rewrite" or phase == "access" or phase == "content" or phase == "timer"
        or phase == "ssl_cert" or phase == "ssl_session_fetch" or phase == "precontent"
end

-- Take lock `name` for this call. If it cannot be had (a full dict, or a
-- phase that cannot wait), go on without it: no lock rather than no answer.
local function lock(self, cx, name)
    if cx.held[name] then
        return
    end
    local d, wait, waited = self.bdict, 0.0005, 0
    while true do
        local ok, err = d:safe_add("l:" .. name, true, LOCK_TTL)
        if ok then
            cx.held[name] = true
            return
        end
        if err ~= "exists" or waited >= LOCK_WAIT or not can_sleep() then
            ngx.log(ngx.WARN, "artex-shield: going on without lock ", name, ": ", err)
            return
        end
        ngx.sleep(wait)
        waited = waited + wait
        wait = min(wait * 2, 0.01)
    end
end

local function unlock(self, cx, name)
    if cx.held[name] then
        cx.held[name] = nil
        self.bdict:delete("l:" .. name)
    end
end

-- ---- construction -------------------------------------------------------------------
-- options: settings (config.lua); opts.tracks / opts.blocks: lua_shared_dict
-- names or dict objects (default "artex_shield" and "artex_shield_blocks");
-- opts.clock: a function returning Unix seconds (default ngx.now).
function _M.new(options, opts)
    opts = opts or {}
    local cfg = config.make(options)
    local self = setmetatable({cfg = cfg}, Shield)
    self.clock = opts.clock or ngx.now
    self.tdict = dict(opts.tracks, "artex_shield")
    self.bdict = dict(opts.blocks, "artex_shield_blocks")
    self.blocks_name = type(opts.blocks) == "string" and opts.blocks or "artex_shield_blocks"
    self.trusted = assert(ip.networks(cfg.trusted_proxies))
    self.allowed = assert(ip.networks(cfg.allow_cidrs))
    self.canaries = {}
    for _, p in ipairs(cfg.canary_paths) do
        self.canaries[util.norm_path(tostring(p))] = true
    end
    self.tls_deny = {}
    for _, v in ipairs(cfg.tls_denylist) do
        self.tls_deny[py.lower(tostring(v))] = true
    end
    self.enum_skip_ext = {}
    for _, e in ipairs(cfg.enum_ignore_extensions) do
        self.enum_skip_ext[(gsub(py.lower(tostring(e)), "^%.+", ""))] = true
    end
    local secret = cfg.client_check_secret
    if secret and secret ~= "" then
        self.check_key = secret
    else
        -- the reference makes one per process; here every worker must agree
        self.bdict:safe_add("ck", crypto.random(32))
        self.check_key = self.bdict:get("ck") or crypto.random(32)
    end
    self.check_path = util.prefixes({cfg.client_check_path}, "client_check_path")[1]
    self.history = max(cfg.rate_limit, cfg.cadence_samples)
    self.track_ttl = max(7 * 86400, 2 * cfg.max_block_ttl, 2 * cfg.client_check_ttl)
    self.stats = {requests = 0, throttled = 0, blocked = 0, friendly = 0, unidentified = 0, refused = 0}
    self.sig = signatures.get()
    self.bdict:safe_add("bp", self.clock())    -- a new table is stamped as pruned now, as the reference does
    return self
end

function Shield:now()
    return self.clock()
end

-- ---- client address -----------------------------------------------------------------
-- X-Forwarded-For is believed only from a trusted proxy.
function Shield:client_ip(remote_addr, forwarded_for)
    local remote = py.strip(remote_addr or "")
    if remote == "" then
        remote = "0.0.0.0"
    end
    if forwarded_for and forwarded_for ~= "" and ip.in_nets(remote, self.trusted) then
        local hops = {}
        for hop in (forwarded_for .. ","):gmatch("([^,]*),") do
            hop = py.strip(hop)
            if hop ~= "" then
                hops[#hops + 1] = hop
            end
        end
        for k = #hops, 1, -1 do
            local addr = ip.hop_ip(hops[k])
            if not addr then
                break
            end
            if not ip.in_nets(addr, self.trusted) then
                return addr
            end
        end
    end
    return remote
end

function Shield:identified(addr)
    return ip.usable(addr) and not ip.in_nets(addr, self.trusted)
end

function Shield:trusted_peer(addr)
    return ip.in_nets(addr, self.trusted)
end

-- ---- per-call context and state --------------------------------------------------------
local function begin(self, key)
    local cx = {tracks = {}, dirty = {}, held = {}}
    lock(self, cx, "t:" .. key)
    cx.key = key
    return cx
end

local function existing(self, cx, key)
    local t = cx.tracks[key]
    if t == nil then
        local raw = self.tdict:get("t:" .. key)
        t = raw and track_.decode(raw) or false
        cx.tracks[key] = t
    end
    return t or nil
end

local function track(self, cx, key, now)
    local t = existing(self, cx, key)
    if not t then
        t = track_.new(now)
        cx.tracks[key] = t
    end
    cx.dirty[key] = true
    return t
end

-- Write back what this call changed and let go of its locks.
local function finish(self, cx)
    local now = self:now()
    for key in pairs(cx.dirty) do
        local t = cx.tracks[key]
        if t then
            local ok, err = self.tdict:set("t:" .. key, track_.encode(t, now, self.cfg.rate_window,
                self.cfg.cadence_samples), self.track_ttl)
            if not ok then
                ngx.log(ngx.ERR, "artex-shield: cannot keep the track of ", key, ": ", err)
            end
        end
    end
    unlock(self, cx, "blocks")
    if cx.key then
        unlock(self, cx, "t:" .. cx.key)
    end
end

-- Run fn(self, cx, ...) under client key's lock; write back whatever happens.
local function with_client(self, key, fn, ...)
    local cx = begin(self, key)
    local ok, a, b = pcall(fn, self, cx, ...)
    finish(self, cx)
    if not ok then
        error(a, 0)
    end
    return a, b
end

-- ---- the block table ------------------------------------------------------------------
local function block_until(self, k)
    return self.bdict:get("b:" .. k)
end

local prune_blocks

local function set_block(self, cx, k, expiry, now)
    lock(self, cx, "blocks")
    local d = self.bdict
    local existed = d:get("b:" .. k) ~= nil
    local seq = d:incr("bs", 1, 0) % 4294967296
    local ok, err = d:safe_set("b:" .. k, expiry, max(expiry - now, 0) + BLOCK_GRACE, seq)
    if not ok and err == "no memory" then
        ngx.log(ngx.WARN, "artex-shield: the blocks dict is full before max_blocks; dropping the blocks nearest ",
            "their end to make room (make lua_shared_dict ", self.blocks_name, " bigger)")
        prune_blocks(self, cx, now, true)
        existed = d:get("b:" .. k) ~= nil
        ok, err = d:safe_set("b:" .. k, expiry, max(expiry - now, 0) + BLOCK_GRACE, seq)
    end
    if not ok then
        ngx.log(ngx.ERR, "artex-shield: cannot block ", k, ": ", err)
        return
    end
    if not existed then
        d:incr("bn", 1, 0)
    end
end

local function drop_block(self, cx, k)
    lock(self, cx, "blocks")
    local d = self.bdict
    if d:get("b:" .. k) == nil then
        return false
    end
    d:delete("b:" .. k)
    d:incr("bn", -1, 0)
    return true
end

local function covering(key)
    local keys = {key}
    if find(key, ":", 1, true) then
        local k = ip.wider(key)
        while k do
            keys[#keys + 1] = k
            k = ip.wider(k)
        end
    end
    return keys
end

local function blocked(self, cx, key, now)
    for _, k in ipairs(covering(key)) do
        local expiry = block_until(self, k)
        if expiry then
            if expiry > now then
                return true
            end
            lock(self, cx, "blocks")                -- expired: drop it, unless it was renewed meanwhile
            local current = block_until(self, k)
            if current and current <= now then
                drop_block(self, cx, k)
            elseif current then
                return true
            end
        end
    end
    return false
end

prune_blocks = function(self, cx, now, room)
    lock(self, cx, "blocks")
    local d, cfg = self.bdict, self.cfg
    d:set("bp", now)
    local live = {}
    for _, name in ipairs(d:get_keys(0)) do
        if sub(name, 1, 2) == "b:" then
            local expiry, seq = d:get(name)
            if expiry then
                if expiry <= now then
                    d:delete(name)
                else
                    live[#live + 1] = {name, expiry, seq or 0}
                end
            end
        end
    end
    local count = #live
    local over = count - cfg.max_blocks + 1
    local drop = over > 0 and max(over, floor(cfg.max_blocks / 10)) or 0
    if room then
        drop = max(drop, 1, floor(count / 10))      -- the dict filled up before max_blocks: a tenth of what is there
    end
    drop = min(count, drop)
    if drop > 0 then
        sort(live, function(a, b)                   -- nearest to expiry first; ties in the order they were set
            if a[2] ~= b[2] then
                return a[2] < b[2]
            end
            return a[3] < b[3]
        end)
        for k = 1, drop do
            d:delete(live[k][1])
        end
        count = count - drop
    end
    d:set("bn", count)
end

local function members(self, parent)
    local n = 0
    for _, child in ipairs(ip.children(parent)) do
        if block_until(self, child) ~= nil then
            n = n + 1
        end
    end
    return n
end

local emit

local function escalate(self, cx, key, now)
    local cfg = self.cfg
    local need = cfg.v6_escalate_after
    local parent = ip.wider(key)
    while need > 0 and parent and members(self, parent) >= need do
        for _, child in ipairs(ip.children(parent)) do
            drop_block(self, cx, child)
        end
        set_block(self, cx, parent, now + cfg.block_ttl, now)
        emit(self, "block", parent, cfg.block_score, {"behavior:network-rotation"}, "-", "-", "", "-",
            cfg.mode == "enforce")
        parent = ip.wider(parent)
    end
end

local function block(self, cx, t, key, now)
    local cfg = self.cfg
    t.strikes = t.strikes + 1
    self.stats.blocked = self.stats.blocked + 1
    local ttl = min(cfg.block_ttl * 2 ^ (t.strikes - 1), cfg.max_block_ttl)
    lock(self, cx, "blocks")
    if now - (self.bdict:get("bp") or 0) >= 60 or (self.bdict:get("bn") or 0) >= cfg.max_blocks then
        prune_blocks(self, cx, now)
    end
    set_block(self, cx, key, now + ttl, now)
    t.hard, t.soft_points, t.throttled_until, t.not_found = 0, 0, 0, {}
    escalate(self, cx, key, now)
end

-- ---- scoring helpers -------------------------------------------------------------------
local function decay(self, t, now)
    local dt = now - t.updated
    if dt > 0 then
        local factor = 0.5 ^ (dt / self.cfg.half_life)
        t.hard = t.hard * factor
        t.soft_points = t.soft_points * factor
        if score_of(t) < 0.5 then
            t.hard, t.soft_points = 0, 0
        end
    end
    t.updated = now
end

local function soft_due(self, t, label, now)
    local last = t.soft[label]
    if last and now - last < self.cfg.half_life then
        return false
    end
    t.soft[label] = now
    return true
end

local function add(self, t, hits)
    for _, x in ipairs(hits) do
        if x[3] then
            t.soft_points = min(self.cfg.soft_cap, t.soft_points + x[2])
        else
            t.hard = t.hard + x[2]
        end
    end
end

local function labels_of(hits, hard_only)
    local out = {}
    for _, x in ipairs(hits) do
        if not hard_only or not x[3] then
            out[#out + 1] = x[1]
        end
    end
    return out
end

local function concat_lists(a, b, c)
    local out = {}
    for _, l in ipairs({a, b, c or {}}) do
        for _, x in ipairs(l) do
            out[#out + 1] = x
        end
    end
    return out
end

-- ---- events ----------------------------------------------------------------------------
local log_json

emit = function(self, action, addr, score, labels, method, path, ua, ref, enforced)
    local event = {ts = os.date("!%Y-%m-%dT%H:%M:%S", floor(self:now())) .. "+00:00", action = action,
        enforced = enforced, ip = addr, score = floor(score * 10 + 0.5) / 10, hits = labels, method = method,
        path = py.slice(path, 512), ua = py.slice(ua, 256), ref = ref}
    local hook = self.cfg.on_event
    if hook == nil then
        if not log_json then
            log_json = require("cjson.safe").new()
            log_json.encode_escape_forward_slash(false)
        end
        ngx.log(ngx.WARN, "artex-shield: ", log_json.encode(event))
        return
    end
    local ok, err = pcall(hook, event)
    if not ok then
        ngx.log(ngx.ERR, "artex-shield: on_event failed: ", err)
    end
end

local function decision(action, enforced, score, hits, ref, addr, extra)
    local d = {action = action, enforced = enforced, score = score, hits = hits, ref = ref, ip = addr,
        retry_after = 0, friendly = false, induced = false}
    if extra then
        for k, v in pairs(extra) do
            d[k] = v
        end
    end
    d.stop = enforced and action ~= "pass"
    return d
end

local function new_ref()
    return crypto.hex(crypto.random(4))
end

-- ---- headers -----------------------------------------------------------------------------
-- Lower-case name -> value, and the names in the order they came. headers is
-- a list of {name, value} pairs (in order) or a name -> value table (read in
-- sorted order); a value that is a list is joined with ", ".
local function header_map(headers)
    local h, order = {}, {}
    local function put(name, value)
        name = py.utf8(py.lower(tostring(name)))
        if type(value) == "table" then
            value = concat(value, ", ")
        end
        value = py.utf8(tostring(value))
        if h[name] == nil then
            order[#order + 1] = name
        end
        h[name] = value
    end
    if headers[1] ~= nil then
        for _, pair in ipairs(headers) do
            put(pair[1], pair[2])
        end
    else
        local names = {}
        for name in pairs(headers) do
            names[#names + 1] = name
        end
        sort(names)
        for _, name in ipairs(names) do
            put(name, headers[name])
        end
    end
    return h, order
end

-- ---- honeytokens -----------------------------------------------------------------------------
local BASIC = "^[" .. py.SPACE .. "]*basic[" .. py.SPACE .. "]+([A-Za-z0-9+/_=-]{4,8192})"

local function honeytoken(self, npath, query, h, order, body)
    local tokens = self.cfg.honeytokens
    local function has(text)
        if text == "" then
            return false
        end
        for _, t in ipairs(tokens) do
            if find(text, t, 1, true) then
                return true
            end
        end
        local decoded = util.decode(text)
        if decoded == text then
            return false
        end
        for _, t in ipairs(tokens) do
            if find(decoded, t, 1, true) then
                return true
            end
        end
        return false
    end
    for _, name in ipairs(order) do
        if name ~= "referer" then
            local value = py.slice(h[name], 16384)
            if has(value) then
                return name == "cookie" and "cookie" or "header"
            end
            if name == "authorization" or name == "proxy-authorization" then
                local m = ngx.re.match(value, BASIC, "ijou")
                if m then
                    local b64 = m[1]
                    if find(b64, "[-_]") then
                        b64 = gsub(gsub(b64, "-", "+"), "_", "/")
                    end
                    local raw = py.b64decode(b64 .. "===")
                    if has(py.latin1(raw or "")) then
                        return "header"
                    end
                end
            end
        end
    end
    if has(py.slice(query, 65536)) then
        return "query"
    end
    if has(npath) then
        return "path"
    end
    local limit = self.cfg.honeytoken_body_limit
    if body and body ~= "" and limit > 0 and has(py.latin1(sub(body, 1, limit))) then
        return "body"
    end
    return nil
end

-- ---- sensors -------------------------------------------------------------------------------
local search = signatures.search

local function scan(self, method, npath, query, h, order, ua)
    local cfg, sig = self.cfg, self.sig
    local hits = {}
    if self.canaries[npath] then
        hits[#hits + 1] = {"decoy:canary-path", 100, false}
    elseif search(sig.sensitive_paths, npath) then
        hits[#hits + 1] = {"decoy:sensitive-file-probe", 60, false}
    end
    local hard
    for _, r in ipairs(sig.hard_ua) do
        if search(r[1], ua) then
            hard = r
            break
        end
    end
    if hard then
        hits[#hits + 1] = {hard[3], hard[2], false}
    else
        for _, r in ipairs(sig.soft_ua) do
            if search(r[1], ua) then
                hits[#hits + 1] = {r[3], r[2], true}
            end
        end
        if py.strip(ua) == "" then
            hits[#hits + 1] = {"ua:empty", 20, true}
        end
        if search(sig.browser_ua, ua) and not search(sig.crawler_ua, ua) and (h["accept-language"] or "") == "" then
            hits[#hits + 1] = {"shape:browser-ua-without-browser-headers", 20, true}
        end
    end
    local verb = py.upper(method)
    if sig.odd_methods[verb] or sig.soft_methods[verb] then
        hits[#hits + 1] = {"method:" .. verb, 30, sig.soft_methods[verb] == true}
    end
    local target = util.url_text(npath, query)
    local plain = util.strip_sql_comments(target)
    local found, seen = {}, {}
    for _, list in ipairs({sig.payloads, sig.oob}) do
        for _, r in ipairs(list) do
            if search(r[1], target) or (plain and search(r[1], plain)) then
                found[#found + 1] = r[2]
                seen[r[2]] = true
            end
        end
    end
    local values = {}
    for k, name in ipairs(order) do
        values[k] = h[name]
    end
    local head_blob = util.decode(concat(values, " "))
    for _, r in ipairs(sig.oob) do
        if not seen[r[2]] and search(r[1], head_blob) then
            found[#found + 1] = r[2]
            seen[r[2]] = true
        end
    end
    for _, label in ipairs(found) do
        hits[#hits + 1] = {label, 50, false}
    end
    if cfg.tls_header and next(self.tls_deny) then
        local fp = py.lower(h[py.lower(cfg.tls_header)] or "")
        if fp ~= "" and self.tls_deny[fp] then
            hits[#hits + 1] = {"tls:denylisted-fingerprint", 40, true}
        end
    end
    return hits
end

local function radar(self, t, now, seen)
    local cfg = self.cfg
    local hits = {}
    for _, x in ipairs(seen) do
        if not x[3] or soft_due(self, t, x[1], now) then
            hits[#hits + 1] = x
        end
    end
    local recent = 0
    for _, x in ipairs(t.times) do
        if now - x <= cfg.rate_window then
            recent = recent + 1
        end
    end
    if recent + 1 > cfg.rate_limit then
        hits[#hits + 1] = {"behavior:request-flood", 30, false}
        t.times = {}
    elseif #t.times >= cfg.cadence_samples then
        local seq = {}
        for k = #t.times - cfg.cadence_samples + 1, #t.times do
            seq[#seq + 1] = t.times[k]
        end
        seq[#seq + 1] = now
        local gaps = {}
        for k = 2, #seq do
            gaps[k - 1] = seq[k] - seq[k - 1]
        end
        local count = #gaps
        local mean = py.fsum(gaps) / count
        if cfg.cadence_min_mean <= mean and mean <= cfg.cadence_max_mean then
            local devs, squares = {}, {}
            for k, g in ipairs(gaps) do
                devs[k] = g - mean
                squares[k] = devs[k] * devs[k]
            end
            local ss = py.fsum(squares) - py.fsum(devs) ^ 2 / count
            local cv = sqrt(max(ss, 0) / count) / mean
            if cv <= cfg.cadence_max_cv and soft_due(self, t, "behavior:metronomic-cadence", now) then
                hits[#hits + 1] = {"behavior:metronomic-cadence", 20, true}
            end
        end
    end
    return hits
end

-- ---- client check ------------------------------------------------------------------------------
local function client_request(self, path, h, now)
    local cfg = self.cfg
    if not cfg.client_check or not util.under(path, cfg.client_check_api_prefixes) or not client_check.script_made(h) then
        return nil
    end
    local flags = client_check.verify(self.check_key, client_check.cookie(h["cookie"] or "", cfg.client_check_cookie),
        now, cfg.client_check_ttl)
    return {flags ~= nil, flags or 0}
end

local function client_hits(self, t, now, checked)
    if not checked then
        return {}
    end
    local cfg = self.cfg
    local valid, flags = checked[1], checked[2]
    local hits = {}
    local reported = flags ~= 0 or (t.automation_at ~= nil and now - t.automation_at < cfg.client_check_ttl)
    if reported and soft_due(self, t, "client:automation-reported", now) then
        hits[#hits + 1] = {"client:automation-reported", cfg.client_check_points, true}
    end
    if not valid and t.checked_at == nil and t.page_at ~= nil and now - t.page_at >= cfg.client_check_grace
        and soft_due(self, t, "client:no-check", now) then
        hits[#hits + 1] = {"client:no-check", cfg.client_check_points, true}
    end
    return hits
end

-- ---- fire control --------------------------------------------------------------------------------
local function engage(self, cx, t, key, addr, now, labels, method, path, ua, ref, enforce)
    local cfg = self.cfg
    local score = score_of(t)
    if score >= cfg.block_score then
        block(self, cx, t, key, now)
        emit(self, "block", addr, score, labels, method, path, ua, ref, enforce)
        return decision("block", enforce, score, labels, ref, addr)
    end
    if score >= cfg.throttle_score then
        local wait = max(cfg.retry_after, ceil(cfg.half_life * log(score / cfg.throttle_score, 2)) + 1)
        t.throttled_until = now + wait
        self.stats.throttled = self.stats.throttled + 1
        emit(self, "throttle", addr, score, labels, method, path, ua, ref, enforce)
        return decision("throttle", enforce, score, labels, ref, addr, {retry_after = wait})
    end
    t.throttled_until = 0
    if labels[1] then
        emit(self, "score", addr, score_of(t), labels, method, path, ua, ref, enforce)
    end
    return decision("pass", enforce, score_of(t), labels, ref, addr)
end

-- ---- before the site runs ---------------------------------------------------------------------
local function decide(self, cx, addr, key, method, path, query, headers, body)
    local cfg, sig = self.cfg, self.sig
    local now = self:now()
    local h, order = header_map(headers or {})
    local ua = h["user-agent"] or ""
    local ref = new_ref()
    local enforce = cfg.mode == "enforce"
    local npath = util.norm_path(path)
    local allowed = ip.in_nets(addr, self.allowed)
    local exempt = not allowed and util.under(path, cfg.exempt_paths)
    local induced = not cfg.score_induced and util.induced(h)
    local eref = signatures.capture(sig.assessment_ua, ua)
    local hits = {}

    self.stats.requests = self.stats.requests + 1
    -- An allowlisted address is never scored. Nor is a request for an exempt
    -- path, but a client blocked for what it did elsewhere stays blocked there too.
    if allowed then
        return decision("pass", enforce, 0, {}, ref, addr)
    end
    if exempt then
        if blocked(self, cx, key, now) then
            return decision("block", enforce, cfg.block_score, {"blocklist"}, ref, addr)
        end
        return decision("pass", enforce, 0, {}, ref, addr)
    end
    if not self:identified(addr) then
        self.stats.unidentified = self.stats.unidentified + 1
        local labels = {"config:unidentified-client"}
        local warned = self.tdict:get("unidentified")
        if not warned or now - warned >= cfg.half_life then
            self.tdict:set("unidentified", now, ceil(cfg.half_life) + 60)
            emit(self, "unidentified", addr, 0, labels, method, path, ua, ref, enforce)
        end
        return decision("pass", enforce, 0, labels, ref, addr)
    end
    if eref then
        for _, e in ipairs(cfg.engagements) do
            if e.reference == eref and e.start <= now and now < e["end"] and ip.in_nets(addr, e.nets) then
                self.stats.friendly = self.stats.friendly + 1
                local t = track(self, cx, key, now)
                local label = "iff:engagement=" .. eref
                if soft_due(self, t, "friendly", now) then
                    emit(self, "friendly", addr, 0, {label}, method, path, ua, ref, enforce)
                end
                return decision("pass", enforce, 0, {label}, ref, addr, {friendly = true})
            end
        end
        hits[#hits + 1] = {"artex:unverified-assessment-label", 100, false}
    end
    if enforce and blocked(self, cx, key, now) then
        return decision("block", enforce, cfg.block_score, {"blocklist"}, ref, addr)
    end

    local seen = scan(self, method, npath, query, h, order, ua)
    if cfg.honeytokens[1] then
        local where = honeytoken(self, npath, query, h, order, body)
        if where then
            seen[#seen + 1] = {"decoy:honeytoken-" .. where, max(100, cfg.block_score), false}
        end
    end
    local checked = client_request(self, path, h, now)

    if blocked(self, cx, key, now) then
        local all = concat_lists(hits, seen)
        local labels = concat_lists({"blocklist"}, labels_of(all))
        local loud = labels_of(all, true)[1] ~= nil
        if loud or soft_due(self, track(self, cx, key, now), "blocked", now) then
            emit(self, "blocked", addr, cfg.block_score, labels, method, path, ua, ref, enforce)
        end
        return decision("block", enforce, cfg.block_score, labels, ref, addr)
    end
    if induced then
        local labels = labels_of(concat_lists(hits, seen), true)
        if not labels[1] then
            return decision("pass", enforce, 0, {}, ref, addr, {induced = true})
        end
        self.stats.refused = self.stats.refused + 1
        emit(self, "refuse", addr, 0, labels, method, path, ua, ref, enforce)
        return decision("refuse", enforce, 0, labels, ref, addr, {induced = true})
    end
    local t = track(self, cx, key, now)
    decay(self, t, now)
    hits = concat_lists(hits, radar(self, t, now, seen), client_hits(self, t, now, checked))
    push(t.times, now, self.history)
    if enforce and t.throttled_until > now then
        hits[#hits + 1] = {"behavior:ignored-retry-after", cfg.ignored_throttle_points, false}
    end
    add(self, t, hits)
    return engage(self, cx, t, key, addr, now, labels_of(hits), method, path, ua, ref, enforce)
end

-- Decide on one request. addr: the client address (from client_ip); path:
-- percent-decoded once; query: as sent, without "?"; headers: see
-- header_map; body: the start of the body, read only for honeytokens.
-- Returns a decision: {action, enforced, stop, score, hits, ref, ip,
-- retry_after, friendly, induced}.
function Shield:check(addr, method, path, query, headers, body)
    addr = py.utf8(addr or "")
    return with_client(self, ip.track_key(addr), decide, addr, ip.track_key(addr), py.utf8(method or "GET"),
        py.utf8(path or "/"), py.utf8(query or ""), headers, body)
end

-- ---- after the site answered ------------------------------------------------------------------
local function newly_missing(self, t, npath, now)
    local k = sub(ngx.md5(npath), 1, 16)
    local last
    for i, m in ipairs(t.missing) do
        if m[1] == k then
            last = m[2]
            remove(t.missing, i)
            break
        end
    end
    t.missing[#t.missing + 1] = {k, now}
    while #t.missing > MISSING_MEMORY do
        remove(t.missing, 1)
    end
    return last == nil or now - last > self.cfg.half_life
end

local function client_page(self, cx, addr, key)
    if not self:identified(addr) then
        return
    end
    local t = existing(self, cx, key)
    if t and t.page_at == nil then
        t.page_at = self:now()
        cx.dirty[key] = true
    end
end

local function observed(self, cx, addr, key, path, status, induced, content_type)
    local cfg, sig = self.cfg, self.sig
    if cfg.client_check and not induced and status >= 200 and status < 300 then
        local kind = py.lower(py.strip((content_type .. ";"):match("^([^;]*);")))
        if kind == "text/html" or kind == "application/xhtml+xml" then
            client_page(self, cx, addr, key)
        end
    end
    if status ~= 404 or induced then
        return
    end
    local now = self:now()
    local npath = util.norm_path(path)
    if util.under(path, cfg.exempt_paths) or ip.in_nets(addr, self.allowed) then
        return
    end
    local hits = {}
    if search(sig.recon_paths, npath) then
        hits[#hits + 1] = {"recon:probe-404", 25, false}
    end
    if search(sig.missing_sensitive, npath) and not search(sig.sensitive_paths, npath) then
        hits[#hits + 1] = {"decoy:sensitive-file-probe", 60, false}
    end
    local guess = not util.under(path, cfg.enum_ignore_prefixes) and not self.enum_skip_ext[util.extension(npath)]
    local t = existing(self, cx, key)
    if not t or blocked(self, cx, key, now) then
        return
    end
    decay(self, t, now)
    cx.dirty[key] = true
    if guess and newly_missing(self, t, npath, now) then
        push(t.not_found, now, 512)
        if cfg.slow_enum_budget > 0 then
            local most = max(cfg.slow_enum_budget, 1)
            if #t.slow == most and now - t.slow[1] <= cfg.slow_enum_window then
                hits[#hits + 1] = {"behavior:slow-enumeration", cfg.slow_enum_points, false}
            end
            push(t.slow, now, most)
        end
    end
    while t.not_found[1] and now - t.not_found[1] > cfg.enum_window do
        remove(t.not_found, 1)
    end
    if #t.not_found >= cfg.enum_404_threshold then
        hits[#hits + 1] = {"behavior:path-enumeration", 40, false}
        t.not_found = {}
    end
    if not hits[1] then
        return
    end
    add(self, t, hits)
    local labels = labels_of(hits)
    local score = score_of(t)
    if score >= cfg.block_score then
        block(self, cx, t, key, now)
        emit(self, "block", addr, score, labels, "-", path, "", "-", cfg.mode == "enforce")
    else
        emit(self, "score", addr, score_of(t), labels, "-", path, "", "-", cfg.mode == "enforce")
    end
end

-- Feed back the status (and Content-Type) the site answered with.
function Shield:observe(addr, path, status, induced, content_type)
    addr = py.utf8(addr or "")
    local key = ip.track_key(addr)
    with_client(self, key, observed, addr, key, py.utf8(path or "/"), tonumber(status) or 0, induced == true,
        py.utf8(content_type or ""))
end

-- ---- client check (optional) ----------------------------------------------------------------------
local function check_reply(self, cx, addr, key, query, secure)
    local cfg = self.cfg
    local now = self:now()
    local f = util.params(query)["f"] or ""
    local flags = (py.is_digits(f) and #f < 6) and tonumber(f) % 8 or 0
    if self:identified(addr) then
        local t = track(self, cx, key, now)
        t.checked_at = now
        if flags ~= 0 then
            t.automation_at = now
        end
    end
    local value = client_check.sign(self.check_key, floor(now), flags)
    local attrs = format("Path=/; Max-Age=%d; HttpOnly; SameSite=Lax", cfg.client_check_ttl)
    return {status = 204, headers = {
        {"Set-Cookie", cfg.client_check_cookie .. "=" .. value .. "; " .. attrs .. (secure and "; Secure" or "")},
        {"Cache-Control", "no-store"}, {"Content-Length", "0"}}, body = ""}
end

-- Answer the check script's call: {status = 204, headers = {{name, value}, ...}, body = ""}.
function Shield:client_check_reply(addr, query, headers, secure)
    addr = py.utf8(addr or "")
    local key = ip.track_key(addr)
    return with_client(self, key, check_reply, addr, key, py.utf8(query or ""), secure == true)
end

-- The check script itself, served at client_check_path .. ".js".
function Shield:client_check_asset()
    local body = client_check.script(self.check_path)
    return {status = 200, headers = {{"Content-Type", "text/javascript; charset=utf-8"},
        {"Content-Length", tostring(#body)}, {"Cache-Control", "public, max-age=3600"},
        {"X-Content-Type-Options", "nosniff"}}, body = body}
end

-- "check" or "script" for the client check's own endpoints, when it is on; else nil.
function Shield:client_check_route(path)
    if not self.cfg.client_check then
        return nil
    end
    local npath = util.norm_path(py.utf8(path or "/"))
    if npath == self.check_path then
        return "check"
    end
    return npath == self.check_path .. ".js" and "script" or nil
end

function Shield:client_check_tag()
    return client_check.tag(py.rtrim_bytes(self.cfg.client_check_path, py.SLASH))
end

-- ---- command post ---------------------------------------------------------------------------------
-- Active blocks: network -> expiry (Unix seconds).
function Shield:blocklist()
    local cx = {tracks = {}, dirty = {}, held = {}}
    local ok, out = pcall(function()
        lock(self, cx, "blocks")
        local d, now, out = self.bdict, self:now(), {}
        for _, name in ipairs(d:get_keys(0)) do
            if sub(name, 1, 2) == "b:" then
                local expiry = d:get(name)
                if expiry and expiry <= now then
                    d:delete(name)
                    d:incr("bn", -1, 0)
                elseif expiry then
                    out[sub(name, 3)] = expiry
                end
            end
        end
        return out
    end)
    finish(self, cx)
    if not ok then
        error(out, 0)
    end
    return out
end

-- Lift the block on addr, including a wider IPv6 prefix that covers it.
function Shield:unblock(addr)
    local key = ip.track_key(py.utf8(addr or ""))
    return with_client(self, key, function(_, cx)
        cx.tracks[key], cx.dirty[key] = nil, nil
        self.tdict:delete("t:" .. key)
        local dropped = false
        for _, k in ipairs(covering(key)) do
            dropped = drop_block(self, cx, k) or dropped
        end
        return dropped
    end)
end

_M.Shield = Shield
return _M
