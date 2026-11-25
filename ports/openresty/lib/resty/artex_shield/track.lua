-- One client's state, as kept in the shared dict between requests. To stay
-- small it holds only what can still change a decision, and it is written in
-- a compact text form: OpenResty's cjson keeps 16 digits, and timestamps need
-- all 17 to come back exactly.

local find, sub, gsub, format, concat = string.find, string.sub, string.gsub, string.format, table.concat
local tonumber = tonumber

local _M = {}

function _M.new(now)
    return {hard = 0, soft_points = 0, updated = now, times = {}, not_found = {}, slow = {},
        missing = {},            -- {{path key, when}, ...}, oldest first (128 kept)
        soft = {},               -- soft label -> when it last counted
        strikes = 0, throttled_until = 0,
        page_at = nil,           -- first HTML page served (client check)
        checked_at = nil,        -- last completed client check
        automation_at = nil}     -- last check that reported automation
end

function _M.score(t)
    return t.hard + t.soft_points
end

-- Append with a length limit, dropping the oldest: deque(maxlen=max).append.
function _M.push(ring, x, max)
    ring[#ring + 1] = x
    if #ring > max then
        table.remove(ring, 1)
    end
end

local function num(x)
    return x == nil and "" or format("%.17g", x)
end

local function nums(list, first)
    local out = {}
    for k = first or 1, #list do
        out[#out + 1] = format("%.17g", list[k])
    end
    return concat(out, ",")
end

local function esc(s)
    return (gsub(s, "[%%|;=,]", function(c)
        return format("%%%02X", c:byte())
    end))
end

local function unesc(s)
    return (gsub(s, "%%(%x%x)", function(h)
        return string.char(tonumber(h, 16))
    end))
end

-- The track as text. Request times older than the rate window and outside
-- the last cadence_samples can change no decision, so they are not kept.
function _M.encode(t, now, rate_window, cadence_samples)
    local times = t.times
    local first, keep = 1, #times - cadence_samples
    while first <= keep and now - times[first] > rate_window do
        first = first + 1
    end
    local missing = {}
    for k, m in ipairs(t.missing) do
        missing[k] = m[1] .. "=" .. format("%.17g", m[2])
    end
    local soft = {}
    for label, when in pairs(t.soft) do
        soft[#soft + 1] = esc(label) .. "=" .. format("%.17g", when)
    end
    return concat({"1", num(t.hard), num(t.soft_points), num(t.updated), num(t.strikes), num(t.throttled_until),
        num(t.page_at), num(t.checked_at), num(t.automation_at), nums(times, first), nums(t.not_found), nums(t.slow),
        concat(missing, ";"), concat(soft, ";")}, "|")
end

local function split(s, sep)
    local out = {}
    if s == "" then
        return out
    end
    local start = 1
    while true do
        local at = find(s, sep, start, true)
        if not at then
            out[#out + 1] = sub(s, start)
            return out
        end
        out[#out + 1] = sub(s, start, at - 1)
        start = at + 1
    end
end

local function list(s)
    local out = split(s, ",")
    for k, v in ipairs(out) do
        out[k] = tonumber(v)
    end
    return out
end

-- A track from encode()'s text, or nil if it is not one.
function _M.decode(text)
    local f = split(text, "|")
    if f[1] ~= "1" or #f ~= 14 then
        return nil
    end
    local t = {hard = tonumber(f[2]), soft_points = tonumber(f[3]), updated = tonumber(f[4]),
        strikes = tonumber(f[5]), throttled_until = tonumber(f[6]), page_at = tonumber(f[7]),
        checked_at = tonumber(f[8]), automation_at = tonumber(f[9]), times = list(f[10]), not_found = list(f[11]),
        slow = list(f[12]), missing = {}, soft = {}}
    for k, pair in ipairs(split(f[13], ";")) do
        local key, when = pair:match("^(.-)=(.*)$")
        t.missing[k] = {key, tonumber(when)}
    end
    for _, pair in ipairs(split(f[14], ";")) do
        local label, when = pair:match("^(.-)=(.*)$")
        t.soft[unesc(label)] = tonumber(when)
    end
    return t
end

return _M
