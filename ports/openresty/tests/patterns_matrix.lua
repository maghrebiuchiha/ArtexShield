-- Every signature pattern on hostile 30 KB inputs: the same atoms as the
-- reference's Cost tests and the PHP port's. tests/cost.lua runs it under
-- resty; tests/nginx/smoke.conf runs it in nginx behind configure(), with the
-- JIT stack the edge sets, and tests/smoke.py checks the answer.

local signatures = require "resty.artex_shield.signatures"

local _M = {}

_M.ATOMS = {"a", "db", "a-", "a.", "/", " ", "\n", "\r\n ", "; ", ";\n", "/*", "/* a ", "*/", "' or ", "{{ ", " on",
    " onmouse", "#{1", "${T", "../", "..\\", "javascript:", "javascript: ", "<script>", "<script ",
    "' and '1", "' or 1 ", "union select ", "1 union select ", "sleep(", "<iframe ", "<x onclick=",
    "1", "mozilla/5.0 ", "ARTEX-Assessment/1 ", "union ", "union all ",
    "' ", "' or ", "sleep ( ", "; ", "| cat ", "{{1 ", "${ ", "<%= 1", "on", "onload ", "<svg",
    "backup.", "/wp-config.php.a", "/swagger/", "/admin/", "x.oast", "-.", "curl/", "\195\169", "\196\177",
    "\226\128\168"}

function _M.patterns()
    local sig = signatures.get()
    local out = {}
    for _, r in ipairs(sig.hard_ua) do out[#out + 1] = {"HARD_UA " .. r[3], r[1]} end
    for _, r in ipairs(sig.soft_ua) do out[#out + 1] = {"SOFT_UA " .. r[3], r[1]} end
    for _, r in ipairs(sig.payloads) do out[#out + 1] = {r[2], r[1]} end
    for _, r in ipairs(sig.oob) do out[#out + 1] = {r[2], r[1]} end
    for _, name in ipairs({"assessment_ua", "browser_ua", "crawler_ua", "sensitive_paths", "missing_sensitive",
                           "recon_paths"}) do
        out[#out + 1] = {name, sig[name]}
    end
    return out
end

local function seconds(fn)
    ngx.update_time()
    local started = ngx.now()
    fn()
    ngx.update_time()
    return ngx.now() - started
end

-- {slow = {...}, failed = {...}, jit_stack = n, count = patterns}: slow lists
-- searches over budget (best of two), failed the PCRE errors search() cannot
-- get past, jit_stack how many searches ran out of JIT stack (on PCRE2 those
-- are matched again without the JIT and are not failures).
function _M.run(budget)
    local out = {slow = {}, failed = {}, jit_stack = 0}
    local patterns = _M.patterns()
    out.count = #patterns
    for _, p in ipairs(patterns) do
        local name, rx = p[1], p[2]
        for _, atom in ipairs(_M.ATOMS) do
            local text = string.rep(atom, math.floor(30000 / #atom))
            for _, subject in ipairs({text, "/" .. text .. "!"}) do
                local _, _, err = ngx.re.find(subject, rx, "ijou")
                if err then
                    out.jit_stack = out.jit_stack + 1
                    if signatures.is_pcre1() then
                        out.failed[#out.failed + 1] = name .. " on " .. string.format("%q", atom) .. ": " .. err
                    else
                        local _, _, again = ngx.re.find(subject, rx, "iou")
                        if again then
                            out.failed[#out.failed + 1] = name .. " on " .. string.format("%q", atom) .. ": " .. again
                        end
                    end
                end
                if not err or not signatures.is_pcre1() then
                    local took = math.min(seconds(function() signatures.search(rx, subject) end),
                        seconds(function() signatures.search(rx, subject) end))
                    if took >= budget then
                        out.slow[#out.slow + 1] = string.format("%s on %q: %.2f s", name, atom, took)
                    end
                end
            end
        end
    end
    table.sort(out.failed)
    table.sort(out.slow)
    return out
end

return _M
