-- wrk script: every request a new visitor (a fresh address in X-Forwarded-For),
-- with a browser's headers, so the shield scores each one in full.
--
--   wrk -t1 -c1 -d10s --latency -s tests/nginx/visitors.lua http://127.0.0.1:8599/

local n = 0

request = function()
    n = n + 1
    local ip = string.format("10.%d.%d.%d", math.floor(n / 65536) % 256, math.floor(n / 256) % 256, n % 256)
    return wrk.format("GET", "/products/item-" .. n .. "?ref=home", {
        ["Host"] = "shop.example",
        ["X-Forwarded-For"] = ip,
        ["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0 Safari/537.36",
        ["Accept"] = "text/html,application/xhtml+xml",
        ["Accept-Language"] = "en-GB,en;q=0.9",
        ["Accept-Encoding"] = "gzip, br",
    })
end
