-- The shield's settings from environment variables, named as for
-- artex-shield-proxy. nginx.conf passes them in with `env` lines; the resty
-- command that prints the decoys reads the same ones.
--
--   ARTEX_SHIELD_MODE               monitor (default) or enforce
--   ARTEX_SHIELD_TRUSTED_PROXIES    your load balancer or CDN, CIDRs separated by commas or spaces
--   ARTEX_SHIELD_CANARY_SECRET      a long random string you keep: decides the canary paths
--   ARTEX_SHIELD_HONEYTOKEN_SECRET  another one: decides the fake credentials
--   ARTEX_SHIELD_CLIENT_CHECK       1 to turn on the client check
--   ARTEX_SHIELD_ADMIN_TOKEN        16 characters or more: the admin location then asks for it

local _M = {}

local function list(value)
    local out = {}
    for item in (value or ""):gmatch("[^,%s]+") do
        out[#out + 1] = item
    end
    return out
end

local function set(name)
    local value = os.getenv(name)
    return value and value ~= "" and value or nil
end

function _M.from_env()
    local settings = {
        mode = set("ARTEX_SHIELD_MODE") or "monitor",
        trusted_proxies = list(os.getenv("ARTEX_SHIELD_TRUSTED_PROXIES")),
        canary_secret = set("ARTEX_SHIELD_CANARY_SECRET"),
        honeytoken_secret = set("ARTEX_SHIELD_HONEYTOKEN_SECRET"),
        admin_token = set("ARTEX_SHIELD_ADMIN_TOKEN"),
    }
    local check = set("ARTEX_SHIELD_CLIENT_CHECK")
    if check == "1" or check == "true" or check == "yes" then
        settings.client_check = true
    end
    return settings
end

return _M
