-- The optional client-side check: a script that reports browser automation, and a signed cookie.

local crypto = require "resty.artex_shield.crypto"
local py = require "resty.artex_shield.py"

local sub, find, gsub, format = string.sub, string.find, string.gsub, string.format
local re_find = ngx.re.find

local _M = {}

_M.FLAGS = 7

-- Must stay identical to client_check._SCRIPT; the vector test compares it with the spec.
_M.SCRIPT = [==[(function () {
  try {
    var w = window, d = document, n = navigator, f = 0, k, keys;
    try { if (w.sessionStorage.getItem("artex_check")) return; w.sessionStorage.setItem("artex_check", "1"); } catch (e) {}
    if (n.webdriver === true) f |= 1;
    if (w.callPhantom || w._phantom || w.__nightmare || w.domAutomation || w.domAutomationController ||
        w.__playwright__binding__ || w.__pwInitScripts) f |= 2;
    var el = d.documentElement;
    if ((el && el.getAttribute("webdriver") !== null) || d.__selenium_unwrapped || d.__webdriver_evaluate ||
        d.__driver_evaluate || d.__webdriver_script_fn) f |= 4;
    try { keys = Object.keys(d); for (k = 0; k < keys.length; k++) { if (keys[k].indexOf("cdc_") >= 0) { f |= 4; break; } } } catch (e) {}
    var url = PATH + "?v=1&f=" + f;
    if (w.fetch) { w.fetch(url, {credentials: "same-origin", cache: "no-store"})["catch"](function () {}); }
    else { var x = new XMLHttpRequest(); x.open("GET", url, true); x.send(); }
  } catch (e) {}
})();
]==]

-- The check script, reporting to path.
function _M.script(path)
    local quoted = py.json_string(path)
    return (gsub(_M.SCRIPT, "PATH", function()
        return quoted
    end))
end

-- The <script> tag for every HTML page; the edge serves path .. ".js".
function _M.tag(path)
    return '<script src="' .. path .. '.js" async></script>'
end

local function mac(key, issued, flags)
    return sub(crypto.b64url(crypto.hmac(key, format("1.%d.%d", issued, flags))), 1, 22)
end

-- Cookie value: version, when issued, what was reported, signature.
function _M.sign(key, issued, flags)
    return format("1.%d.%d.", issued, flags) .. mac(key, issued, flags)
end

-- The flags of a valid, unexpired cookie this key signed; nil otherwise.
function _M.verify(key, value, now, ttl)
    if value == nil or value == "" or py.length(value) > 100 then
        return nil
    end
    local v, issued, flags, sig = value:match("^([^.]*)%.([^.]*)%.([^.]*)%.([^.]*)$")
    if v ~= "1" or not py.is_digits(issued) or not py.is_digits(flags) then
        return nil
    end
    -- Python reads them as integers, leading zeros and all, and signs those.
    issued, flags = gsub(issued, "^0+", ""), gsub(flags, "^0+", "")
    if #issued > 15 or #flags > 15 then
        return nil                                 -- far outside any valid time or flag value
    end
    local i, f = tonumber(issued) or 0, tonumber(flags) or 0
    if not (now - ttl <= i and i <= now + 300) or f > _M.FLAGS then
        return nil
    end
    return crypto.equal(mac(key, i, f), sig) and f or nil
end

-- The value of cookie name in a Cookie header, or nil.
function _M.cookie(header, name)
    for part in (py.slice(header, 16384) .. ";"):gmatch("([^;]*);") do
        local piece = py.strip(part)
        local eq = find(piece, "=", 1, true)
        if eq and sub(piece, 1, eq - 1) == name then
            return py.trim_bytes(py.strip(sub(piece, eq + 1)), py.QUOTE)
        end
    end
    return nil
end

local PAGEISH = [[text/html|application/xhtml|image/|text/css|video/|audio/|font/]]

-- Did a page's script send this request (fetch or XHR)? h: lower-case names.
function _M.script_made(h)
    local mode = py.lower(py.strip(h["sec-fetch-mode"] or ""))
    if mode ~= "" then
        return (mode == "cors" or mode == "same-origin") and py.lower(py.strip(h["sec-fetch-dest"] or "empty")) == "empty"
    end
    if py.lower(py.strip(h["x-requested-with"] or "")) == "xmlhttprequest" then
        return true
    end
    return not re_find(py.lower(h["accept"] or ""), PAGEISH, "jo")
end


return _M
