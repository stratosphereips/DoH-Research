package.path = package.path .. ";/usr/share/lua/5.3/?.lua;/usr/share/lua/5.3/?/init.lua;/usr/lib64/lua/5.3/?.lua;/usr/lib64/lua/5.3/?/init.lua;./?.lua;./?/init.lua"
package.cpath = package.cpath .. ";/usr/lib64/lua/5.3/?.so;/usr/lib64/lua/5.3/loadall.so;./?.so"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local json = require "json"
local strbuf = require "strbuf"
local base64 = require "base64"
local nsedebug = require "nsedebug"

local http_request = require "http.request"
local http_tls = require "http.tls"

description = [[
Performs a DOH lookup against the target site
variables: b = <base64 encoded query string>
]]

---
-- @usage
-- nmap --script=doh-h2-post -p 443 <target>
--
-- @output
-- PORT    STATE SERVICE
-- 443/tcp open  https
-- | doh-h2-post:
-- |   response: { [":status"] = 200,["date"] = Tue, 02 Mar 2021 22:01:29 GMT,["content-type"] = application/dns-message,["content-length"] = 49,["access-control-allow-origin"] = *,["cf-request-id"] = 08968ef5b8000027884c0c7000000001,["expect-ct"] = max-age=604800, report-uri="https://report-uri.cloudflare.com/cdn-cgi/beacon/expect-ct",["server"] = cloudflare,["cf-ray"] = 629de7692a602788-PRG,}
-- |   body: \xAB\xCD\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00\x03www\x07example\x03com\x00\x00\x01\x00\x01\xC0\x0C\x00\x01\x00\x01\x00\x01'Y\x00\x04]\xB8\xD8"
-- |_  request: { ["port"] = 443,["host"] = 1.1.1.1,["version"] = 2,["headers"] = { [":method"] = POST,[":authority"] = 1.1.1.1,[":path"] = /dns-query,[":scheme"] = https,["user-agent"] = example/client,["accept"] = application/dns-message,["content-type"] = application/dns-message,["content-length"] = 33,} ,["body"] = \xAB\xCD\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03www\x07example\x03com\x00\x00\x01\x00\x01,["ctx"] = SSL_CTX*: 0x55b83f623cd8,["tls"] = true,}
--
---

author = {"Tomas Cejka","cejkat@cesnet.cz"}
license = "Creative Commons https://creativecommons.org/licenses/by-nc-sa/4.0/"
categories = { "discovery" }
portrule = shortport.http

function dump(o)
   if type(o) == 'table' then
      local s = '{ '
      for k,v in pairs(o) do
         if type(k) ~= 'number' then k = '"'..k..'"' end
         s = s .. '['..k..'] = ' .. dump(v) .. ','
      end
      return s .. '} '
   else
      return tostring(o)
   end
end


action = function(host,port)
    local output = {}
    local qstring = base64.dec("q80BAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB")

    local tlsctx = http_tls.new_client_context()
    tlsctx:setVerify(0, 0)
    req = http_request.new_from_uri("https://"..host.ip..":"..port.number.."/dns-query")
    req.ctx = tlsctx
    req.headers:upsert(':method', 'POST')
    req.headers:append("accept", "application/dns-message")
    req.headers:upsert("user-agent", "example/client")
    req.headers:upsert('accept', 'application/dns-message')
    req.headers:upsert('content-type', 'application/dns-message')
    req:set_body(qstring)
    req.version = 2
    output["request"] = dump(req)
    if nmap.debugging() > 0 then
       print("Request: ", output["request"])
    end
    local headers, stream = assert(req:go())
    if nmap.debugging() > 0 then
       print("Response: ", dump(headers))
    end
    output["response"] = dump(headers)
    local body = assert(stream:get_body_as_string())
    -- if headers:get ":status" ~= "200" then
    --     error(body)
    -- end
    if nmap.debugging() > 0 then
       print(body)
    end
    output["body"] = body

    return output
end


