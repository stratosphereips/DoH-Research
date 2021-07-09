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
-- nmap --script=doh-h2 -p 443 <target>
--
-- @output
-- PORT    STATE SERVICE
-- 443/tcp open  https
-- | doh-h2:
-- |_  body: {"Status":0,"TC":false,"RD":true,"RA":true,"AD":true,"CD":false,"Question":[{"name":"www.example.com","type":1}],"Answer":[{"name":"www.example.com","type":1,"TTL":75396,"data":"93.184.216.34"}]}
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
    local tlsctx = http_tls.new_client_context()

    tlsctx:setVerify(0, 0)
    req = http_request.new_from_uri("https://"..host.ip..":"..port.number.."/dns-query?name=www.example.com&type=A")
    req.ctx = tlsctx
    req.headers:append("accept", "application/dns-json")
    req.headers:upsert("user-agent", "example/client")
    req.version = 2
    if nmap.debugging() > 0 then
        print("Request: ", dump(req))
    end
    local headers, stream = assert(req:go())
    if nmap.debugging() > 0 then
        print("Response: ", dump(headers))
    end
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


