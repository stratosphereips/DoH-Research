local nmap = require "nmap"
local shortport = require "shortport"
local http = require "http"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local json = require "json"
local strbuf = require "strbuf"
local base64 = require "base64"

package.path = package.path .. ";/usr/share/lua/5.3/?.lua;/usr/share/lua/5.3/?/init.lua;/usr/lib64/lua/5.3/?.lua;/usr/lib64/lua/5.3/?/init.lua;./?.lua;./?/init.lua"
package.cpath = package.cpath .. ";/usr/lib64/lua/5.3/?.so;/usr/lib64/lua/5.3/loadall.so;./?.so"
local http_request = require "http.request"
local http_tls = require "http.tls"

description = [[
Performs a checking of DoH service against the target host and port
]]

---
-- @usage
-- nmap --script=dns-doh-check -p443 <target>
--
-- @output
-- PORT    STATE SERVICE
-- 443/tcp open  https
-- | dns-doh-check:
-- |   DoH-GET-PARAMS: false
-- |   DoH-BASE64-PARAM: true
-- |_  DoH-POST: false
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

  local results = {}
  local timeout = 2

  -- construct the query string, the path in the DOH HTTPS GET
  local basequery = "q80BAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB"
  -- define the header value (which defines the output type)
  local options = {header={}, timeout=timeout * 1000}
  options['redirect_ok'] = function(host, port)
    local c = 5
    return function(url)
      if ( c==0 ) then return false end
      c = c - 1
      return true
    end
  end

  local query1 = '/dns-query?name=www.example.com&type=A'
  local query2 = '/dns-query?dns='..basequery
  local query3 = '/dns-query'

  -- HTTP checks
  if nmap.debugging() > 0 then
    print("DoH-GET-PARAM checking...")
  end
  local response = http.get(host.ip, port.number, query1, options)
  if response.status == 200 and http.response_contains(response, 'Content%-type: application/dns%-') then
    results["DoH-GET-PARAMS"] = true
  else
    results["DoH-GET-PARAMS"] = false
  end

  if nmap.debugging() > 0 then
    print("DoH-BASE64-PARAM checking...")
  end
  response = http.get(host.ip, port.number, query2, options)
  if response.status == 200 and http.response_contains(response, 'Content%-type: application/dns%-') then
    results["DoH-BASE64-PARAM"] = true
  else
    results["DoH-BASE64-PARAM"] = false
  end

  options['header']['Content-Type'] = 'application/dns-message'
  qstring = base64.dec(basequery)

  if nmap.debugging() > 0 then
    print("DoH-POST checking...")
  end
  response = http.post(host.ip, port.number, query3, options, "", qstring)
  if response.status == 200 and http.response_contains(response, 'Content%-type: application/dns%-') then
    results["DoH-POST"] = true
  else
    results["DoH-POST"] = false
  end

  -- HTTP2 checks
  local target = host.ip..":"..port.number
  local tlsctx = http_tls.new_client_context()

  tlsctx:setVerify(0, 0)
  req = http_request.new_from_uri("https://"..target..query1)
  req.ctx = tlsctx
  req.headers:append("accept", "application/dns-json")
  req.headers:upsert("user-agent", "example/client")
  req.version = 2
  if nmap.debugging() > 0 then
    print("DoH2-GET-PARAMS checking...")
  end
  local headers, stream = req:go(timeout)
  if headers and headers:get(":status") == "200" then
    if headers:get("content-type") == "application/dns-json" then
      results["DoH2-GET-PARAMS"] = true
    else
      if nmap.debugging() > 0 then
        print("Wrong Content-Type = "..headers:get("content-type"))
      end
      results["DoH2-GET-PARAMS"] = false
    end
  else
    results["DoH2-GET-PARAMS"] = false
  end

  req = http_request.new_from_uri("https://"..target..query2)
  req.ctx = tlsctx
  req.headers:append("accept", "application/dns-message")
  req.headers:upsert("user-agent", "example/client")
  req.version = 2
  if nmap.debugging() > 0 then
    print("DoH2-BASE64-PARAMS checking...")
  end
  local headers, stream = req:go(timeout)
  if headers and headers:get(":status") == "200" then
    if headers:get("content-type") == "application/dns-message" then
      results["DoH2-BASE64-PARAMS"] = true
    else
      if nmap.debugging() > 0 then
        print("Wrong Content-Type = "..headers:get("content-type"))
      end
      results["DoH2-BASE64-PARAMS"] = false
    end
  else
    results["DoH2-BASE64-PARAMS"] = false
  end

  req = http_request.new_from_uri("https://"..target..query3)
  req.ctx = tlsctx
  req.headers:upsert(':method', 'POST')
  req.headers:append("accept", "application/dns-message")
  req.headers:upsert("user-agent", "example/client")
  req.headers:upsert('accept', 'application/dns-message')
  req.headers:upsert('content-type', 'application/dns-message')
  req:set_body(qstring)
  req.version = 2
  if nmap.debugging() > 0 then
    print("DoH2-POST checking...")
  end
  headers, stream = req:go(timeout)
  if headers and headers:get(":status") == "200" then
    if headers:get("content-type") == "application/dns-message" then
      results["DoH2-POST"] = true
    else
      if nmap.debugging() > 0 then
        print("Wrong Content-Type = "..headers:get("content-type"))
      end
      results["DoH2-POST"] = false
    end
  else
    results["DoH2-POST"] = false
  end

  return results
end

