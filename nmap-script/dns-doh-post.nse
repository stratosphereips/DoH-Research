local nmap = require "nmap"
local shortport = require "shortport"
local http = require "http"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local json = require "json"
local strbuf = require "strbuf"
local base64 = require "base64"

description = [[
Performs a DOH lookup against the target site
variables: b = <base64 encoded query string>
]]

---
-- @usage
-- nmap --script=dns-doh-post --script-args binquery=<base64 DOH query> <target>
-- nmap --script=dns-doh-post -p 443 --script-args binquery=q80BAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB 8.8.8.8
--
-- @output
-- 443/tcp open   https
-- | results of query
--
---

author = {"Tomas Cejka","cejkat@cesnet.cz"}
license = "Creative Commons https://creativecommons.org/licenses/by-nc-sa/4.0/"
categories = { "discovery" }
portrule = shortport.http

action = function(host,port)
     -- collect the command line arguments
     local query = stdnse.get_script_args('binquery')

     -- check that both arg values are present and non-zero
     if(query==nil or query == '') then
         return "DNS query in base64 required"
     end

     -- construct the query string, the path in the DOH HTTPS GET

     -- define the header value (which defines the output type)
     local options = {header={}}
     options['header']['Accept'] = 'application/dns-message'
     options['header']['Content-Type'] = 'application/dns-message'
     options['redirect_ok'] = function(host, port)
         local c = 5
         return function(url)
            if ( c==0 ) then return false end
            c = c - 1
            return true
         end
     end

     local qstring = base64.dec(query)

     -- Get some DOH answers!
     local response = http.post(host.ip, port.number, "/dns-query", options, "", qstring)

     return response
end

