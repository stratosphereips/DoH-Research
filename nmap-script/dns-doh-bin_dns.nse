local nmap = require "nmap"
local shortport = require "shortport"
local http = require "http"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local json = require "json"
local strbuf = require "strbuf"

description = [[
Performs a DOH lookup against the target site
variables: b = <base64 DoH query>
]]

---
-- @usage
-- nmap --script=dns-doh-bin_dns --script-args binquery=<base64 DoH query> <target>
-- nmap --script=dns-doh-bin_dns -p 443 --script-args binquery=q80BAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB 8.8.8.8
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
         return "DNS query operation is not defined (A,AAAA,MX,PTR,TXT etc)"
     end

     -- construct the query string, the path in the DOH HTTPS GET
     local qstring = '/dns-query?dns='..query

     -- define the header value (which defines the output type)
     local options = {header={}}
     options['header']['accept'] = 'application/dns-message'
     options['redirect_ok'] = function(host, port)
         local c = 5
         return function(url)
            if ( c==0 ) then return false end
            c = c - 1
            return true
         end
     end

     -- Get some DOH answers!
     local response = http.get(host.ip, port.number, qstring, options)

     return response
end
