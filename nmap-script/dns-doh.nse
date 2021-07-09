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
variables: t = <target of dns query>
           q = <dns query type>
]]

---
-- @usage
-- nmap <target> --script=doh <DNS server> --script-args query=<query type>,target=<DNS lookup value>
--
-- @output
-- 443/tcp open   https
-- | results of query
--
---

author = {"Rob VandenBrink","rob@coherentsecurity.com"}
license = "Creative Commons https://creativecommons.org/licenses/by-nc-sa/4.0/"
categories = { "discovery" }
portrule = shortport.http

action = function(host,port)
     -- collect the command line arguments
     local query = stdnse.get_script_args('query')
     local target = stdnse.get_script_args('target')

     -- check that both arg values are present and non-zero
     if(query==nil or query == '') then
         return "DNS query operation is not defined (A,AAAA,MX,PTR,TXT etc)"
     end
     if(target==nil or target=='') then
         return "DNS target is not defined (host, domain, IP address etc)"
     end

     -- construct the query string, the path in the DOH HTTPS GET
     local qstring = '/dns-query?name='..target..'&type='..query

     -- define the header value (which defines the output type)
     local options = {header={}}
     options['header']['accept'] = 'application/dns-json'

     -- Get some DOH answers!
     local response = http.get(host.ip, port.number, qstring, options)

     -- convert results to JSON for more legible output
     local stat, resp =json.parse(response.body)

     return resp
end
