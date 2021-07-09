# dns-doh.nse
NMAP Scripts for DNS over HTTPS

Syntax is nmap -p443 --script dns-doh.nse <dns server ip> --script-args target=`<target>`,query=`<query type>`
  
Full write-up is at https://isc.sans.edu/forums/diary/Fun+with+NMAP+NSE+Scripts+and+DOH+DNS+over+HTTPS/27026/

# HTTP2 support

H2 support is done by lua-http library (doc: https://daurnimator.github.io/lua-http/0.3/).
For Fedora, it can be installed by:

`dnf install lua-http`

Since it is installed into /usr instead of /usr/local, there is an update of `path` and `cpath` in the script.

# DoH modes

## HTTP1

HTTP1 is not recommended but some DoH resolvers support it.

DoH-GET-PARAMS: sends request as GET params `/dns-query?name=www.example.com&type=A`

DoH-BASE64-PARAM: sends request as GET param in base64 encoded DNS request `/dns-query?dns=q80BAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB`

DoH-POST: sends request as POST content to URL `/dns-query`, the body is in DNS wirefire format

## HTTP2

HTTP2 is recommended by DoH standard, the three modes are described in the previous section.

DoH2-BASE64-PARAMS

DoH2-POST

DoH2-GET-PARAMS

# Examples

```
$ nmap -P0 -p443 --script=dns-doh-check 8.8.8.8
Starting Nmap 7.80 ( https://nmap.org ) at 2021-03-02 21:55 CET
Nmap scan report for dns.google (8.8.8.8)
Host is up (0.0039s latency).

PORT    STATE SERVICE
443/tcp open  https
| dns-doh-check: 
|   DoH2-BASE64-PARAMS: true
|   DoH-GET-PARAMS: false
|   DoH-BASE64-PARAM: true
|   DoH2-POST: false
|   DoH-POST: false
|_  DoH2-GET-PARAMS: false

Nmap done: 1 IP address (1 host up) scanned in 1.43 seconds
```

```
$ nmap  --script=doh-h2-bin -p 443 1.1.1.1
Starting Nmap 7.80 ( https://nmap.org ) at 2021-03-02 22:51 CET
Nmap scan report for one.one.one.one (1.1.1.1)
Host is up (0.011s latency).

PORT    STATE SERVICE
443/tcp open  https
| doh-h2-bin:
|_  response: 200

Nmap done: 1 IP address (1 host up) scanned in 0.95 seconds
```

```
$ nmap  --script=doh-h2-post -p 443 1.1.1.1
Starting Nmap 7.80 ( https://nmap.org ) at 2021-03-02 23:01 CET
Nmap scan report for one.one.one.one (1.1.1.1)
Host is up (0.015s latency).

PORT    STATE SERVICE
443/tcp open  https
| doh-h2-post:
|   response: { [":status"] = 200,["date"] = Tue, 02 Mar 2021 22:01:29 GMT,["content-type"] = application/dns-message,["content-length"] = 49,["access-control-allow-origin"] = *,["cf-request-id"] = 08968ef5b8000027884c0c7000000001,["expect-ct"] = max-age=604800, report-uri="https://report-uri.cloudflare.com/cdn-cgi/beacon/expect-ct",["server"] = cloudflare,["cf-ray"] = 629de7692a602788-PRG,}
|   body: \xAB\xCD\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00\x03www\x07example\x03com\x00\x00\x01\x00\x01\xC0\x0C\x00\x01\x00\x01\x00\x01'Y\x00\x04]\xB8\xD8"
|_  request: { ["port"] = 443,["host"] = 1.1.1.1,["version"] = 2,["headers"] = { [":method"] = POST,[":authority"] = 1.1.1.1,[":path"] = /dns-query,[":scheme"] = https,["user-agent"] = example/client,["accept"] = application/dns-message,["content-type"] = application/dns-message,["content-length"] = 33,} ,["body"] = \xAB\xCD\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03www\x07example\x03com\x00\x00\x01\x00\x01,["ctx"] = SSL_CTX*: 0x55b83f623cd8,["tls"] = true,}

Nmap done: 1 IP address (1 host up) scanned in 0.91 seconds
```


```
$ nmap  --script=doh-h2 -p 443 1.1.1.1
Starting Nmap 7.80 ( https://nmap.org ) at 2021-03-02 23:06 CET
Nmap scan report for one.one.one.one (1.1.1.1)
Host is up (0.016s latency).

PORT    STATE SERVICE
443/tcp open  https
| doh-h2:
|_  body: {"Status":0,"TC":false,"RD":true,"RA":true,"AD":true,"CD":false,"Question":[{"name":"www.example.com","type":1}],"Answer":[{"name":"www.example.com","type":1,"TTL":75396,"data":"93.184.216.34"}]}

Nmap done: 1 IP address (1 host up) scanned in 0.64 seconds
```

# Troubleshooting


## nmap is blocked during the scan

Unfortunataly, `cqueues.poll()`, which is called from lua-http (our
dependency), behaves in a strange way when it gets negative timeout. This
causes infinite loop / blocking.

A possible workaround is to modify source code of `/usr/share/lua/5*/h2_stream.lua` - add the following code:

```
    if timeout < 0 then
            return nil, ce.strerror(ce.ETIMEDOUT), ce.ETIMEDOUT
    end
```

inside `function stream_methods:get_headers(timeout)` before
`local which = cqueues.poll(self.recv_headers_cond, self.connection, timeout)`

as it is shown in [./h2_stream.lua.patch](./h2_stream.lua.patch).

