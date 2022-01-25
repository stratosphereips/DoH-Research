# DoH-Checker
This python script is created to check servers identified by their IP addresses for their DNS over HTTP resolving capabilities.

Since DoH resolvers can be reached in multiple ways, the script is issuing requests in various formats, for domain example.com

## DoH Query formats

There are multiple versions of DoH formats. The DoH RFC [1] defines that DNS can be queried via HTTP GET and HTTP POST requests. Moreover, there is a DNS JSON [2] version of DoH. Each DoH format can be used within HTTP/1 and HTTP/2.

The DoH checker script is checking all previously mentioned formats via both versions of HTTPS in the following way:

### RFC 8484 compliant versions
#### DoH-DNS-GET

```
http:###.###.###.###/dns-query?dns=q80BAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB
accept: application/dns-message

```


#### DoH-DNS-POST

```
http:###.###.###.###/dns-query
accept: application/dns-message
content-type: application/dns-message
content: q80BAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB
```

### DNS JSON compliant version
#### DoH-JSON
```
http:###.###.###.###/dns-query?name=example.com&type=AAAA
accept: application/dns-json
```


## Usage:
```
python3 main.py -f inputfile -j numberOfThreats
```

**Input:**

The script expects a list of IP addresses separated by newline as an input.

**Output:**

CSV with DoH compatible server IP addresses. The columns stand for:

**IP**
: DoH compatible server IP address (IPv6, IPv4)

**jsonH1**
: If the server support DoH-JSON via HTTP/1 (True/False)

**jsonH2**
: If the server support DoH-JSON via HTTP/2 (True/False)

**getH1**
: If the server supports DoH-DNS-GET via HTTP/1 (True/False)

**getH2**
: If the server supports DoH-DNS-GET via HTTP/2 (True/False)

**postH1**
: If the server supports DoH-DNS-POST via HTTP/1 (True/False)

**postH2**
: If the server supports DoH-DNS-POST via HTTP/2 (True/False)

**hostname**
: Reverse DNS name (PTR record)

**ESNIsupport**
: If the server support Encrypted SNI proposed by RFC draft [3] (True/False)

**TLS13support**
: If the server support TLS13 (True/False)


## Example Output:

```
IP,jsonH1,jsonH2,getH1,getH2,postH1,postH2,hostname,ESNIsupport,TLS13support
1.1.1.1,True,True,True,True,True,True,1.1.1.1,False,False
```


## References
[1] Hoffman, P. and McManus P., "DNS Queries over HTTPS (DoH)", RFC 8484, DOI 10.17487/RFC8484, October 2018, <https://www.rfc-editor.org/info/rfc8484>.

[2] Hoffman, P., "Representing DNS Messages in JSON", RFC 8427, DOI 10.17487/RFC8427, July 2018, <https://www.rfc-editor.org/info/rfc8427>.


[3] Rescorla, E. and Kazuho, O. and Sullivan, N. nad Wood, Ch., "TLS Encrypted Client Hello", draft-ietf-tls-esni-13, Internet-Draft, August 2021, <https://datatracker.ietf.org/doc/html/draft-ietf-tls-esni-13>
