# DoH Research Scripts for CVUT/CESNET/AVAST DoH Project
This repository is related to a reserach on the adoption of DoH technologies.
It has been done by researchers from the Czech Technical University in Prague (FIT[1] and FEL faculties[2]), CESNET[3] and Avast Software[4].

This repository holds:
- "DoH Internet Servers Dataset.csv": A dataset of well-known and verified DoH providers as they were found in lists on the Internet. This is the first comprehensive list of DoH providers well-known to the community that include all other lists (In April 2021).
- "list-of-doh-servers-internet-April-2021.csv": A dataset on DoH servers found by an Internet scan of their port 443/TCP and a verification with a novel Nmap NSE script. These are mostly still _unknown_ DoH servers for the community that the public is setting up.
- "nmap-script": A folder with our novel Nmap NSE script to scan and verify DoH servers with six different techniques.

The dataset of well-known DoH providers is in the file ```DoH Internet Servers Dataset.csv```. Its columsn are:

    IP Address: IP address of the DoH server
    Domain Name 1: Domain associated with the IP
    Domain Name 2: Domain associated with the IP
    Domain Name 3: Domain associated with the IP
    Domain Name 4: Domain associated with the IP
    ASN: ASN associated with the IP

The dataset of DoH servers found around the world is in the file ```list-of-doh-servers-internet-April-2021.csv```. Its columns are:

    IP: IP address of the DoH server
    HTTP1-JSON: If it supports HTTP/1 in JSON format.
    HTTP2-JSON: If it supports HTTP/2 in JSON format.
    HTTP1-RFC-GET: If it supports HTTP/1 with GET method.
    HTTP2-RFC-GET: If it supports HTTP/2 with GET method.
    HTTP1-RFC-POST: If it supports HTTP/1 with POST method.
    HTTP2-RFC-POST: If it supports HTTP/2 with POST method.
    TLS 1.3 support: If it supports TLS/1.3
    hostname: hostname that we assume is related to the DoH server



The NMAP NSE script can be found in the folder ```nmap-script```.
The python script used for NMAP NSE result validation can be found in the folder ```validation-script```

The authors of this work are:
- Sebastián García, garciseb@fel.cvut.cz
- Karel Hynek, hynekkar@fit.cvut.cz
- Dmtrii Vekshin, dmitrii.vekshin@avast.com
- Tomáš Čejka, cejkat@cesnet.cz
- Armin Wasicek, armin.wasicek@avast.com

[1] https://fit.cvut.cz/
[2] https://fel.cvut.cz/
[3] https://www.cesnet.cz/
[4] https://www.avast.com/
