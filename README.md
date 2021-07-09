# DoH Research files and scripts
This repository is related to a reserach on the adoption of Encrypted DNS technologies, in particular DoH.
It has been done by researchers from the Czech Technical University in Prague (FIT[1] and FEL faculties[2]), CESNET[3] and Avast Software[4].

This repository holds:
- A dataset of well-known and verified DoH providers as they are advertised on the Internet. This is the first comprehensive list of DoH providers that include all other lists.
- A dataset on DoH servers around the world found by an Internet scan of their ports and verification with a novel Nmap NSE script. These are mostly still _unknown_ DoH servers that the public is setting up and most are not published yet.

The dataset of well-known DoH providers is in the file ```confirmed-doh-servers-v1.csv```.
Its columsn are: 

    IP: IP address of the DoH server
    H1JSON: If it supports HTTP/1 in JSON format.
    H2JSON: If it supports HTTP/2 in JSON format.
    H1GET: If it supports HTTP/1 with GET method.
    H2GET: If it supports HTTP/2 with GET method.
    H1POST: If it supports HTTP/1 with POST method.
    H2POST: If it supports HTTP/2 with POST method.


The dataset of DoH servers found around the world is in the file ```list-of-doh-servers-internet.txt```. Its columns are:

    IP: IP address of the DoH server
    domain: domain that we assume is related to given our analysis.


The NMAP NSE script can be found in the folder ```nmap-script```.

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

