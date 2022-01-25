import urllib3
import json
import base64
import ssl
import hyper
import copy
from scapy.all import DNS
import socket
import argparse
import pyasn

from esnicheck.esnicheck.check import ESNICheck

from func_timeout import FunctionTimedOut, func_set_timeout
from joblib import Parallel, delayed

timeout = 60
class dohChecker:
    urllib3.disable_warnings()
    acceptJsonHeader = {"accept": "application/dns-json"}
    acceptDNSHeader = {"accept": "application/dns-message"}
    postHeader = {'content-type': 'application/dns-message', 'accept': 'application/dns-message'}
    dnsQuery = 'q80BAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB'

    def __init__(self):
        self.sslcontext = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
        self.sslcontext.verify_mode = ssl.CERT_NONE
        self.sslcontext.check_hostname = False
        self.dns = DNS();
        # hyper.tls._context = self.sslcontext

    @func_set_timeout(timeout)
    def testJsonH1(self, ip):
        self.sslcontext.set_alpn_protocols(['http/1.1'])
        try:
            conn = hyper.HTTP11Connection(str(ip), port=443, ssl_context=self.sslcontext)
            status = self.__testJson(conn)
            conn.close()
        except (Exception, TimeoutError, FunctionTimedOut):
            status = False
        except AttributeError:
            pass

        return status

    @func_set_timeout(timeout)
    def testJsonH2(self, ip):
        self.sslcontext.set_alpn_protocols(['h2'])
        try:
            conn = hyper.HTTP20Connection(str(ip), port=443, ssl_context=self.sslcontext)
            status = self.__testJson(conn)
            conn.close()
        except (Exception, TimeoutError, FunctionTimedOut):
            status = False
        except AttributeError:
            pass
        return status

    @func_set_timeout(timeout)
    def testGetH1(self, ip):
        self.sslcontext.set_alpn_protocols(['http/1.1'])
        try:
            conn = hyper.HTTP11Connection(str(ip), port=443, ssl_context=self.sslcontext)
            status = self.__testDNSGet(conn)
            conn.close()
        except (Exception, TimeoutError, FunctionTimedOut):
            status = False
        except AttributeError:
            pass
        return status

    @func_set_timeout(timeout)
    def testGetH2(self, ip):
        self.sslcontext.set_alpn_protocols(['h2'])
        try:
            conn = hyper.HTTP20Connection(str(ip), port=443, ssl_context=self.sslcontext)
            status = self.__testDNSGet(conn)
            conn.close()
        except (Exception, TimeoutError, FunctionTimedOut):
            status = False
        except AttributeError:
            pass
        return status

    @func_set_timeout(timeout)
    def testPostH1(self, ip):
        self.sslcontext.set_alpn_protocols(['http/1.1'])
        try:
            conn = hyper.HTTP11Connection(str(ip), port=443, ssl_context=self.sslcontext)
            status = self.__testDNSPost(conn)
            conn.close()
        except (Exception, TimeoutError, FunctionTimedOut):
            status = False
        except AttributeError:
            pass
        return status

    @func_set_timeout(timeout)
    def testPostH2(self, ip):
        self.sslcontext.set_alpn_protocols(['h2'])
        try:
            conn = hyper.HTTP20Connection(str(ip), port=443, ssl_context=self.sslcontext)
            status = self.__testDNSPost(conn, ip)
            conn.close()
        except (Exception, TimeoutError,FunctionTimedOut, ):
            status = False
        except AttributeError:
            pass
        return status

    def __testDNSGet(self, conn):
        conn.request('GET', '/dns-query?dns=' + self.dnsQuery, headers=self.acceptDNSHeader)
        resp = conn.get_response()
        if resp.status == 200:
            if 'Content-Type' in resp.headers:
                ct = resp.headers['content-type'][0]
                if ct == b'application/dns-message':
                    self.dns.dissect(resp.read());
                    return True
        return False

    def __testDNSPost(self, conn, ipin=""):
        postdata = base64.b64decode(self.dnsQuery)
        specHeaders = copy.deepcopy(self.postHeader)
        if ipin != "":
            specHeaders[":authority"] = ipin
            specHeaders[":scheme"] = "https"
            specHeaders["Accept"] = "*/*"
            specHeaders["User-Agent"] = "curl/7.64.1"
            specHeaders["Content-length"] = str(len(postdata))

        conn.request('POST', '/dns-query', body=postdata, headers=specHeaders)
        resp = conn.get_response()
        if resp.status == 200:
            if 'Content-Type' in resp.headers:
                ct = resp.headers['content-type'][0]
                if ct == b'application/dns-message':
                    self.dns.dissect(resp.read());
                    return True
        return False

    def __testJson(self, conn):
        conn.request('GET', '/dns-query?name=example.com&type=AAAA', headers=self.acceptJsonHeader)
        resp = conn.get_response()
        if resp.status == 200:
            if 'Content-Type' in resp.headers:
                ct = resp.headers['content-type'][0]
                #print(ct)
                if ct == b'application/dns-json':
                    dohContent = json.loads(resp.read())
                    if "Question" in dohContent and "Answer" in dohContent:
                        return True
        return False


def checkDoh(ip):
    checker = dohChecker()
    asndb = pyasn.pyasn('ipasn011021.dat')
    try:
        jsonh1status = checker.testJsonH1(ip)
        jsonh2status = checker.testJsonH2(ip)
        geth1status = checker.testGetH1(ip)
        geth2status = checker.testGetH2(ip)
        posth2status = checker.testPostH2(ip)
        posth1status = checker.testPostH1(ip)
    except (FunctionTimedOut):
        return

    if (jsonh1status or jsonh2status or geth2status or geth1status or posth1status or posth2status):
        try:
            url = str(socket.getnameinfo((ip, 0), 0)[0])
        except Exception:
            url = str(None);

        try:
            asn = asndb.lookup(str(ip))[0]
        except Exception:
            asn = str(None);

        try:
            esni = ESNICheck(url)
            hasESNI = str(esni.has_esni())
            hasTLS13 = str(esni.has_tls13()[0])
        except Exception:
            hasESNI = "False";
            hasTLS13 = "False";


        print(str(ip) + "," + str(jsonh1status) + "," + str(jsonh2status) + "," + str(geth1status) + "," + str(
            geth2status) + "," + str(posth1status) + "," + str(posth2status) + "," + str(url) + "," + str(hasESNI) + "," + str(hasTLS13) + "," + str(asn))


"""
Main
"""

parser = argparse.ArgumentParser(description='Check DNS over HTTPS resolvers')
parser.add_argument('-f','--file', type=argparse.FileType('r'), help='File with IP addresses', required=True)
parser.add_argument('-j','--jobs', type=int, help='Number of parallel requests', required=False, default=25)
args = parser.parse_args()

print("IP,jsonH1,jsonH2,getH1,getH2,postH1,postH2,hostname,ESNIsupport,TLS13support, asn")
element_information = Parallel(n_jobs=args.jobs, prefer="threads")(delayed(checkDoh)(line.rstrip("\n")) for line in args.file)
