from socket import socket
import ssl
import OpenSSL
import csv
import argparse
from datetime import datetime
import whois

def restricted_generalized_time_to_datetime(string):
    if string[-1] != 'Z':
        return ValueError
    if '.' in string:
        if string[-2] == '0':
            raise ValueError
        if string[14] != '.':
            raise ValueError
        return datetime.strptime(string[:-1], '%Y%m%d%H%M%S.%f')
    elif len(string) != 15:
        raise ValueError

    return datetime.strptime(string[:-1], '%Y%m%d%H%M%S')


def getCertInfo(ip):
    try:
        cert = ssl.get_server_certificate((ip, 443))
    except:
        print("Problem with {}", ip)
        return None
    x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
    result = {}
    result["IP"] = ip
    for data in [x509.get_issuer().get_components(),x509.get_subject().get_components()] :
        for i in data:
            result["CRT_" + i[0].decode("latin-1")] = i[1].decode("latin-1")
    whois_dict = whois.whois(result["CRT_" + "CN"].replace("*.", ""))

    result["CRT_" + "NOT_AFTER"] = restricted_generalized_time_to_datetime(x509.get_notAfter().decode("latin-1")).strftime("%Y-%m-%d")
    result["CRT_" + "NOT_BEFORE"] = restricted_generalized_time_to_datetime(x509.get_notBefore().decode("latin-1")).strftime("%Y-%m-%d")
    result["CRT_" + "EXPIRED"] = x509.has_expired()

    for key in whois_dict.keys():
        result["WHOIS_" + key] = whois_dict[key]

    return result



parser = argparse.ArgumentParser(description='Check certificates')
parser.add_argument('-i','--ifile', type=argparse.FileType('r'), help='CSV File with IP addresses', required=True)
parser.add_argument('-o','--ofile', type=argparse.FileType('w'), help='CSV File TLS cert informations', required=True)
args = parser.parse_args()

input_file = csv.DictReader(args.ifile)

fields_set = set()
dict_array = []
for row in input_file:
    certDict = getCertInfo(row["IP"])
    if certDict:
        dict_array.append(certDict)
        for i in certDict.keys():
            fields_set.add(i);
fields = list(fields_set)
fields.sort();
writer = csv.DictWriter(args.ofile, fieldnames=fields)
writer.writeheader()
for i in dict_array:
    writer.writerow(i)


