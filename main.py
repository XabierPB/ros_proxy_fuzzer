from netfilterqueue import NetfilterQueue
from scapy.all import *
import urllib3
from io import BytesIO
from http.client import HTTPResponse


class BytesIOSocket:
    def __init__(self, content):
        self.handle = BytesIO(content)

    def makefile(self, mode):
        return self.handle


def response_from_bytes(data):
    sock = BytesIOSocket(data)

    response = HTTPResponse(sock)
    response.begin()

    return urllib3.HTTPResponse.from_httplib(response)


def intercept(packet):
    payload = packet.get_payload()
    print('[+] Packet has arrived: ')
    # print(payload.hex()) # Prints something like: 45000034a5b340003906b73c02142c78ac140a340050b024...
    # print(packet)  # Prints something like: TCP packet, 152 bytes

    spkt = IP(payload)
    xmlrpc_packet = spkt['IP']['TCP'].payload



    packet.accept()





nfqueue = NetfilterQueue()
nfqueue.bind(0, intercept)


try:
    print('[+] Waiting for packets...')
    nfqueue.run()


    xmlrpc_packet = p['IP']['TCP'].payload


    response = response_from_bytes(xmlrpc_packet.load)
    print(response.headers)
    print(response.data)


except KeyboardInterrupt:
    print('[?] Shutting down...')
except Exception as e:
    print(e)
