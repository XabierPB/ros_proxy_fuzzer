from netfilterqueue import NetfilterQueue
from scapy.all import *
import urllib3
from io import BytesIO
from http.client import HTTPResponse
import untangle


class BytesIOSocket:
    def __init__(self, content):
        self.handle = BytesIO(content)

    def makefile(self, mode):
        return self.handle


def response_from_bytes(data):
    sock = BytesIOSocket(data)

    http_response = HTTPResponse(sock)
    http_response.begin()

    return urllib3.HTTPResponse.from_httplib(http_response)


def intercept(packet):
    payload = packet.get_payload()
    # print('[+] Packet has arrived: ')
    # print(payload.hex()) # Prints something like: 45000034a5b340003906b73c02142c78ac140a340050b024...
    # print(packet)  # Prints something like: TCP packet, 152 bytes
    spkt = IP(payload)
    if spkt.haslayer('TCP'):
        payload = spkt['IP']['TCP'].payload
        if len(payload) > 0:
            load_bytes = payload.load
            try:
                if load_bytes.startswith(b'HTTP/1.0') or load_bytes.startswith(b'HTTP/1.0'):
                    # TODO Debug to find the fileds of response
                    response = response_from_bytes(load_bytes)
                    print(response.headers)
                    #print(response.data)
                    xml_obj = 
                elif load_bytes.startswith(b'POST'):
                    request = load_bytes.decode().split('\r\n\r\n')
                    request_header = request[0]
                    request_content = request[1]
                    print(request_header)

                    print('-'*78)

            except ValueError:
                pass
    packet.accept()


nfqueue = NetfilterQueue()
nfqueue.bind(0, intercept)

try:
    print('[+] Waiting for packets...')
    nfqueue.run()

except KeyboardInterrupt:
    print('[?] Shutting down...')
except Exception as e:
    print(e)
