from netfilterqueue import NetfilterQueue
from scapy.all import *
import urllib3
from



def intercept(packet):
    payload = packet.get_payload()
    print('[+] Packet has arrived: ')
    # print(payload.hex()) # Prints something like: 45000034a5b340003906b73c02142c78ac140a340050b024...
    # print(packet)  # Prints something like: TCP packet, 152 bytes

    spkt = IP(payload)
    #spkt.show()  # prints dissected IP packet

    if spkt.haslayer('Raw'):
        raw = spkt[Raw].load
        print(ord(raw[slice(0, 1)]))
    else:
        xmlrpc_packet = http.HTTP(spkt['IP']['TCP'].payload)
        xmlrpc_packet.show()  # prints dissected IP packet

    packet.accept()


nfqueue = NetfilterQueue()
nfqueue.bind(0, intercept)

try:
    print('[+] Waiting for packets...')
    #nfqueue.run()
    packets = rdpcap('ros.pcapng')
    for p in packets:
        print('='*78)
        xmlrpc_packet = p['IP']['TCP'].payload
        xmlrpc_packet.show()  # prints dissected IP packet
except KeyboardInterrupt:
    print('[?] Shutting down...')
