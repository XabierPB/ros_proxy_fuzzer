from netfilterqueue import NetfilterQueue
from scapy.all import *


def intercept(packet):
    payload = packet.get_payload()
    print('[+] Packet has arrived: ')
    # print(payload.hex()) # Prints something like: 45000034a5b340003906b73c02142c78ac140a340050b024...
    # print(packet)  # Prints something like: TCP packet, 152 bytes

    spkt = IP(payload)
    spkt.show()  # prints dissected IP packet

    if spkt.haslayer('Raw'):
        raw = spkt[Raw].load
        print(ord(raw[slice(0, 1)]))

    packet.accept()


nfqueue = NetfilterQueue()
nfqueue.bind(0, intercept)

try:
    print('[+] Waiting for packets...')
    nfqueue.run()
except KeyboardInterrupt:
    print('[?] Shutting down...')
