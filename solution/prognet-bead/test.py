#!/usr/bin/env python3
import random
import socket
import sys
import os
import time

from scapy.all import IP, TCP, Ether, get_if_hwaddr, get_if_list, sendp

from ppvr_header import PPVR

def get_if():
    ifs=get_if_list()
    iface=None # "h1-eth0"
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break;
    if not iface:
        print("Cannot find eth0 interface")
        exit(1)
    return iface

def main():
    if len(sys.argv)<4:
        print('pass 3 arguments: <destination> <packet_length> <time_between_packets>')
        exit(1)

    addr = socket.gethostbyname(sys.argv[1])
    iface = get_if()
    packet_length = int(sys.argv[2])

    while True:
        #print "sending on interface %s to %s" % (iface, str(addr))
        pkt =  Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff')
        pkt = pkt / PPVR() / IP(dst=addr) / TCP(dport=1234, sport=random.randint(49152,65535)) / os.urandom(packet_length)
        #pkt.show()
        sendp(pkt, iface=iface, verbose=False)
        time.sleep(int(sys.argv[3]) / 1000.0)

if __name__ == '__main__':
    main()
