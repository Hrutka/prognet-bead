#!/usr/bin/env python3
import os
import sys

from scapy.all import (
    TCP,
    FieldLenField,
    FieldListField,
    IntField,
    IPOption,
    ShortField,
    get_if_list,
    sniff
)
from scapy.layers.inet import _IPOption_HDR

from ppvr_header import PPVR

labels = []

def get_if():
    ifs=get_if_list()
    iface=None
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break;
    if not iface:
        print("Cannot find eth0 interface")
        exit(1)
    return iface

class IPOption_MRI(IPOption):
    name = "MRI"
    option = 31
    fields_desc = [ _IPOption_HDR,
                    FieldLenField("length", None, fmt="B",
                                  length_of="swids",
                                  adjust=lambda pkt,l:l+4),
                    ShortField("count", 0),
                    FieldListField("swids",
                                   [],
                                   IntField("", 0),
                                   length_from=lambda pkt:pkt.count*4) ]

def handle_pkt(pkt):
    if PPVR in pkt:
        layer = pkt.getlayer(PPVR)
        #print("Packet length sum: %s\tDelta time: \t%s\tThroughput: \t%s\tValue: %s, Label: %s" % (layer.DEBUG_HEADER_pl_sum, layer.DEBUG_HEADER_delta, layer.tp, layer.max_label, layer.label))
        addLabel(layer.label)
    #    hexdump(pkt)
        sys.stdout.flush()

def addLabel(label):
    if len(labels) == 100:
        labels.pop(0)
        labels.append(label)
        print_distribution()
    else:
        labels.append(label)

def print_distribution():
    tmp = labels.copy()
    tmp.sort()
    act = 0
    piece = 0
    line = ""
    for i in range(len(tmp)):
        if act == tmp[i]:
            piece += 1
        else:
            line += str(act) + ": " + str(piece) + ", "
            act = tmp[i]
            piece = 1
    line += str(act) + ": " + str(piece)
    print(line)

def main():
    ifaces = [i for i in os.listdir('/sys/class/net/') if 'eth' in i]
    iface = ifaces[0]
    print("sniffing on %s" % iface)
    sys.stdout.flush()
    sniff(iface = iface,
          prn = lambda x: handle_pkt(x))

if __name__ == '__main__':
    main()
