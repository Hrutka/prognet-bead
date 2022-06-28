#!/usr/bin/env python3
from scapy.all import *

TYPE_PPVR = 0x1212
TYPE_IPV4 = 0x0800

class PPVR(Packet):
    name = "PPVR"
    fields_desc=[
        ShortField("pid", 0),
        ShortField("label", 0),
        ShortField("max_label", 0),
        BitField("tp", 0, 32), # Throughput
        #BitField("DEBUG_HEADER_timestamp_0", 0, 48), # TODO: REMOVE
        #BitField("DEBUG_HEADER_timestamp_1", 0, 48), # TODO: REMOVE
        #BitField("DEBUG_HEADER_timestamp_2", 0, 48), # TODO: REMOVE
        #BitField("DEBUG_HEADER_timestamp_3", 0, 48),  # TODO: REMOVE
        BitField("DEBUG_HEADER_delta", 0, 32),  # TODO: REMOVE
        BitField("DEBUG_HEADER_pl_sum", 0, 32),  # TODO: REMOVE
        #BitField("DEBUG_HEADER_remainder", 0, 32),  # TODO: REMOVE
    ]

bind_layers(Ether, PPVR, type=TYPE_PPVR)
bind_layers(PPVR, IP, pid=TYPE_IPV4)
