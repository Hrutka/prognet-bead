from scapy.all import *

TYPE_PPVR = 0x1212
TYPE_IPV4 = 0x0800

class PPVR(Packet):
    name = "PPVR"
    fields_desc=[
        ShortField("pid", 0),
        ShortField("label", 0),
        BitField("tp", 0, 32), # Throughput
        BitField("timestamp_0", 0, 48), # TODO: REMOVE
        BitField("timestamp_1", 0, 48), # TODO: REMOVE
        BitField("timestamp_2", 0, 48), # TODO: REMOVE
        BitField("timestamp_3", 0, 48)  # TODO: REMOVE
    ]

bind_layers(Ether, PPVR, type=TYPE_PPVR)
bind_layers(PPVR, IP, pid=TYPE_IPV4)
