import socket
import json
from config import *
from scapy.all import *
from scapy.layers.inet6 import IPv6, UDP, Ether, traceroute6


# 通过IPv6包头拿到本机IPv6地址
def get_local_ipv6_addr():
    return IPv6(dst=SERVER_ADDR).src


# 用traceroute获得到目的地路径
def get_path_to(dst_addr):
    res, _ = traceroute6(dst_addr)
    return [get_local_ipv6_addr()] + [item[1][0] for item in
                                      sorted(res.get_trace()[dst_addr].items(), key=lambda x: x[0])]


# payload是dict
def reply_udp_packet(pkt, payload: dict):
    send(IPv6(dst=pkt[IPv6].src) / UDP(sport=pkt[UDP].dport, dport=pkt[UDP].sport) / json.dumps(payload))


if __name__ == '__main__':
    print(get_local_ipv6_addr())
    print(get_path_to(SERVER_ADDR))
