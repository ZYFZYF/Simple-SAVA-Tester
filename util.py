import socket
import json
from config import *
from scapy.all import *
from scapy.layers.inet6 import IPv6, UDP, Ether, traceroute6


# 通过IPv6包头拿到本机IPv6地址
def get_local_ipv6_addr():
    return IPv6(dst=DNS_ADDR).src


def get_local_mac_addr():
    return get_if_hwaddr(conf.iface)


# 用traceroute获得到目的地路径
def get_path_to(dst_addr):
    res, _ = traceroute6(dst_addr)
    return [get_local_ipv6_addr()] + [item[1][0] for item in
                                      sorted(res.get_trace()[dst_addr].items(), key=lambda x: x[0])]


# payload是dict
def reply_udp_packet(pkt, payload: dict):
    send(IPv6(dst=pkt[IPv6].src) / UDP(sport=pkt[UDP].dport, dport=pkt[UDP].sport) / json.dumps(payload))


# 从payload中解析出json数据
def parse_payload(pkt):
    return json.loads(pkt.payload.payload.payload.load)['data']


def get_alive_clients():
    if get_local_ipv6_addr() == SERVER_ADDR:
        return []
    send(IPv6(dst=SERVER_ADDR) / UDP(sport=ACCESS_CLIENT_LIST_PORT, dport=ACCESS_CLIENT_LIST_PORT))
    clients = parse_payload(sniff(filter=f'port {ACCESS_CLIENT_LIST_PORT}', count=1)[0])
    return [client for client in clients if client != get_local_ipv6_addr()]


if __name__ == '__main__':
    print(get_local_ipv6_addr())
    # print(get_path_to(SERVER_ADDR))
    print(get_if_addr6(conf.iface))

    print(get_if_hwaddr(conf.iface))
    print(get_if_raw_addr6(conf.iface))
    print(get_if_raw_hwaddr(conf.iface))
