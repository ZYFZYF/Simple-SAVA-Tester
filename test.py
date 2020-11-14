from scapy.all import *
from scapy.layers.inet6 import IPv6, UDP, Ether, traceroute6
from scapy.as_resolvers import AS_resolver_radb
import time


def test_send_ethernet():
    B = '2001:da8:ff:212::41:23'
    for i in range(100):
        a = Ether(src='aa:bb:cc:dd:ee:dd') / IPv6(dst=B) / UDP(sport=52984, dport=9877) / 'QAQQ'
        time.sleep(1)
        sendp(a)


def test_send():
    B = '2001:da8:ff:212::41:23'
    for i in range(100):
        a = IPv6(src='240c:c0a3:300:fff0:9f00:2675:be5c:f077', dst=B) / UDP(sport=52984, dport=9877) / 'QAQQ'
        time.sleep(1)
        send(a)


def callback(packet):
    packet.show()


def test_recv():
    sniff(filter="host 2001:da8:ff:212::41:23 and udp", count=2, timeout=5, prn=callback)


def test_trace_route():
    a, b = traceroute6('2001:da8:ff:212::41:23')
    print(a.get_trace())
    a.graph(target='>test.png', ASres=AS_resolver_radb(), type='png')
    w = sorted(a.get_trace()['2001:da8:ff:212::41:23'].items(), key=lambda x: x[0])
    print([i[1][0] for i in w])


if __name__ == '__main__':
    # test_send_ethernet()
    test_send()
    # send(IPv6(src='2402:f000:2:4001:4c0:f05d:b450:b37a', dst='2001:da8:ff:212::41:23') / UDP(sport=12345,
    #                                                                                          dport=9877) / 'Test')
    # test_trace_route()
