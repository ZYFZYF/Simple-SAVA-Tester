from util import *


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
    # addr = '2402:f000:11:210::17'
    addr = '2001:da8:ff:212::41:23'
    a, b = traceroute6(addr)
    print(a.get_trace())
    a.graph(target='>test2.png', ASres=AS_resolver_radb(), type='png')
    w = sorted(a.get_trace()[addr].items(), key=lambda x: x[0])
    print([i[1][0] for i in w])


def test_icmp():
    B = '2001:da8:ff:212::41:23'
    for i in range(100):
        # a = IPv6(src=get_local_ipv6_addr()[:-1] + '1', dst=B) / ICMPv6EchoRequest()
        a = IPv6(src=B, dst='2402:f000:11:210::17') / ICMPv6EchoRequest()
        time.sleep(1)
        send(a)


def test_mac_modify():
    spoof_macs = [LOCAL_MAC_ADDR[:-1] + 'e']
    # LOCAL_MAC_ADDR[:-1] + 'f
    # ]
    # 'a4:83:e7:89:10:1e',
    # '74:83:e7:89:10:1d',
    # 'e4:83:e7:89:10:1d',
    # 'a4:83:e7:89:10:1d']
    for mac in spoof_macs:
        print(mac)
        while True:
            sendp(Ether(src=mac, dst=NEXT_HOP_MAC) / IPv6(dst='2001:da8:ff:212::41:23') / UDP(sport=9876, dport=9877),
                  iface=LOCAL_IPv6_IFACE)
            time.sleep(1)


def test_origin_mac():
    spoof_macs = [LOCAL_MAC_ADDR]
    # LOCAL_MAC_ADDR[:-1] + 'f
    # ]
    # 'a4:83:e7:89:10:1e',
    # '74:83:e7:89:10:1d',
    # 'e4:83:e7:89:10:1d',
    # 'a4:83:e7:89:10:1d']
    for mac in spoof_macs:
        print(mac)
        while True:
            sendp(Ether(src=mac, dst=NEXT_HOP_MAC) / IPv6(dst='2001:da8:ff:212::41:23') / UDP(sport=9876, dport=9877),
                  iface=LOCAL_IPv6_IFACE)
            time.sleep(1)


if __name__ == '__main__':
    # test_send_ethernet()
    # test_send()
    # send(IPv6(src='2402:f000:2:4001:4c0:f05d:b450:b37a', dst='2001:da8:ff:212::41:23') / UDP(sport=12345,
    #                                                                                          dport=9877) / 'Test')
    # test_trace_route()
    # test_icmp()
    test_mac_modify()
    # test_origin_mac()
