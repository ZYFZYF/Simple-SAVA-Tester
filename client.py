from scapy.layers.inet6 import Ether

from util import *

conf.verb = 0


def send_heart_beat():
    while True:
        send(IPv6(dst=SERVER_ADDR) / UDP(dport=HEART_BEAT_PORT), count=HEART_BEAT_COUNT)
        time.sleep(HEART_BEAT_INTERVAL)


unused_port = FIRST_UNUSED_PORT


def get_unused_port():
    global unused_port
    unused_port += 1
    return unused_port


# 通过TCP socket进行交互信息
def send_control_message(skt, data):
    send_body = json.dumps({'data': data}).encode()
    skt.sendall(struct.pack('i', len(send_body)))
    skt.sendall(send_body)


def recv_control_message(skt):
    data_len = struct.unpack('i', skt.recv(4))[0]
    data = skt.recv(data_len).decode()
    return json.loads(data)['data']


# 与addr进行一系列测试，自己发包，对面收
def send_test_to(skt, dst_addr):
    def recv_ready_signal():
        while recv_control_message(skt) != READY_MESSAGE:
            pass

    print('---------------------------------------------接受空闲端口-----------------------------------------------------')
    dst_port = recv_control_message(skt)
    print(f'prepare to send UDP packet to port {dst_port}')

    forge_addr_list = get_spoof_ips(dst_addr)
    if RUN_IP_SPOOF_TEST:
        print('-------------------------------------------伪造源IP地址测试---------------------------------------------------')

        send_control_message(skt, forge_addr_list)
        recv_ready_signal()
        start_time = time.time()
        for i in range(TEST_REPEAT_COUNT):
            for forge_addr in forge_addr_list:
                send(IPv6(src=forge_addr, dst=dst_addr) / UDP(sport=SEND_UDP_PORT, dport=dst_port) / json.dumps(
                    {'data': forge_addr}))
        print(
            f'send {TEST_REPEAT_COUNT * len(forge_addr_list)} packets and cost {int(time.time() - start_time)} seconds')
        recv_count_dict = recv_control_message(skt)
        for forge_addr, receive_count in recv_count_dict.items():
            send_result_to_server(ssid=LOCAL_WLAN_SSID,
                                  type='IP_in_UDP',
                                  src_ip=LOCAL_IPv6_ADDR,
                                  src_mac=LOCAL_MAC_ADDR,
                                  dst_ip=dst_addr,
                                  spoof_ip=forge_addr,
                                  send_spoof_num=TEST_REPEAT_COUNT,
                                  recv_spoof_num=receive_count)
            print(f'forge {forge_addr} to {dst_addr} success {receive_count}/{TEST_REPEAT_COUNT}')

    forge_mac_list = get_spoof_macs()
    if RUN_MAC_SPOOF_TEST:
        print(
            f'------------------------------------------伪造MAC地址测试----------------------------------------------------')
        # RANDOM_MAC]
        send_control_message(skt, forge_mac_list)
        recv_ready_signal()
        start_time = time.time()
        for i in range(TEST_REPEAT_COUNT):
            for forge_mac in forge_mac_list:
                sendp(Ether(src=forge_mac) / IPv6(dst=dst_addr) / UDP(sport=SEND_UDP_PORT, dport=dst_port) / json.dumps(
                    {'data': forge_mac}))
        print(
            f'send {TEST_REPEAT_COUNT * len(forge_mac_list)} packets and cost {int(time.time() - start_time)} seconds')
        recv_count_dict = recv_control_message(skt)
        for forge_mac, receive_count in recv_count_dict.items():
            send_result_to_server(ssid=LOCAL_WLAN_SSID,
                                  type='MAC_in_UDP',
                                  src_ip=LOCAL_IPv6_ADDR,
                                  src_mac=LOCAL_MAC_ADDR,
                                  dst_ip=dst_addr,
                                  spoof_mac=forge_mac,
                                  send_spoof_num=TEST_REPEAT_COUNT,
                                  recv_spoof_num=receive_count)
            print(f'forge {forge_mac} to {dst_addr} success {receive_count}/{TEST_REPEAT_COUNT}')

    if RUN_ICMP_SPOOF_TEST:
        print(
            f'------------------------------------------伪造PING测试----------------------------------------------------')
        ping_targets = PING_TARGETS + [dst_addr]
        print(f'there are {len(ping_targets)} paths to localize')
        send_control_message(skt, len(ping_targets))
        for i, ping_target in enumerate(ping_targets):
            path = get_path_to(ping_target)
            targets = [target for target in path[1:] if target != dst_addr]
            send_control_message(skt, targets)
            print(f'in {i} path, we have {len(targets)} target to ping')
            recv_ready_signal()
            for j in range(TEST_REPEAT_COUNT):
                for target in targets:
                    send(IPv6(src=dst_addr, dst=target) / ICMPv6EchoRequest())
            recv_count_dict = recv_control_message(skt)
            for target, receive_count in recv_count_dict.items():
                send_result_to_server(ssid=LOCAL_WLAN_SSID,
                                      type='IP_in_ICMP',
                                      src_ip=LOCAL_IPv6_ADDR,
                                      src_mac=LOCAL_MAC_ADDR,
                                      spoof_ip=dst_addr,
                                      ping_target=target,
                                      path=','.join(path),
                                      send_spoof_num=TEST_REPEAT_COUNT,
                                      recv_spoof_num=receive_count)
                print(f'ping target is {target} and success {receive_count}/{TEST_REPEAT_COUNT}')


def receive_test_from(skt, src_addr):
    def send_ready_signal():
        send_control_message(skt, READY_MESSAGE)

    print(f'-------------------------------------------发送空闲端口------------------------------------------------------')
    dst_port = get_unused_port()
    print(f'get a free port {dst_port}')
    send_control_message(skt, dst_port)

    if RUN_IP_SPOOF_TEST:
        print(f'-----------------------------------------伪造源IP地址测试----------------------------------------------------')
        forge_addr_list = recv_control_message(skt)
        print(f'get forge addr list = {forge_addr_list}')
        recv_count_dict = {forge_addr: 0 for forge_addr in forge_addr_list}

        def count_recv_spoof_ip_pkt(pkt):
            forge_addr = parse_payload(pkt)
            if forge_addr in forge_addr_list:
                recv_count_dict[forge_addr] += 1
            else:
                print('Bazinga! Look at what you received!')

        sniff(filter=f'dst port {dst_port}', iface=LOCAL_IPv6_IFACE, timeout=TEST_TIMEOUT_SECONDS,
              started_callback=send_ready_signal, prn=count_recv_spoof_ip_pkt)
        for forge_addr, receive_count in recv_count_dict.items():
            print(f'receive {receive_count} packets from {forge_addr}')
        send_control_message(skt, recv_count_dict)

    if RUN_MAC_SPOOF_TEST:
        print(
            f'------------------------------------------伪造MAC地址测试----------------------------------------------------')
        forge_mac_list = recv_control_message(skt)
        print(f'get forge mac list = {forge_mac_list}')
        recv_count_dict = {forge_mac: 0 for forge_mac in forge_mac_list}

        def count_recv_spoof_mac_pkt(pkt):
            forge_mac = parse_payload(pkt)
            if forge_mac in forge_mac_list:
                recv_count_dict[forge_mac] += 1
            else:
                print('Bazinga! Look at what you received!')

        sniff(filter=f'dst port {dst_port}', iface=LOCAL_IPv6_IFACE, timeout=TEST_TIMEOUT_SECONDS,
              started_callback=send_ready_signal, prn=count_recv_spoof_mac_pkt)
        for forge_mac, receive_count in recv_count_dict.items():
            print(f'receive {receive_count} packets from {forge_mac}')
        send_control_message(skt, recv_count_dict)

    if RUN_ICMP_SPOOF_TEST:
        print(
            f'------------------------------------------伪造PING测试----------------------------------------------------')
        path_count = recv_control_message(skt)
        print(f'get path count is {path_count}')
        for i in range(path_count):
            ping_targets = recv_control_message(skt)
            print(f'{i}: need to ping {ping_targets}')
            recv_count_dict = {target: 0 for target in ping_targets}

            def count_recv_icmp_pkt(pkt):
                if pkt[IPv6].src in recv_count_dict.keys():
                    recv_count_dict[pkt[IPv6].src] += 1

            sniff(filter=f'dst host {LOCAL_IPv6_ADDR} && icmp6 && ip6[40] == 129', iface=LOCAL_IPv6_IFACE,
                  timeout=TEST_TIMEOUT_SECONDS, started_callback=send_ready_signal, prn=count_recv_icmp_pkt)
            for ping_target, receive_count in recv_count_dict.items():
                print(f'receive {receive_count} ping reply from {ping_target}')

            send_control_message(skt, recv_count_dict)


# 监听测试请求
def monitor_test():
    server_socket = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    server_socket.bind((LOCAL_IPv6_ADDR, MONITOR_TCP_PORT))
    server_socket.listen(5)
    print(f'start listening in {MONITOR_TCP_PORT} for test...')
    while True:
        client_socket, client = server_socket.accept()
        print(f'listen {client[0]}:{client[1]} want to test with me... accept')

        # 交互控制信息之后开新线程来具体做测试
        def new_thread_to_test():
            print(f'start test with {client[0]}')
            receive_test_from(client_socket, client[0])
            send_test_to(client_socket, client[0])
            print(f'finish test with {client[0]}')
            client_socket.close()

        threading.Thread(target=new_thread_to_test).start()


def main():
    # 先与对端获得对方的可用端口，再进行收发测试
    def do_test_with(addr):
        try:
            print(f'start test with {addr}')
            skt = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            skt.connect((addr, MONITOR_TCP_PORT))
            send_test_to(skt, addr)
            receive_test_from(skt, addr)
            skt.close()
            print(f'finish test with {addr}')
        except Exception as e:
            print(f'ERROR: {e}')

    running_tests = set([SERVER_ADDR] + get_alive_clients())
    print(f'local addr is {LOCAL_IPv6_ADDR}')
    print(f'alive clients are {get_alive_clients()}')
    print(f'running test are {running_tests}')
    for addr in running_tests:
        do_test_with(addr)
    print(f'finish all tests!')
    monitor_test()


def send_result_to_server(**data):
    send(IPv6(dst=SERVER_ADDR) / UDP(sport=SEND_UDP_PORT, dport=RECEIVE_RESULT_PORT) / json.dumps({'data': data}))


if __name__ == '__main__':
    threading.Thread(target=send_heart_beat).start()
    threading.Thread(target=main).start()
