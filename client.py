import socket
from util import *
from tqdm import tqdm

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
    skt.sendall(json.dumps({'data': data}).encode())


def recv_control_message(skt):
    return json.loads(skt.recv(1024).decode())['data']


# 与addr进行一系列测试，自己发包，对面收
def send_test_to(skt, dst_addr):
    def recv_ready_signal():
        while recv_control_message(skt) != READY_MESSAGE:
            pass

    print('---------------------------------------------接受空闲端口-----------------------------------------------------')
    dst_port = recv_control_message(skt)
    print(f'prepare to send UDP packet to port {dst_port}')
    print('---------------------------------------------正常包测试------------------------------------------------------')
    # 每次进行伪造包发送时要等待ready信号
    recv_ready_signal()
    send(IPv6(dst=dst_addr) / UDP(sport=SEND_UDP_PORT, dport=dst_port), count=TEST_REPEAT_COUNT, inter=0.01)
    recv_normal_count = recv_control_message(skt)
    print(f'send from {LOCAL_IPv6_ADDR} to {dst_addr} success {recv_normal_count}/{TEST_REPEAT_COUNT}')

    if RUN_IP_SPOOF_TEST:
        print('-------------------------------------------伪造源IP地址测试---------------------------------------------------')
        local_addr = LOCAL_IPv6_ADDR
        forge_addr_list = get_alive_clients() + [local_addr[:-1] + '7', local_addr[:-1] + 'e', '5' + local_addr[1:],
                                                 'e' + local_addr[1:]] + [RANDOM_ADDR] + [
                              SERVER_ADDR]  # TODO 能不能主动发现邻居地址并进行伪造
        send_control_message(skt, len(forge_addr_list))
        for forge_addr in forge_addr_list:
            send_control_message(skt, forge_addr)
            recv_ready_signal()
            send(IPv6(src=forge_addr, dst=dst_addr) / UDP(sport=SEND_UDP_PORT, dport=dst_port) / json.dumps(
                {'data': forge_addr}), count=TEST_REPEAT_COUNT, inter=0.01)
            # print(f'send {TEST_REPEAT_COUNT} packets to {dst_addr} with forged addr {src_addr}')
            receive_count = recv_control_message(skt)
            send_result_to_server(type='IP_in_UDP',
                                  src_ip=LOCAL_IPv6_ADDR,
                                  src_mac=get_local_mac_addr(),
                                  dst_ip=dst_addr,
                                  spoof_ip=forge_addr,
                                  send_normal_num=TEST_REPEAT_COUNT,
                                  recv_normal_num=recv_normal_count,
                                  send_spoof_num=TEST_REPEAT_COUNT,
                                  recv_spoof_num=receive_count)
            print(f'forge {forge_addr} to {dst_addr} success {receive_count}/{TEST_REPEAT_COUNT}')

    if RUN_MAC_SPOOF_TEST:
        print(
            f'------------------------------------------伪造MAC地址测试----------------------------------------------------')
        local_mac = get_local_mac_addr()
        forge_mac_list = [local_mac[:-1] + '7', local_mac[:-1] + 'e', '5' + local_mac[1:], 'e' + local_mac[1:],
                          RANDOM_MAC]
        send_control_message(skt, len(forge_mac_list))
        for forge_mac in forge_mac_list:
            send_control_message(skt, forge_mac)
            recv_ready_signal()
            # print(f'forge mac is {forge_mac}')
            sendp(Ether(src=forge_mac) / IPv6(dst=dst_addr) / UDP(sport=SEND_UDP_PORT, dport=dst_port) / json.dumps(
                {'data': forge_mac}), count=TEST_REPEAT_COUNT, inter=0.01)
            receive_count = recv_control_message(skt)
            send_result_to_server(type='MAC_in_UDP',
                                  src_ip=LOCAL_IPv6_ADDR,
                                  src_mac=get_local_mac_addr(),
                                  dst_ip=dst_addr,
                                  spoof_mac=forge_mac,
                                  send_normal_num=TEST_REPEAT_COUNT,
                                  recv_normal_num=recv_normal_count,
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
            send_control_message(skt, len(path) - 1)
            print(f'in {i} path, we have {len(path) - 1} target to ping')
            for target in path[1:]:
                send_control_message(skt, target)
                recv_ready_signal()
                send(IPv6(src=dst_addr, dst=target) / ICMPv6EchoRequest(), count=TEST_REPEAT_COUNT, inter=0.01)
                receive_count = recv_control_message(skt)
                send_result_to_server(type='IP_in_ICMP',
                                      src_ip=LOCAL_IPv6_ADDR,
                                      src_mac=get_local_mac_addr(),
                                      spoof_ip=dst_addr,
                                      ping_target=target,
                                      path=path,
                                      send_normal_num=TEST_REPEAT_COUNT,
                                      recv_normal_num=recv_normal_count,
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

    print(f'--------------------------------------------正常包测试------------------------------------------------------')
    receive_count = len(sniff(filter=f'src host {src_addr} && dst port {dst_port}', timeout=TEST_TIMEOUT_SECONDS,
                              iface=LOCAL_IPv6_IFACE,
                              count=TEST_REPEAT_COUNT, started_callback=send_ready_signal))
    print(f'receive {receive_count} packets')
    send_control_message(skt, receive_count)

    if RUN_IP_SPOOF_TEST:
        print(f'-----------------------------------------伪造源IP地址测试----------------------------------------------------')
        forge_count = recv_control_message(skt)
        print(f'get forge count = {forge_count}')
        for i in tqdm(range(forge_count)):
            forge_addr = recv_control_message(skt)
            receive_count = len(list(filter(lambda pkt: parse_payload(pkt) == forge_addr,
                                            sniff(filter=f'dst port {dst_port}', iface=LOCAL_IPv6_IFACE,
                                                  timeout=TEST_TIMEOUT_SECONDS,
                                                  count=TEST_REPEAT_COUNT,
                                                  started_callback=send_ready_signal))))
            print(f'receive {receive_count} packets from {forge_addr}')
            send_control_message(skt, receive_count)

    if RUN_MAC_SPOOF_TEST:
        print(
            f'------------------------------------------伪造MAC地址测试----------------------------------------------------')
        forge_count = recv_control_message(skt)
        print(f'get forge count = {forge_count}')
        for i in tqdm(range(forge_count)):
            forge_mac = recv_control_message(skt)
            receive_count = len(list(filter(lambda pkt: parse_payload(pkt) == forge_mac,
                                            sniff(filter=f'dst port {dst_port}', iface=LOCAL_IPv6_IFACE,
                                                  timeout=TEST_TIMEOUT_SECONDS,
                                                  count=TEST_REPEAT_COUNT,
                                                  started_callback=send_ready_signal))))
            print(f'receive {receive_count} packets from {forge_mac}')
            send_control_message(skt, receive_count)

    if RUN_ICMP_SPOOF_TEST:
        print(
            f'------------------------------------------伪造PING测试----------------------------------------------------')
        path_count = recv_control_message(skt)
        print(f'get path count is {path_count}')
        for i in range(path_count):
            ping_num = recv_control_message(skt)
            print(f'{i}: need to ping {ping_num} targets')
            for j in range(ping_num):
                ping_target = recv_control_message(skt)
                receive_count = len(
                    sniff(filter=f'src host {ping_target} && icmp6 && ip6[40] == 129', iface=LOCAL_IPv6_IFACE,
                          timeout=TEST_TIMEOUT_SECONDS,
                          count=TEST_REPEAT_COUNT,
                          started_callback=send_ready_signal))
                send_control_message(skt, receive_count)
                print(f'receive {receive_count} ping reply from {ping_target}')


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
        print(f'start test with {addr}')
        skt = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        skt.connect((addr, MONITOR_TCP_PORT))
        send_test_to(skt, addr)
        receive_test_from(skt, addr)
        skt.close()
        print(f'finish test with {addr}')
        return True

    running_tests = set([SERVER_ADDR] + get_alive_clients())
    print(f'local addr is {LOCAL_IPv6_ADDR}')
    print(f'alive clients are {get_alive_clients()}')
    print(f'running test are {running_tests}')
    while len(running_tests) > 0:
        running_tests = [addr for addr in running_tests if not do_test_with(addr)]
    print(f'finish all tests!')
    monitor_test()


def send_result_to_server(**data):
    print(data)
    send(IPv6(dst=SERVER_ADDR) / UDP(sport=SEND_UDP_PORT, dport=RECEIVE_RESULT_PORT) / json.dumps({'data': data}))


if __name__ == '__main__':
    threading.Thread(target=send_heart_beat).start()
    threading.Thread(target=main).start()
