from util import *
from tqdm import tqdm

conf.verb = 0
is_running_test = threading.Event()
is_running_test.clear()
is_ready_to_send = threading.Event()
is_ready_to_send.clear()


def send_heart_beat():
    while True:
        send(IPv6(dst=SERVER_ADDR) / UDP(dport=HEART_BEAT_PORT), count=HEART_BEAT_COUNT)
        time.sleep(HEART_BEAT_INTERVAL)


# 与addr进行一系列测试，自己发包，对面收
def send_test_to(dst_addr, src_port=SPOOF_UDP_PORT, dst_port=SPOOF_UDP_PORT):
    def send_control_message(data):
        is_ready_to_send.wait()
        is_ready_to_send.clear()
        send(IPv6(dst=dst_addr) / UDP(sport=dst_port, dport=src_port) / json.dumps({'data': data}))

    def send_ready_signal():
        send(IPv6(dst=dst_addr) / UDP(dport=SNIFF_READY_PORT))

    def receive_control_message():
        return parse_payload(
            sniff(filter=f'src host {dst_addr} && src port {dst_port} && dst port {src_port}', count=1,
                  started_callback=send_ready_signal)[0])

    print('---------------------------------------------正常包测试------------------------------------------------------')
    is_ready_to_send.wait()
    is_ready_to_send.clear()
    send(IPv6(dst=dst_addr) / UDP(sport=src_port, dport=dst_port), count=TEST_REPEAT_COUNT, inter=0.01)
    receive_count = receive_control_message()
    print(f'send from {get_local_ipv6_addr()} to {dst_addr} success {receive_count}/{TEST_REPEAT_COUNT}')

    print('-------------------------------------------伪造源IP地址测试---------------------------------------------------')
    local_addr = get_local_ipv6_addr()
    forge_addr = get_alive_clients() + [local_addr[:-1] + '7', local_addr[:-1] + 'e', '5' + local_addr[1:],
                                        'e' + local_addr[1:]] + [RANDOM_ADDR] + [SERVER_ADDR]  # TODO 能不能主动发现邻居地址并进行伪造
    is_ready_to_send.wait()
    is_ready_to_send.clear()
    send_control_message(len(forge_addr))
    for src_addr in forge_addr:
        is_ready_to_send.wait()
        is_ready_to_send.clear()
        send_control_message(src_addr)
        is_ready_to_send.wait()
        is_ready_to_send.clear()
        send(IPv6(src=src_addr, dst=dst_addr) / UDP(sport=src_port, dport=dst_port), count=TEST_REPEAT_COUNT,
             inter=0.01)
        receive_count = parse_payload(
            sniff(filter=f'src host {dst_addr} && src port {dst_port} && dst port {src_port}', count=1,
                  started_callback=send_ready_signal)[0])
        print(f'forge {src_addr} to {dst_addr} success {receive_count}/{TEST_REPEAT_COUNT}')


# 与addr进行一系列测试，对面收包，自己收
def receive_test_from(src_addr, src_port=SPOOF_UDP_PORT, dst_port=SPOOF_UDP_PORT):
    def send_control_message(data):
        is_ready_to_send.wait()
        is_ready_to_send.clear()
        send(IPv6(dst=src_addr) / UDP(sport=dst_port, dport=src_port) / json.dumps({'data': data}))

    def send_ready_signal():
        send(IPv6(dst=src_addr) / UDP(dport=SNIFF_READY_PORT))

    def receive_control_message():
        return parse_payload(
            sniff(filter=f'src host {src_addr} && src port {src_port} && dst port {dst_port}', count=1,
                  started_callback=send_ready_signal)[0])

    print(f'--------------------------------------------正常包测试------------------------------------------------------')
    receive_count = len(sniff(filter=f'src host {src_addr} && src port {src_port} && dst port {dst_port}',
                              timeout=TEST_TIMEOUT_SECONDS, count=TEST_REPEAT_COUNT,
                              started_callback=send_ready_signal))
    print(f'receive {receive_count} packets')
    send_control_message(receive_count)

    print(f'-----------------------------------------伪造源IP地址测试----------------------------------------------------')
    forge_count = receive_control_message()
    print(f'get forge count = {forge_count}')
    for i in tqdm(range(forge_count)):
        forge_addr = receive_control_message()
        receive_count = len(list(filter(lambda pkt: parse_payload(pkt) == forge_addr,
                                        sniff(filter=f'src port {src_port} && dst port {dst_port}',
                                              timeout=TEST_TIMEOUT_SECONDS,
                                              count=TEST_REPEAT_COUNT, started_callback=send_ready_signal))))
        print(f'receive {receive_count} packets')
        send_control_message(receive_count)


# 监听测试请求
def monitor_test():
    # 收到请求之后先被测，然后再反方向测回去
    def new_port_to_test(pkt):
        if is_running_test.is_set():
            reply_udp_packet(pkt, {'data': 0})
            return
        is_running_test.set()
        reply_udp_packet(pkt, {'data': 1})

        # 交互控制信息之后开新线程来具体做测试
        def new_thread_to_test():
            print(f'start test with {pkt[IPv6].src}')
            receive_test_from(pkt[IPv6].src)
            send_test_to(pkt[IPv6].src)
            print(f'finish test with {pkt[IPv6].src}')
            is_running_test.clear()

        threading.Thread(target=new_thread_to_test).start()

    sniff(filter=f'dst host {get_local_ipv6_addr()} && dst  port {HELLO_PORT}', prn=new_port_to_test)


def main():
    # 先与对端获得对方的可用端口，再进行收发测试
    def do_test_with(addr):
        print(f'start test with {addr}')
        send(IPv6(dst=addr) / UDP(sport=SPOOF_UDP_PORT, dport=HELLO_PORT))
        can_test = parse_payload(sniff(filter=f'port {SPOOF_UDP_PORT}', count=1)[0])
        if can_test == 0:
            print(f'addr {addr} is running test with others...')
            return False
        if is_running_test.is_set():
            print(f'client was tested by others')
            return False
        is_running_test.set()
        send_test_to(addr)
        receive_test_from(addr)
        print(f'finish test with {addr}')
        is_running_test.clear()
        return True

    running_tests = set([SERVER_ADDR] + get_alive_clients())
    print(f'local addr is {get_local_ipv6_addr()}')
    print(f'alive clients are {get_alive_clients()}')
    print(f'running test are {running_tests}')
    while len(running_tests) > 0:
        running_tests = [addr for addr in running_tests if not do_test_with(addr)]


def ready_packet():
    sniff(filter=f'dst host {get_local_ipv6_addr()} && dst port {SNIFF_READY_PORT}',
          prn=lambda pkt: is_ready_to_send.set())


if __name__ == '__main__':
    threading.Thread(target=send_heart_beat).start()
    threading.Thread(target=monitor_test).start()
    threading.Thread(target=main).start()
    threading.Thread(target=ready_packet).start()
