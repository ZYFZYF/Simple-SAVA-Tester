from util import *

unused_port = FIRST_UNUSED_PORT
conf.verb = 0


def get_unused_port():
    global unused_port
    unused_port += 1
    return unused_port


def send_heart_beat():
    while True:
        send(IPv6(dst=SERVER_ADDR) / UDP(dport=HEART_BEAT_PORT), count=HEART_BEAT_COUNT)
        time.sleep(HEART_BEAT_INTERVAL)


# 与addr进行一系列测试，自己发包，对面收
def send_test_to(dst_addr, src_port, dst_port):
    def send_control_message(data):
        time.sleep(WAIT_SECONDS)
        send(IPv6(dst=dst_addr) / UDP(sport=dst_port, dport=src_port) / json.dumps({'data': data}))

    def receive_control_message():
        return parse_payload(
            sniff(filter=f'src host {dst_addr} && src port {dst_port} && dst port {src_port}', count=1)[0])

    # --------------------------------------------------正常包测试--------------------------------------------------------
    time.sleep(WAIT_SECONDS)
    send(IPv6(dst=dst_addr) / UDP(sport=src_port, dport=dst_port), count=TEST_REPEAT_COUNT)
    receive_count = receive_control_message()
    print(f'send from {get_local_ipv6_addr()} to {dst_addr} success {receive_count}/{TEST_REPEAT_COUNT}')

    # ------------------------------------------------伪造源IP地址测试-----------------------------------------------------
    local_addr = get_local_ipv6_addr()
    forge_addr = get_alive_clients() + [local_addr[:-1] + '7', local_addr[:-1] + 'e', '5' + local_addr[1:],
                                        'e' + local_addr[1:]] + [RANDOM_ADDR] + [SERVER_ADDR]  # TODO 能不能主动发现邻居地址并进行伪造
    send_control_message(len(forge_addr))
    for src_addr in forge_addr:
        time.sleep(WAIT_SECONDS)
        send(IPv6(src=src_addr, dst=dst_addr) / UDP(sport=src_port, dport=dst_port), count=TEST_REPEAT_COUNT,
             verbose=VERBOSE)
        receive_count = parse_payload(
            sniff(filter=f'src host {dst_addr} && src port {dst_port} && dst port {src_port}', count=1)[0])
        print(f'forge {src_addr} to {dst_addr} success {receive_count}/{TEST_REPEAT_COUNT}')
    time.sleep(WAIT_SECONDS)


# 与addr进行一系列测试，对面收包，自己收
def receive_test_from(src_addr, src_port, dst_port):
    def send_control_message(data):
        send(IPv6(dst=src_addr) / UDP(sport=dst_port, dport=src_port) / json.dumps({'data': data}))

    def receive_control_message():
        return parse_payload(
            sniff(filter=f'src host {src_addr} && src port {src_port} && dst port {dst_port}', count=1)[0])

    # --------------------------------------------------正常包测试--------------------------------------------------------
    receive_count = len(sniff(filter=f'src host {src_addr} && src port {src_port} && dst port {dst_port}',
                              timeout=TEST_TIMEOUT_SECONDS))
    send_control_message(receive_count)

    # ------------------------------------------------伪造源IP地址测试-----------------------------------------------------
    forge_count = receive_control_message()
    print(f'get forge count = {forge_count}')
    for i in range(forge_count):
        receive_count = len(sniff(filter=f'src port {src_port} && dst port {dst_port}', timeout=TEST_TIMEOUT_SECONDS))
        send_control_message(receive_count)

    print(f'wait for {WAIT_SECONDS} seconds to prepare for transfer...')
    time.sleep(WAIT_SECONDS)


# 监听测试请求
def monitor_test():
    # 收到请求之后先被测，然后再反方向测回去
    def new_port_to_test(pkt):
        dst_port = get_unused_port()
        reply_udp_packet(pkt, {'data': dst_port})

        # 交互控制信息之后开新线程来具体做测试
        def new_thread_to_test():
            print(f'start test with {pkt[IPv6].src}')
            receive_test_from(pkt[IPv6].src, pkt[UDP].sport, dst_port)
            send_test_to(pkt[IPv6].src, dst_port, pkt[UDP].sport)
            print(f'finish test with {pkt[IPv6].src}')

        threading.Thread(target=new_thread_to_test).start()

    sniff(filter=f'dst port {HELLO_PORT}', prn=new_port_to_test)


def main():
    # 先与对端获得对方的可用端口，再进行收发测试
    def do_test_with(addr):
        print(f'start test with {addr}')
        src_port = get_unused_port()
        send(IPv6(dst=addr) / UDP(sport=src_port, dport=HELLO_PORT))
        dst_port = parse_payload(sniff(filter=f'port {unused_port}', count=1)[0])
        send_test_to(addr, src_port, dst_port)
        receive_test_from(dst_addr, dst_port, src_port)
        print(f'finish test with {addr}')

    for dst_addr in [SERVER_ADDR] + get_alive_clients():
        if dst_addr != get_local_ipv6_addr():
            do_test_with(dst_addr)
    # 主动发起测试完成之后就可以开启监听了
    threading.Thread(target=monitor_test).start()


if __name__ == '__main__':
    threading.Thread(target=send_heart_beat).start()
    threading.Thread(target=main).start()
