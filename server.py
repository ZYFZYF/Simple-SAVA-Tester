from ClientManager import ClientManager
from client import monitor_test
from util import *

clientManger = ClientManager()
clientManger.start()


def receive_heart_beat():
    sniff(filter=f'dst host {LOCAL_IPv6_ADDR} && dst port {HEART_BEAT_PORT}', iface=LOCAL_IPv6_IFACE,
          prn=lambda pkt: clientManger.receive_heart_beat(pkt[IPv6].src))


def get_alive_clients():
    sniff(filter=f'dst host {LOCAL_IPv6_ADDR} && dst port {ACCESS_CLIENT_LIST_PORT}', iface=LOCAL_IPv6_IFACE,
          prn=lambda pkt: reply_udp_packet(pkt, {'data': clientManger.get_alive_clients()}))


def receive_result():
    def save_result(pkt):
        data = parse_payload(pkt)
        data['time'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        table_name = data['type']
        del data['type']
        insert_into(table_name, data)

    sniff(filter=f'dst host {LOCAL_IPv6_ADDR} && dst port {RECEIVE_RESULT_PORT}', iface=LOCAL_IPv6_IFACE,
          prn=save_result)


def receive_log():
    server_socket = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    server_socket.bind((LOCAL_IPv6_ADDR, TRANSFER_LOG_FILE_PORT))
    server_socket.listen(5)
    print(f'start listening in {TRANSFER_LOG_FILE_PORT} for collecting results...')
    while True:
        client_socket, client = server_socket.accept()
        print(f'receive log from {client[0]}:{client[1]}')

        # 交互控制信息之后开新线程来具体做测试
        def new_thread_to_test():
            filename = recv_control_message(client_socket)
            line_num = recv_control_message(client_socket)
            os.makedirs(os.path.split(filename)[0], exist_ok=True)
            with open(f'{filename}', 'w', encoding='utf-8') as f:
                for i in range(line_num):
                    content = recv_control_message(client_socket)
                    f.writelines([content])

            client_socket.close()

        threading.Thread(target=new_thread_to_test).start()


if __name__ == '__main__':
    threading.Thread(target=receive_heart_beat).start()
    threading.Thread(target=get_alive_clients).start()
    threading.Thread(target=monitor_test).start()
    threading.Thread(target=receive_result).start()
    threading.Thread(target=receive_log).start()
