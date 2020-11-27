import datetime
from util import *
from ClientManager import ClientManager
from client import monitor_test

clientManger = ClientManager()
clientManger.start()


def receive_heart_beat():
    sniff(filter=f'dst port {HEART_BEAT_PORT}', prn=lambda pkt: clientManger.receive_heart_beat(pkt[IPv6].src))


def get_alive_clients():
    sniff(filter=f'dst host {get_local_ipv6_addr()} && dst port {ACCESS_CLIENT_LIST_PORT}',
          prn=lambda pkt: reply_udp_packet(pkt, {'data': clientManger.get_alive_clients()}))


def receive_result():
    def save_result(pkt):
        data = parse_payload(pkt)
        data['time'] = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        table_name = data['type']
        del data['type']
        insert_into(table_name, data)

    sniff(filter=f'dst port {RECEIVE_RESULT_PORT}', prn=save_result)


if __name__ == '__main__':
    threading.Thread(target=receive_heart_beat).start()
    threading.Thread(target=get_alive_clients).start()
    threading.Thread(target=monitor_test).start()
    threading.Thread(target=receive_result).start()
