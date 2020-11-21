from util import *
from ClientManager import ClientManager
from client import monitor_test

clientManger = ClientManager()
clientManger.start()


def receive_heart_beat():
    sniff(filter=f'dst port {HEART_BEAT_PORT}', prn=lambda pkt: clientManger.receive_heart_beat(pkt[IPv6].src))


def get_alive_clients():
    sniff(filter=f'dst port {ACCESS_CLIENT_LIST_PORT}',
          prn=lambda pkt: reply_udp_packet(pkt, {'data': clientManger.get_alive_clients()}))


if __name__ == '__main__':
    threading.Thread(target=receive_heart_beat).start()
    threading.Thread(target=get_alive_clients).start()
    threading.Thread(target=monitor_test).start()
