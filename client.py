import time, threading
from util import *


def send_heart_beat():
    while True:
        send(IPv6(dst=SERVER_ADDR) / UDP(dport=HEART_BEAT_PORT), count=HEART_BEAT_COUNT)
        time.sleep(HEART_BEAT_INTERVAL)


def main():
    # 获得当前活跃的client列表
    send(IPv6(dst=SERVER_ADDR) / UDP(sport=ACCESS_CLIENT_LIST_PORT, dport=ACCESS_CLIENT_LIST_PORT))
    clients = json.loads(sniff(filter=f'port {ACCESS_CLIENT_LIST_PORT}', count=1)[0].payload.payload.payload.load)[
        RETURN_CLIENT_KEY]
    print(f'Now alive clients are {clients}')


if __name__ == '__main__':
    threading.Thread(target=send_heart_beat).start()
    threading.Thread(target=main).start()
