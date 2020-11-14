import time, threading
from config import *


class ClientManager(threading.Thread):
    def __init__(self):
        super(ClientManager, self).__init__()
        self.last_heart_beat_time = dict()

    def get_alive_clients(self):
        return list(self.last_heart_beat_time.keys())

    def receive_heart_beat(self, addr):
        if addr not in self.last_heart_beat_time.keys():
            print(f'A new client {addr} login..............................')
        self.last_heart_beat_time[addr] = time.time()

    def check_alive_clients(self):
        for addr, last_time in list(self.last_heart_beat_time.items()):
            # 允许一定的误差
            if time.time() - last_time > 1.5 * HEART_BEAT_INTERVAL:
                del self.last_heart_beat_time[addr]
                print(f'Client {addr} is dead..............................')

    def run(self):
        while True:
            self.check_alive_clients()
            time.sleep(HEART_BEAT_INTERVAL)
