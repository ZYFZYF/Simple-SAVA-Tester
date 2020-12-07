SERVER_ADDR = '2001:da8:ff:212::41:23'  # 服务器地址
DNS_ADDR = '2400:3200::1'  # 阿里云DNS服务器地址
RANDOM_ADDR = '1234::5678'  # 随便造的IPv6地址
RANDOM_MAC = '00:22:33:44:55:66'

HEART_BEAT_PORT = 15000  # 向服务器端发送心跳UDP包的端口
HEART_BEAT_INTERVAL = 10  # 发送心跳的时间间隔
HEART_BEAT_COUNT = 10  # 一次发送心跳包的数量（担心UDP丢包）

ACCESS_CLIENT_LIST_PORT = 15001  # 服务器端供访问当前活跃的client列表的端口

SEND_UDP_PORT = 15002  # 发送UDP报文所用端口
RECEIVE_RESULT_PORT = 15003  # SERVER接受测试结果所用的端口
MONITOR_TCP_PORT = 15004  # client监听该端口来建立TCP连接与其他client交互控制信息
FIRST_UNUSED_PORT = 15005  # 分配给做测试用

TEST_REPEAT_COUNT = 100  # 每个测试包发送次数
TEST_TIMEOUT_SECONDS = 15  # 每个测试等待时间

READY_MESSAGE = 'READY'  # sniff准备好之后的回调，用来告诉对方我准备好了

# PING_TARGETS = ['2402:f000:11:210::17', '2402:f000:0:404::5']  # Ping的路径
PING_TARGETS = []
AVAILABLE_PREFIX = [56, 60, 64]

RUN_IP_SPOOF_TEST = True
RUN_MAC_SPOOF_TEST = True
RUN_ICMP_SPOOF_TEST = True

SAVE_TO_DATABASE = False
