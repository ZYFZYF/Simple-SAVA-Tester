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
TRANSFER_LOG_FILE_PORT = 15005  # server监听这个端口来接受client生成的log文件
FIRST_UNUSED_PORT = 15006  # 分配给做测试用

TEST_REPEAT_COUNT = 100  # 每个测试包发送次数
TEST_WAIT_SECONDS = 3  # 每个测试等待时间，从发送完最后一个包到开始统计的时间，所以相对可以较短

READY_MESSAGE = 'READY'  # sniff准备好之后的回调，用来告诉对方我准备好了
FINISH_MESSAGE = 'FINISH'  # 发送数据包之后告诉对面，你可以结束嗅探了

# PING_TARGETS = ['2402:f000:11:210::17', '2402:f000:0:404::5']  # Ping的路径
PING_TARGETS = []
SPOOF_IP_PREFIX_CHOICES = list(reversed(list(range(12, 81, 4)))) + [10]
SPOOF_MAC_PREFIX_CHOICES = list(reversed([2, 4, 6, 8, 10]))
# AVAILABLE_PREFIX = list(range(50, 60))

RUN_IP_SPOOF_TEST = True
RUN_MAC_SPOOF_TEST = True
RUN_ICMP_SPOOF_TEST = False
RUN_TEST_WITH_OTHER_CLIENTS = True

SAVE_TO_DATABASE = True
