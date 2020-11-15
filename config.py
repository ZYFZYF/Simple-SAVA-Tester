SERVER_ADDR = '2001:da8:ff:212::41:23'  # 服务器地址
DNS_ADDR = '2400:3200::1'  # 阿里云DNS服务器地址
RANDOM_ADDR = '1234::5678'  # 随便造的地址

HEART_BEAT_PORT = 15000  # 向服务器端发送心跳UDP包的端口
HEART_BEAT_INTERVAL = 10  # 发送心跳的时间间隔
HEART_BEAT_COUNT = 10  # 一次发送心跳包的数量（担心UDP丢包）

ACCESS_CLIENT_LIST_PORT = 15001  # 服务器端供访问当前活跃的client列表的端口

HELLO_PORT = 15002  # 为了与某台机器测试而发送报文的端口
FIRST_UNUSED_PORT = 15003  # 未使用的端口

TEST_REPEAT_COUNT = 100  # 每个测试包发送次数
TEST_TIMEOUT_SECONDS = 20  # 每个测试等待时间
WAIT_SECONDS = 10  # 收发交换等待时间

READY_MESSAGE = 'READY'  # sniff准备好之后的回调，用来告诉对方我准备好了

PING_TARGETS = ['2402:f000:11:210::17',
                '2402:f000:0:404::5']  # Ping的路径

VERBOSE = True  # 是否显示发包时的log