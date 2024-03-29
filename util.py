import ipaddress
import json
from enum import Enum

import psutil
import pymysql
from scapy.all import *
from scapy.layers.inet6 import IPv6, Ether, UDP, traceroute6, ICMPv6EchoRequest

from config import *

# 初始化随机数种子
random.seed(time.time())


class SpoofMacCategory(Enum):
    NO_SPOOF = "不伪造"
    FIX = "固定mac地址"
    FIX_PREFIX = "固定前缀，随机后缀"
    RANDOM = "完全随机"


class SpoofIpCategory(Enum):
    NO_SPOOF = "不伪造"
    FIX = "固定ip地址"
    SRC_OUT_BOUND = "本子网出方向"
    DST_IN_BOUND = "对端子网入方向"
    ACTIVE_CLIENTS = "其他活跃客户端地址"


# 通过IPv6包头拿到本机IPv6地址
def get_local_ipv6_addr():
    return IPv6(dst=DNS_ADDR).src


def get_ipv6_iface():
    for iface, addrs in psutil.net_if_addrs().items():
        for addr in addrs:
            if addr.address == get_local_ipv6_addr():
                return iface


def get_local_mac_addr():
    return get_if_hwaddr(get_ipv6_iface())


def get_running_os():
    system = sys.platform
    if system in ['win32', 'win64']:
        return 'windows'
    if system in ['linux']:
        return system
    if system == 'darwin':
        return 'mac'
    raise Exception(f"Not supported os {system}")


RUNNING_OS = get_running_os()


def get_connected_wifi_ssid():
    if RUNNING_OS == 'mac':
        ret = subprocess.run(
            "/System/Library/PrivateFrameworks/Apple80211.framework/Resources/airport -I  | awk -F' SSID: '  '/ SSID: / {print $2}'",
            shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output = ret.stdout.decode().strip()
        return output
    # TODO 先不管Linux用户
    if RUNNING_OS == 'linux':
        pass
    if RUNNING_OS == 'windows':
        ret = subprocess.run("netsh wlan show interfaces",
                             shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output = re.search(r'SSID(.*?)BSSID', str(ret.stdout), re.M | re.I).group(1)
        return output.replace('\\r', '').replace('\\n', '').replace(':', '').strip()
    return 'UNKNOWN'


# 通过系统ping来获取下一跳也就是网关的mac地址
def get_next_hop_mac():
    def send_system_ping_pkt_thread():
        def send_system_ping_pkt():
            if RUNNING_OS in ['linux', 'mac']:
                cmd = ['ping6', '-c', '3', DNS_ADDR]
            elif RUNNING_OS == 'windows':
                cmd = ['ping', '-6', '-n', '3', DNS_ADDR]
            else:
                raise Exception(f'Not supported OS {RUNNING_OS}')

            while subprocess.check_call(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT) != 0:
                pass
            print('ping packet send finished')

        threading.Thread(target=send_system_ping_pkt).start()

    try:
        system_ping_pkt = sniff(filter=f'icmpv6 && dst host {DNS_ADDR}', count=1, iface=get_ipv6_iface(),
                                started_callback=send_system_ping_pkt_thread)
    except:
        print("can not compile icmpv6, use icmp6")
        system_ping_pkt = sniff(filter=f'icmp6 && dst host {DNS_ADDR}', count=1, iface=get_ipv6_iface(),
                                started_callback=send_system_ping_pkt_thread)
    # print(f'get the mac address of next hop is {system_ping_pkt[0].dst}')
    return system_ping_pkt[0].dst


LOCAL_IPv6_ADDR = get_local_ipv6_addr()
LOCAL_MAC_ADDR = get_local_mac_addr()
LOCAL_IPv6_IFACE = get_ipv6_iface()
LOCAL_WLAN_SSID = get_connected_wifi_ssid()
NEXT_HOP_MAC = get_next_hop_mac()


def icmp_traceroute6(dst_addr):
    ans, _ = srp(Ether(src=LOCAL_MAC_ADDR, dst=NEXT_HOP_MAC) / IPv6(dst=dst_addr, hlim=(1, 30)) / ICMPv6EchoRequest(),
                 timeout=2, filter="icmp6", iface=LOCAL_IPv6_IFACE)
    res = [get_local_ipv6_addr()]
    for snd, rcv in ans:
        if rcv[IPv6].src not in res:
            res.append(rcv[IPv6].src)
    return res


def tcp_traceroute6(dst_addr):
    res, _ = traceroute6(dst_addr)
    if dst_addr not in res.get_trace():
        return [get_local_ipv6_addr(), dst_addr]
    else:
        return [get_local_ipv6_addr()] + [item[1][0] for item in
                                          sorted(res.get_trace()[dst_addr].items(), key=lambda x: x[0])]


# 用traceroute获得到目的地路径
def get_path_to(dst_addr):
    tcp_result = tcp_traceroute6(dst_addr)
    icmp_result = icmp_traceroute6(dst_addr)
    return tcp_result if len(tcp_result) > len(icmp_result) else icmp_result


# payload是dict
def reply_udp_packet(pkt, payload: dict):
    # print(f'receive get client list request from {pkt[IPv6].src}', payload)
    sendp(Ether(src=LOCAL_MAC_ADDR, dst=NEXT_HOP_MAC) / IPv6(dst=pkt[IPv6].src) / UDP(sport=pkt[UDP].dport,
                                                                                      dport=pkt[
                                                                                          UDP].sport) / json.dumps(
        payload),
          iface=LOCAL_IPv6_IFACE)


# 从payload中解析出json数据
def parse_payload(pkt):
    return json.loads(pkt.payload.payload.payload.load)['data']


def get_alive_clients():
    if get_local_ipv6_addr() == SERVER_ADDR:
        from server import ClientManager
        return ClientManager.get_alive_clients()
    while True:
        sendp(Ether(src=LOCAL_MAC_ADDR, dst=NEXT_HOP_MAC) / IPv6(dst=SERVER_ADDR) / UDP(sport=ACCESS_CLIENT_LIST_PORT,
                                                                                        dport=ACCESS_CLIENT_LIST_PORT),
              iface=LOCAL_IPv6_IFACE)
        recv_packets = sniff(filter=f'dst host {LOCAL_IPv6_ADDR} && port {ACCESS_CLIENT_LIST_PORT}', count=1,
                             timeout=3, iface=LOCAL_IPv6_IFACE)
        if len(recv_packets) > 0:
            clients = parse_payload(recv_packets[0])
            return [client for client in clients if client != LOCAL_IPv6_ADDR]
        else:
            print(f'server is sleeping?')


def get_conn():
    return pymysql.connect(
        host='127.0.0.1',
        user='root',
        password='root',
        database='sava',
        charset='utf8',
        local_infile=True
    )


def query_data(sql):
    conn = get_conn()
    try:
        cursor = conn.cursor(pymysql.cursors.DictCursor)
        cursor.execute(sql)
        return cursor.fetchall()
    finally:
        conn.close()


def do_sql(sql):
    conn = get_conn()
    try:
        cursor = conn.cursor(pymysql.cursors.DictCursor)
        cursor.execute(sql)
        conn.commit()
    finally:
        conn.close()


# 插入一行数据
def insert_into(table_name, values):
    keys = list(values.keys())
    os.makedirs('result', exist_ok=True)
    save_file = f'result/{table_name}.csv'
    if not os.path.exists(save_file):
        with open(save_file, 'w') as f:
            f.write(','.join(keys) + '\n')
    with open(save_file, 'a') as f:
        f.write(','.join([f"'{values[key]}'" for key in keys]) + '\n')
    if SAVE_TO_DATABASE:
        do_sql(
            f'''insert into {table_name} ({','.join(keys)}) values ({','.join([f"'{values[key]}'" for key in keys])})''')


def clear_all_data():
    for table in ['IP_in_UDP', 'MAC_in_UDP', 'IP_in_ICMP']:
        file = f'result/{table}.csv'
        if os.path.exists(file):
            os.remove(file)
            if SAVE_TO_DATABASE:
                do_sql(f'truncate table {table}')
    import shutil
    shutil.rmtree('log')


def translate_ipv6_addr_to_int(ip_addr):
    return int(ipaddress.IPv6Address(ip_addr))


def translate_int_to_ipv6_addr(ip_int):
    return str(ipaddress.IPv6Address(ip_int))


def get_local_addr_inside_subnet(ip_addr, prefix_len):
    subnet_space = 2 ** (128 - prefix_len)
    ip_int = translate_ipv6_addr_to_int(ip_addr)
    gateway = ip_int - ip_int % subnet_space
    return translate_int_to_ipv6_addr(gateway + random.randint(0, subnet_space - 1))


def get_spoof_ips(src_addr, dst_addr):
    return {
        SpoofIpCategory.NO_SPOOF: [src_addr],
        SpoofIpCategory.FIX: [RANDOM_ADDR],
        SpoofIpCategory.SRC_OUT_BOUND: [get_local_addr_inside_subnet(src_addr, i) for i in SPOOF_IP_PREFIX_CHOICES],
        SpoofIpCategory.DST_IN_BOUND: [get_local_addr_inside_subnet(dst_addr, i) for i in SPOOF_IP_PREFIX_CHOICES],
        SpoofIpCategory.ACTIVE_CLIENTS: [i for i in get_alive_clients() if i != src_addr and i != dst_addr]
    }


def is_valid_mac_int(mac_int):
    # 第一个byte不能以1结尾
    return mac_int % (2 ** 48) // (2 ** 40) % 2 == 0


def generate_valid_mac_addr():
    while True:
        mac_int = random.randint(0, 2 ** 48)
        if is_valid_mac_int(mac_int):
            return translate_int_to_mac_addr(mac_int)


def translate_mac_addr_to_int(mac_addr):
    return int(mac_addr.replace(':', ''), 16)


def translate_int_to_mac_addr(mac_int):
    hex_desc = str(hex(mac_int))[2:].zfill(12)
    return ":".join([hex_desc[e:e + 2] for e in range(0, 11, 2)])


def get_local_mac_inside_subnet(ip_addr, prefix_len):
    subnet_space = 2 ** (48 - prefix_len)
    ip_int = translate_mac_addr_to_int(ip_addr)
    gateway = ip_int - ip_int % subnet_space
    return translate_int_to_mac_addr(gateway + random.randint(0, subnet_space - 1))


def get_spoof_macs(mac_addr):
    return {
        SpoofMacCategory.NO_SPOOF: [mac_addr],
        SpoofMacCategory.FIX: [RANDOM_MAC],
        SpoofMacCategory.FIX_PREFIX: [get_local_mac_inside_subnet(mac_addr, i * 4) for i in SPOOF_MAC_PREFIX_CHOICES],
        SpoofMacCategory.RANDOM: [generate_valid_mac_addr() for _ in range(5)]
    }


def recv_exact_length(skt, data_len):
    data = b''
    while len(data) < data_len:
        data += (skt.recv(data_len - len(data)))
    return data


# 通过TCP socket进行交互信息
def send_control_message(skt, data):
    send_body = json.dumps({'data': data}).encode()
    skt.sendall(struct.pack('i', len(send_body)))
    skt.sendall(send_body)


def recv_control_message(skt):
    data_len = struct.unpack('i', recv_exact_length(skt, 4))[0]
    data = recv_exact_length(skt, data_len).decode()
    return json.loads(data)['data']


def describe_spoof_result(logger, forge_config, forge_result):
    for forge_category in forge_config.keys():
        forge_total_num = len(forge_config[forge_category])
        forge_success_label = [1 if forge_result[addr] > 0 else 0 for addr in forge_config[forge_category]]
        forge_success_num = sum(forge_success_label)
        expect_success_num = 1 if forge_category in [SpoofIpCategory.NO_SPOOF, SpoofMacCategory.NO_SPOOF] else 0
        info = f"{'PASS!' if forge_success_num == expect_success_num else 'FAIL!' : <10} {forge_success_num :>3}/{forge_total_num :<10} {forge_category.value :<15}"
        # 检查伪造子网是否小子网内可以通过，大子网内通不过，试图找出这个边界
        if forge_category in [SpoofIpCategory.SRC_OUT_BOUND, SpoofIpCategory.DST_IN_BOUND] and 0 < forge_success_num:
            l = None
            for i in range(len(SPOOF_IP_PREFIX_CHOICES)):
                if forge_success_label[i] == 1:
                    l = i
                    break
            r = None
            for i in reversed(range(len(SPOOF_IP_PREFIX_CHOICES))):
                if forge_success_label[i] == 1:
                    r = i
                    break
            # 如果是连续的一段
            if forge_success_num == sum(forge_success_label[l:r + 1]):
                info += f" /{SPOOF_IP_PREFIX_CHOICES[l]} ~ /{SPOOF_IP_PREFIX_CHOICES[r]}子网内可以伪造成功"
            else:
                info += f" 不呈明显的规律性"
        logger.info(info)


if __name__ == '__main__':
    # print(get_spoof_ips(SERVER_ADDR))
    # print(translate_mac_addr_to_int(LOCAL_MAC_ADDR))
    # print(translate_int_to_mac_addr(translate_mac_addr_to_int(LOCAL_MAC_ADDR)))
    # print(translate_int_to_mac_addr(translate_mac_addr_to_int('04:83:e7:89:10:1d')))
    # print(get_connected_wifi_ssid())
    # print(get_running_os())
    # clear_all_data()
    # for i in range(10):
    #     print(generate_valid_mac_addr())
    result = get_spoof_macs('a4:83:e7:89:10:1d')
    for k, v in result.items():
        print(k.value, v)
    result = get_spoof_ips('0000::0000', '8888::8888')
    for k, v in result.items():
        print(k.value, v)
    result = reduce(lambda x, y: x + y, result.values())
    print(result)
