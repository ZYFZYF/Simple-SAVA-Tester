import json

import psutil
import pymysql
from scapy.all import *
from scapy.layers.inet6 import IPv6, UDP, traceroute6, ICMPv6EchoRequest

from config import *


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
    if system in ['win32', 'win64', 'linux']:
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
    # TODO 得找台windows电脑再测
    if RUNNING_OS in ['win32', 'win64']:
        ret = subprocess.run(
            "netsh wlan show interfaces | awk -F' SSID '  '/ SSID / {print $2}'",
            shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output = ret.stdout.decode().replace(':', '').strip()
        return output
    return 'UNKNOWN'


LOCAL_IPv6_ADDR = get_local_ipv6_addr()
LOCAL_MAC_ADDR = get_local_mac_addr()
LOCAL_IPv6_IFACE = get_ipv6_iface()
LOCAL_WLAN_SSID = get_connected_wifi_ssid()


def icmp_traceroute6(dst_addr):
    ans, _ = sr(IPv6(dst=dst_addr, hlim=(1, 30)) / ICMPv6EchoRequest(), timeout=2, filter="icmp6")
    res = [get_local_ipv6_addr()]
    for snd, rcv in ans:
        if rcv.src not in res:
            res.append(rcv.src)
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
    send(IPv6(dst=pkt[IPv6].src) / UDP(sport=pkt[UDP].dport, dport=pkt[UDP].sport) / json.dumps(payload))


# 从payload中解析出json数据
def parse_payload(pkt):
    return json.loads(pkt.payload.payload.payload.load)['data']


def get_alive_clients():
    if get_local_ipv6_addr() == SERVER_ADDR:
        return []
    while True:
        send(IPv6(dst=SERVER_ADDR) / UDP(sport=ACCESS_CLIENT_LIST_PORT, dport=ACCESS_CLIENT_LIST_PORT))
        recv_packets = sniff(filter=f'dst host {LOCAL_IPv6_ADDR} && port {ACCESS_CLIENT_LIST_PORT}', count=1,
                             timeout=3, iface=LOCAL_IPv6_IFACE)
        if len(recv_packets) > 0:
            clients = parse_payload(recv_packets[0])
            return [client for client in clients if client != get_local_ipv6_addr()]
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
        os.remove(f'result/{table}.csv')
        if SAVE_TO_DATABASE:
            do_sql(f'truncate table {table}')


if __name__ == '__main__':
    print(get_connected_wifi_ssid())
    print(LOCAL_IPv6_ADDR, LOCAL_IPv6_IFACE, LOCAL_MAC_ADDR, LOCAL_WLAN_SSID)
