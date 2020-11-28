import socket
import json, pymysql, psutil
from config import *
from scapy.all import *
from scapy.layers.inet6 import IPv6, UDP, Ether, traceroute6, ICMPv6EchoRequest


# 通过IPv6包头拿到本机IPv6地址
def get_local_ipv6_addr():
    return IPv6(dst=DNS_ADDR).src


def get_local_mac_addr():
    return get_if_hwaddr(conf.iface)


def get_ipv6_iface():
    for iface, addrs in psutil.net_if_addrs().items():
        for addr in addrs:
            if addr.address == get_local_ipv6_addr():
                return iface


LOCAL_IPv6_ADDR = get_local_ipv6_addr()
LOCAL_MAC_ADDR = get_local_mac_addr()
LOCAL_IPv6_IFACE = get_ipv6_iface()


# 用traceroute获得到目的地路径
def get_path_to(dst_addr):
    res, _ = traceroute6(dst_addr)
    if dst_addr not in res:
        return [get_local_ipv6_addr(), dst_addr]
    else:
        return [get_local_ipv6_addr()] + [item[1][0] for item in
                                          sorted(res.get_trace()[dst_addr].items(), key=lambda x: x[0])]


# payload是dict
def reply_udp_packet(pkt, payload: dict):
    print(f'receive get client list request from {pkt[IPv6].src}', payload)
    send(IPv6(dst=pkt[IPv6].src) / UDP(sport=pkt[UDP].dport, dport=pkt[UDP].sport) / json.dumps(payload))


# 从payload中解析出json数据
def parse_payload(pkt):
    return json.loads(pkt.payload.payload.payload.load)['data']


def get_alive_clients():
    if get_local_ipv6_addr() == SERVER_ADDR:
        return []
    while True:
        send(IPv6(dst=SERVER_ADDR) / UDP(sport=ACCESS_CLIENT_LIST_PORT, dport=ACCESS_CLIENT_LIST_PORT))
        recv_packets = sniff(filter=f'dst host {get_local_ipv6_addr()} && port {ACCESS_CLIENT_LIST_PORT}', count=1,
                             timeout=3)
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
    # print(get_local_ipv6_addr())
    # print(get_path_to(SERVER_ADDR))
    # print(get_if_addr6(conf.iface))
    #
    # print(get_if_hwaddr(conf.iface))
    # print(get_if_raw_addr6(conf.iface))
    # print(get_if_raw_hwaddr(conf.iface))
    print(get_ipv6_iface())
