from psutil import net_io_counters
import time

def get_net_flow(net_card):
    """
    返回流量发送和接收的信息, 输入为网卡名字
    """
    net_info = net_io_counters(pernic=True).get(net_card)  #获取流量统计信息
    # 字节数统计信息
    recv_bytes = net_info.bytes_recv
    sent_bytes = net_info.bytes_sent
    # 数据包统计信息
    recv_pak = net_info.packets_recv
    sent_pak = net_info.packets_sent
    return recv_bytes, sent_bytes, recv_pak, sent_pak


def change_format(count):
    """
    改变字节数格式
    """
    if count < 1024:
        return "%.2f B/s" % count
    if count < 1048576:
        return "%.2f KB/s" % (count/1024)
    count >>= 10
    if count < 1048576:
        return "%.2f MB/s" % (count/1024)
    count >>= 10
    return "%.2f GB/s" % (count/1024)

def get_rate(net_card):
    """
    统计每秒接收到的数据大小, 输入为网卡名字
    """
    net_cards = []
    old = [0, 0, 0, 0]
    new = [0, 0, 0, 0]
    if net_card is None:    # 抓取全部网卡的速度
        net_cards = net_io_counters(pernic=True).keys()
    else:
        net_cards.append(net_card)
    for card in net_cards:
        # 上一秒收集的数据
        info = get_net_flow(card)
        for i in range(4):
            old[i] += info[i]
    time.sleep(1)
    # 当前所收集的数据
    for card in net_cards:
        # 上一秒收集的数据
        info = get_net_flow(card)
        for i in range(4):
            new[i] += info[i]
    info = []
    for i in range(4):
        info.append(new[i] - old[i])
    recv_bytes = change_format(info[0])  # 每秒接收的字节
    sent_bytes = change_format(info[1])  # 每秒发送的字节
    recv_pak = str(info[2]) + " pak/s"  # 每秒接收的数据包
    sent_pak = str(info[3]) + " pak/s"  # 每秒发送的数据包
    return recv_bytes, sent_bytes, recv_pak, sent_pak

if __name__ == '__main__':
    while True:
        print(get_rate("wlp2s0"))