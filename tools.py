# -*- coding: utf-8 -*-
"""
工具集
可获取网卡列表, 某个网卡的下载速度上传速度等
"""

import time
from platform import system
from psutil import net_if_addrs, net_io_counters


def get_netcard_name():
    '''
    获取网卡MAC和名字对应字典
    如: {'9C-B6-D0-0E-70-D9': 'WLAN'}
    '''
    netcard_info = {}
    info = net_if_addrs()
    for k, v in info.items():
        for item in v:
            # 除去环路地址
            if item[0] == 2 and item[1] == '127.0.0.1':
                break
            # 创建字典
            elif item[0] == -1 or item[0] == 17:
                netcard_info.update({item[1]: k})
    return netcard_info


def get_nic_list():
    '''
    :return: (系统信息, 网卡字典或列表)
    Linux返回列表, Windows返回字典s
    字典key为网卡名字, value为NIC信息
    如: {'WLAN': 'Killer Wireless-n/a/ac 1535 Wireless Network Adapter'}
    '''
    # 获取系统信息
    system_name = system()
    netcard_name = get_netcard_name()
    if system_name == "Windows":
        import wmi
        wmi_obj = wmi.WMI()
        data = {}
        for nic in wmi_obj.Win32_NetworkAdapterConfiguration():
            if nic.MACAddress is not None:
                # 与前面的字典匹配
                mac_address = str(nic.MACAddress).replace(':', '-')
                if mac_address in netcard_name.keys():
                    net_card_name = netcard_name.get(mac_address)
                    nic_name = str(nic.Caption)[11:]
                    data.update({net_card_name: nic_name})
        return (system_name, data)
    elif system_name == "Linux":
        List = list(netcard_name.values())
        return (system_name, List)
    else:
        return None


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
        return "%.2f KB/s" % (count / 1024)
    count >>= 10
    if count < 1048576:
        return "%.2f MB/s" % (count / 1024)
    count >>= 10
    return "%.2f GB/s" % (count / 1024)


def get_rate(net_card):
    """
    统计每秒接收到的数据大小
    :parma net_card: 网卡名字
    :return : 返回未格式化的信息
    """
    net_cards = []
    old = [0, 0, 0, 0]
    new = [0, 0, 0, 0]
    if net_card is None:  # 抓取全部网卡的速度
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
    return info


def get_formal_rate(info):
    """
    获取格式化的速率
    :parma info: 列表，包含recv_bytes, sent_bytes, recv_pak, sent_pak
    :return :返回格式化后的信息
    """
    recv_bytes = change_format(info[0])  # 每秒接收的字节
    sent_bytes = change_format(info[1])  # 每秒发送的字节
    recv_pak = str(info[2]) + " pak/s"  # 每秒接收的数据包
    sent_pak = str(info[3]) + " pak/s"  # 每秒发送的数据包
    return recv_bytes, sent_bytes, recv_pak, sent_pak

def time_to_formal(time_stamp):
    """
    将时间戳转换为标准的时间字符串
    如： 2018-10-21 20:27:53.123456
    :parma time_stamp: 时间戳，ms为单位
    """
    delta_ms = str(time_stamp - int(time_stamp))
    time_temp = time.localtime(time_stamp)
    my_time = time.strftime("%Y-%m-%d %H:%M:%S", time_temp)
    my_time += delta_ms[1:8]
    return my_time