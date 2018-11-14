# -*- coding: utf-8 -*-
""" 获取网卡 """
from platform import system
from psutil import net_if_addrs


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
