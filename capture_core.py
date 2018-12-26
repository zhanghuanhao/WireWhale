# -*- coding: utf-8 -*-
""" 抓包核心 """
import os
import shutil
from tempfile import NamedTemporaryFile
from threading import Event, Thread
from PyQt5.QtWidgets import QFileDialog, QMessageBox, QTreeWidgetItem
from PyQt5.QtGui import QColor, QBrush
from PyQt5.Qt import Qt

from scapy.layers.inet import *
from scapy.layers.inet6 import *
from scapy.layers.l2 import Ether
from scapy.sendrecv import sniff
from scapy.utils import *
from tools import *

platform, netcards = get_nic_list()
flush_time = 2000
if platform == 'Windows':
    keys = list(netcards.keys())
elif platform == 'Linux':
    keys = list(netcards)

# arp字典
arp_dict = {
    1: "who-has",
    2: "is-at",
    3: "RARP-req",
    4: "RARP-rep",
    5: "Dyn-RARP-req",
    6: "Dyn-RAR-rep",
    7: "Dyn-RARP-err",
    8: "InARP-req",
    9: "InARP-rep"
}
# icmpv6 code字典
icmpv6_code = {
    1: {
        0: "No route to destination",
        1: "Communication with destination administratively prohibited",
        2: "Beyond scope of source address",
        3: "Address unreachable",
        4: "Port unreachable"
    },
    3: {
        0: "hop limit exceeded in transit",
        1: "fragment reassembly time exceeded"
    },
    4: {
        0: "erroneous header field encountered",
        1: "unrecognized Next Header type encountered",
        2: "unrecognized IPv6 option encountered"
    },
}
# 端口字典
ports = {
    80: "HTTP",
    1900: "SSDP",
    53: "DNS",
    123: "NTP",
    21: "FTP",
    20: "FTP_Data",
    22: "SSH"
}

# HTTPS解析
content_type = {
    '14': "Change Cipher Spec",
    '15': "Alert Message",
    '16': "Handshake Protocol",
    '17': "Application Data"
}
version = {'00': "SSLv3", '01': "TLSv1.0", '02': "TLSv1.1", '03': "TLSv1.2"}

# 停止抓包的线程
stop_capturing_thread = Event()

# 数据包背景颜色字典
color_dict = {
    "TCP": "#e7e6ff",
    "TCPv6": "#e7e6ff",
    "UDP": "#daeeff",
    "UDPv6": "#daeeff",
    "ARP": "#faf0d7",
    "SSDP": "#ffe3e5",
    "SSDPv6": "#ffe3e5",
    "HTTP": "#caffbe",
    "HTTPv6": "#caffbe",
    "SSLv3": "#FFFFCC",
    "TLSv1.0": "#FFFFCC",
    "TLSv1.1": "#c797ff",
    "TLSv1.2": "#bfbdff",
    "ICMP": "#fce0ff",
    "ICMPv6": "#fce0ff",
    "NTP": "#daeeff",
    "NTPv6": "#daeeff",
    "DNS": "#CCFF99",
    "DNSv6": "#CCFF99"
}


class Core():
    """ 抓包后台类 """
    # 抓到的包编号从1开始
    packet_id = 1
    # 开始标志
    start_flag = False
    # 暂停标志
    pause_flag = False
    # 停止标志
    stop_flag = False
    # 保存标志
    save_flag = False
    # 窗口
    main_window = None
    # 开始时间戳
    start_timestamp = 0.0
    # 临时文件路径
    temp_file = None
    # 计数器
    counter = {"ipv4": 0, "ipv6": 0, "tcp": 0, "udp": 0, "icmp": 0, "arp": 0}

    def __init__(self, mainwindow):
        """
        初始化, 若不设置netcard则为捕捉所有网卡的数据包
        :parma mainwindow: 传入主窗口
        """
        self.main_window = mainwindow
        temp = NamedTemporaryFile(
            suffix=".pcap", prefix=str(int(time.time())), delete=False)
        self.temp_file = temp.name
        temp.close()

    def process_packet(self, packet, writer):
        """
        处理抓到的数据包
        :parma packet: 需要处理分类的包
        """
        try:
            # 如果暂停，则不对列表进行更新操作
            if not self.pause_flag and packet.name == "Ethernet":
                protocol = None
                if self.packet_id == 1:
                    self.start_timestamp = packet.time
                packet_time = packet.time - self.start_timestamp
                # 第二层
                ether_type = packet.payload.name
                version_add = ""
                # IPv4
                if ether_type == "IP":
                    source = packet[IP].src
                    destination = packet[IP].dst
                    self.counter["ipv4"] += 1
                # IPv6
                elif ether_type == "IPv6":
                    source = packet[IPv6].src
                    destination = packet[IPv6].dst
                    version_add = "v6"
                    self.counter["ipv6"] += 1
                # ARP
                elif ether_type == "ARP":
                    self.counter["arp"] += 1
                    protocol = ether_type
                    source = packet[Ether].src
                    destination = packet[Ether].dst
                    if destination == "ff:ff:ff:ff:ff:ff":
                        destination = "Broadcast"
                else:
                    # 其他协议不处理
                    return
                if ether_type != "ARP":
                    protocol = packet.payload.payload.name
                    sport = None
                    dport = None
                    if protocol == "TCP":
                        sport = packet[TCP].sport
                        dport = packet[TCP].dport
                        protocol += version_add
                        self.counter["tcp"] += 1
                    elif protocol == "UDP":
                        sport = packet[UDP].sport
                        dport = packet[UDP].dport
                        protocol += version_add
                        self.counter["udp"] += 1
                    elif len(protocol) >= 4 and protocol[0:4] == "ICMP":
                        protocol = "ICMP"
                        protocol += version_add
                        self.counter["icmp"] += 1
                    else:
                        return
                    if sport and dport:
                        # HTTPS
                        if sport == 443 or dport == 443:
                            https = packet.payload.payload.payload.__bytes__(
                            ).hex()
                            if len(https) >= 10 and https[2:4] == '03':
                                if https[0:2] in content_type and https[
                                        4:6] in version:
                                    protocol = version[https[4:6]]
                        elif sport in ports:
                            protocol = ports[sport] + version_add
                        elif dport in ports:
                            protocol = ports[dport] + version_add
                item = QTreeWidgetItem(self.main_window.info_tree)
                # 根据协议类型不同设置颜色
                color = color_dict[protocol]
                for i in range(7):
                    item.setBackground(i, QBrush(QColor(color)))
                # 添加行内容
                item.setData(0, Qt.DisplayRole, self.packet_id)
                item.setText(1, "%12.6f " % packet_time)
                item.setText(2, source)
                item.setText(3, destination)
                item.setText(4, protocol)
                item.setData(5, Qt.DisplayRole, len(packet))
                item.setText(6, packet.summary())
                # 设置右对齐，为了格式化后不影响排序
                item.setTextAlignment(1, Qt.AlignRight)
                self.packet_id += 1
                if writer:
                    writer.write(packet)
        except:
            pass

    def on_click_item(self, this_id):
        """
        处理点击列表中的项
        :parma this_id: 包对应的packet_id，在packet_list里获取该packet
        """
        try:
            if not this_id or this_id < 1:
                return
            previous_packet_time, packet = self.read_packet(this_id - 1)
            # 详细信息列表, 用于添加进GUI
            first_return = []
            second_return = []
            # 第一层: Frame
            first_layer = []
            # on wire的长度
            packet_wirelen = "%d bytes (%d bits)" % (packet.wirelen,
                                                     packet.wirelen << 3)
            # 实际抓到的长度
            packet_capturedlen = "%d bytes (%d bits)" % (len(packet),
                                                         len(packet) << 3)
            frame = "Frame %d: %s on wire, %s captured" % (
                this_id, packet_wirelen, packet_capturedlen)
            first_return.append(frame)
            # 抓包的时间
            first_layer.append(
                "Arrival Time: %s" % time_to_formal(packet.time))
            first_layer.append("Epoch Time: %f seconds" % packet.time)
            delta_time = packet.time - previous_packet_time
            first_layer.append(
                "[Time delta from previous captured frame: %f seconds]" %
                delta_time)
            delta_time = packet.time - self.start_timestamp
            first_layer.append(
                "[Time since first frame: %f seconds]" % delta_time)
            first_layer.append("Frame Number: %d" % this_id)
            first_layer.append("Frame Length: %s" % packet_wirelen)
            first_layer.append("Capture Length: %s" % packet_capturedlen)
            # 添加第一层信息到二维列表中
            second_return.append(first_layer)
            first_temp, second_temp = self.get_next_layer(packet)
            first_return += first_temp
            second_return += second_temp
            # dump=True 将hexdump返回而不是打印
        except:
            pass
        return first_return, second_return, hexdump(packet, dump=True)

    def get_next_layer(self, packet):
        """
        递归处理下一层信息
        :parma packet: 处理来自上一层packet的payload
        """
        # 第二层: Ethernet
        first_return = []
        second_return = []
        next_layer = []
        try:
            protocol = packet.name
            packet_class = packet.__class__
            if protocol == "NoPayload":
                return first_return, second_return
            elif protocol == "Ethernet":
                ether_src = packet[packet_class].src
                ether_dst = packet[packet_class].dst
                if ether_dst == "ff:ff:ff:ff:ff:ff":
                    ether_dst = "Broadcast (ff:ff:ff:ff:ff:ff)"
                ethernet = "Ethernet, Src: %s, Dst: %s" % (ether_src,
                                                           ether_dst)
                first_return.append(ethernet)
                next_layer.append("Source: %s" % ether_src)
                next_layer.append("Destination: %s" % ether_dst)
                ether_type = packet.payload.name
                if ether_type == "IP":
                    ether_type += "v4"
                ether_proto = ("Type: %s (%s)" %
                               (ether_type, hex(packet[packet_class].type)))
                next_layer.append(ether_proto)
            # 第三层: 网络层
            # IPv4
            elif protocol == "IP" or protocol == "IP in ICMP":
                protocol += "v4"
                ip_src = packet[packet_class].src
                ip_dst = packet[packet_class].dst
                network = "Internet Protocol Version 4, Src: %s, Dst: %s" % (
                    ip_src, ip_dst)
                first_return.append(network)
                next_layer.append("Version: %d" % packet[packet_class].version)
                next_layer.append(
                    "Header Length: %d bytes (%d)" %
                    (packet[packet_class].ihl << 2, packet[packet_class].ihl))
                next_layer.append("Differentiated Services Field: %s" % hex(
                    packet[packet_class].tos))
                next_layer.append(
                    "Total Length: %d" % packet[packet_class].len)
                next_layer.append("Identification: %s (%d)" % (hex(
                    packet[packet_class].id), packet[packet_class].id))
                next_layer.append(
                    "Flags: %d (%s)" % (packet[packet_class].flags,
                                        hex(packet[packet_class].flags.value)))
                next_layer.append(
                    "Fragment offset: %d" % packet[packet_class].frag)
                next_layer.append(
                    "Time to live: %d" % packet[packet_class].ttl)
                next_protocol = packet.payload.name
                if next_protocol == "IP":
                    next_protocol += "v4"
                next_layer.append("Protocol: %s (%d)" %
                                  (next_protocol, packet[packet_class].proto))
                ip_chksum = packet[packet_class].chksum
                ip_check = packet_class(raw(packet[packet_class])).chksum
                next_layer.append("Header checksum: %s" % hex(ip_chksum))
                next_layer.append("[Header checksum status: " + "Correct]"
                                  if ip_check == ip_chksum else "Incorrect]")
                next_layer.append("Source: %s" % ip_src)
                next_layer.append("Destination: %s" % ip_dst)
            # IPv6
            elif protocol == "IPv6" or protocol == "IPv6 in ICMPv6":
                ipv6_src = packet[packet_class].src
                ipv6_dst = packet[packet_class].dst
                network = ("Internet Protocol Version 6, Src: %s, Dst: %s" %
                           (ipv6_src, ipv6_dst))
                first_return.append(network)
                next_layer.append("Version: %d" % packet[packet_class].version)
                next_layer.append(
                    "Traffice Class: %s" % hex(packet[packet_class].tc))
                next_layer.append(
                    "Flow Label: %s" % hex(packet[packet_class].fl))
                next_layer.append(
                    "Payload Length: %d" % packet[packet_class].plen)
                next_protocol = packet.payload.name
                if next_protocol == "IP":
                    next_protocol += "v4"
                next_layer.append("Next Header: %s (%d)" %
                                  (next_protocol, packet[packet_class].nh))
                next_layer.append("Hop Limit: %d" % packet[packet_class].hlim)
                next_layer.append("Source: %s" % ipv6_src)
                next_layer.append("Destination: %s" % ipv6_dst)
            elif protocol == "ARP":
                arp_op = packet[packet_class].op
                network = "Address Resolution Protocol "
                if arp_op in arp_dict:
                    network += "(%s)" % arp_dict[arp_op]
                first_return.append(network)
                next_layer.append(
                    "Hardware type: %d" % packet[packet_class].hwtype)
                ptype = packet[packet_class].ptype
                temp_str = "Protocol type: %s" % hex(
                    packet[packet_class].ptype)
                if ptype == 0x0800:
                    temp_str += " (IPv4)"
                elif ptype == 0x86DD:
                    temp_str += " (IPv6)"
                next_layer.append(temp_str)
                next_layer.append(
                    "Hardware size: %d" % packet[packet_class].hwlen)
                next_layer.append(
                    "Protocol size: %d" % packet[packet_class].plen)
                temp_str = "Opcode: %d" % arp_op
                if arp_op in arp_dict:
                    temp_str += " (%s)" % arp_dict[arp_op]
                next_layer.append(temp_str)
                next_layer.append(
                    "Sender MAC address: %s" % packet[packet_class].hwsrc)
                next_layer.append(
                    "Sender IP address: %s" % packet[packet_class].psrc)
                next_layer.append(
                    "Target MAC address: %s" % packet[packet_class].hwdst)
                next_layer.append(
                    "Target IP address: %s" % packet[packet_class].pdst)
            # 第四层: 传输层
            elif protocol == "TCP" or protocol == "TCP in ICMP":
                src_port = packet[packet_class].sport
                dst_port = packet[packet_class].dport
                transport = (
                    "Transmission Control Protocol, Src Port: %d, Dst Port: %d"
                    % (src_port, dst_port))
                first_return.append(transport)
                next_layer.append("Source Port: %d" % src_port)
                next_layer.append("Destination Port: %d" % dst_port)
                next_layer.append(
                    "Sequence number: %d" % packet[packet_class].seq)
                next_layer.append(
                    "Acknowledgment number: %d" % packet[packet_class].ack)
                tcp_head_length = packet[packet_class].dataofs
                next_layer.append("Header Length: %d bytes (%d)" %
                                  (tcp_head_length << 2, tcp_head_length))
                next_layer.append(
                    "Flags: %s (%d)" % (hex(packet[packet_class].flags.value),
                                        packet[packet_class].flags))
                next_layer.append(
                    "Window size value: %d" % packet[packet_class].window)
                tcp_chksum = packet[packet_class].chksum
                tcp_check = packet_class(raw(packet[packet_class])).chksum
                next_layer.append("Checksum: %s" % hex(tcp_chksum))
                next_layer.append("[Checksum status: " + "Correct]"
                                  if tcp_check == tcp_chksum else "Incorrect]")
                next_layer.append(
                    "Urgent pointer: %d" % packet[packet_class].urgptr)
                options = packet[packet_class].options
                options_length = len(options) << 2
                if options_length > 0:
                    string = "Options: (%d bytes)" % options_length
                    for item in options:
                        string += ", %s: %s" % (item[0], str(item[1]))
                    next_layer.append(string)
                payload_length = len(packet.payload)
                if payload_length > 0:
                    next_layer.append("TCP payload: %d bytes" % payload_length)
            elif protocol == "UDP" or protocol == "UDP in ICMP":
                src_port = packet[packet_class].sport
                dst_port = packet[packet_class].dport
                length = packet[packet_class].len
                transport = (
                    "User Datagram Protocol, Src Port: %d, Dst Port: %d" %
                    (src_port, dst_port))
                first_return.append(transport)
                next_layer.append("Source Port: %d" % src_port)
                next_layer.append("Destination Port: %d" % dst_port)
                next_layer.append("Length: %d" % length)
                udp_chksum = packet[packet_class].chksum
                udp_check = packet_class(raw(packet[packet_class])).chksum
                next_layer.append("Chksum: %s" % hex(udp_chksum))
                next_layer.append("[Checksum status: " + "Correct]"
                                  if udp_check == udp_chksum else "Incorrect]")
                length = len(packet[packet_class].payload)
                # Have payload
                if length > 0:
                    second_return.append(next_layer.copy())
                    next_layer.clear()
                    payload = bytes(packet[packet_class].payload)
                    # SSDP
                    if src_port == 1900 or dst_port == 1900:
                        first_return.append(
                            "Simple Service Discovery Protocol")
                        payload = bytes.decode(payload).split('\r\n')
                        for string in payload:
                            if string:
                                next_layer.append(string)
                    # Raw
                    else:
                        first_return.append("Data (%d bytes)" % length)
                        next_layer.append("Data: %s" % payload.hex())
                        next_layer.append("[Length: %d]" % length)
            elif protocol == "ICMP" or protocol == "ICMP in ICMP":
                transport = "Internet Control Message Protocol"
                first_return.append(transport)
                packet_type = packet[packet_class].type
                temp_str = "Type: %d" % packet_type
                if packet_type in icmptypes:
                    temp_str += " (%s)" % icmptypes[packet_type]
                next_layer.append(temp_str)
                packet_code = packet[packet_class].code
                temp_str = "Code: %d" % packet_code
                if packet_type in icmpcodes:
                    if packet_code in icmpcodes[packet_type]:
                        temp_str += " (%s)" % icmpcodes[packet_type][
                            packet_code]
                next_layer.append(temp_str)
                icmp_chksum = packet[packet_class].chksum
                icmp_check = packet_class(raw(packet[packet_class])).chksum
                next_layer.append("Checksum: %s" % hex(icmp_chksum))
                next_layer.append("[Checksum status: " + "Correct]" if
                                  icmp_check == icmp_chksum else "Incorrect]")
                if packet_type == 0 or packet_type == 8 or protocol == "ICMP in ICMP":
                    next_layer.append(
                        "Identifier: %d (%s)" % (packet[packet_class].id,
                                                 hex(packet[packet_class].id)))
                    next_layer.append("Sequence number: %d (%s)" %
                                      (packet[packet_class].seq,
                                       hex(packet[packet_class].seq)))
                    data_length = len(packet.payload)
                    if data_length > 0:
                        next_layer.append(
                            "Data (%d bytes): %s" %
                            (data_length, packet[packet_class].load.hex()))
            elif len(protocol) >= 6 and protocol[0:6] == "ICMPv6":
                if protocol.lower().find("option") == -1:
                    transport = "Internet Control Message Protocol v6"
                    first_return.append(transport)
                    proto_type = packet[packet_class].type
                    temp_str = "Type: %d" % proto_type
                    if proto_type in icmp6types:
                        temp_str += " (%s)" % icmp6types[proto_type]
                    next_layer.append(temp_str)
                    packet_code = packet[packet_class].code
                    temp_str = "Code: %d" % packet_code
                    if proto_type in icmpv6_code:
                        if packet_code in icmpv6_code[proto_type]:
                            temp_str += " (%s)" % icmpv6_code[proto_type][
                                packet_code]
                    next_layer.append(temp_str)
                    icmpv6_cksum = packet[packet_class].cksum
                    icmpv6_check = packet_class(raw(
                        packet[packet_class])).cksum
                    next_layer.append("Checksum: %s" % hex(icmpv6_cksum))
                    next_layer.append("[Checksum status: " +
                                      "Correct]" if icmpv6_check ==
                                      icmpv6_cksum else "Incorrect]")
                    if proto_type == "Echo Request" or proto_type == "Echo Reply":
                        next_layer.append("Identifier: %d (%s)" %
                                          (packet[packet_class].id,
                                           hex(packet[packet_class].id)))
                        next_layer.append("Sequence number: %d (%s)" %
                                          (packet[packet_class].seq,
                                           hex(packet[packet_class].seq)))
                        data_length = packet[packet_class].plen - 8
                        if data_length > 0:
                            next_layer.append(
                                "Data (%d bytes): %s" %
                                (data_length, packet[packet_class].load.hex()))
                    elif proto_type == "Neighbor Advertisement":
                        temp_set = "Set (1)"
                        temp_not_set = "Not set (0)"
                        temp_str = "Router: "
                        if packet[packet_class].R == 1:
                            temp_str += temp_set
                        else:
                            temp_str += temp_not_set
                        next_layer.append(temp_str)
                        temp_str = "Solicited: "
                        if packet[packet_class].S == 1:
                            temp_str += temp_set
                        else:
                            temp_str += temp_not_set
                        next_layer.append(temp_str)
                        temp_str = "Override: "
                        if packet[packet_class].O == 1:
                            temp_str += temp_set
                        else:
                            temp_str += temp_not_set
                        next_layer.append(temp_str)
                        next_layer.append(
                            "Reserved: %d" % packet[packet_class].res)
                        next_layer.append(
                            "Target Address: %s" % packet[packet_class].tgt)
                    elif proto_type == "Neighbor Solicitation":
                        next_layer.append(
                            "Reserved: %d" % packet[packet_class].res)
                        next_layer.append(
                            "Target Address: %s" % packet[packet_class].tgt)
                    elif proto_type == "Router Solicitation":
                        next_layer.append(
                            "Reserved: %d" % packet[packet_class].res)
                    elif proto_type == "Router Advertisement":
                        temp_set = "Set (1)"
                        temp_not_set = "Not set (0)"
                        next_layer.append(
                            "Cur hop limit: %d" % packet[packet_class].chlim)
                        temp_str = "Managed address configuration: "
                        if packet[packet_class].M == 1:
                            temp_str += temp_set
                        else:
                            temp_str += temp_not_set
                        next_layer.append(temp_str)
                        temp_str = "Other configuration: "
                        if packet[packet_class].O == 1:
                            temp_str += temp_set
                        else:
                            temp_str += temp_not_set
                        next_layer.append(temp_str)
                        temp_str = "Home Agent: "
                        if packet[packet_class].H == 1:
                            temp_str += temp_set
                        else:
                            temp_str += temp_not_set
                        next_layer.append(temp_str)
                        temp_str = "Preference: %d" % packet[packet_class].prf
                        next_layer.append(temp_str)
                        temp_str = "Proxy: "
                        if packet[packet_class].P == 1:
                            temp_str += temp_set
                        else:
                            temp_str += temp_not_set
                        next_layer.append(temp_str)
                        next_layer.append(
                            "Reserved: %d" % packet[packet_class].res)
                        next_layer.append("Router lifetime (s): %d" %
                                          packet[packet_class].routerlifetime)
                        next_layer.append("Reachable time (ms): %d" %
                                          packet[packet_class].reachabletime)
                        next_layer.append("Retrans timer (ms): %d" %
                                          packet[packet_class].retranstimer)
                    elif proto_type == "Destination Unreachable":
                        next_layer.append("Length: %d (%s)" %
                                          (packet[packet_class].length,
                                           hex(packet[packet_class].length)))
                        next_layer.append(
                            "Unused: %d" % packet[packet_class].unused)
                    elif proto_type == "Packet too big":
                        next_layer.append("MTU: %d" % packet[packet_class].mtu)
                    elif proto_type == "Parameter problem":
                        next_layer.append("PTR: %d" % packet[packet_class].ptr)
                    elif proto_type == "Time exceeded":
                        next_layer.append("Length: %d (%s)" %
                                          (packet[packet_class].length,
                                           hex(packet[packet_class].length)))
                        next_layer.append(
                            "Unused: %d" % packet[packet_class].unused)
                else:
                    # ICMPv6 Option
                    transport = "ICMPv6 Option ("
                    proto_type = packet[packet_class].type
                    # Source Link-Layer or Destination Link-Layer
                    if proto_type == 1 or proto_type == 2:
                        address = packet[packet_class].lladdr
                        if proto_type == 1:
                            transport += "Source Link-Layer Address: %s)" % address
                            proto_type = "Type: Source Link-Layer Address (1)"
                        else:
                            transport += "Destination Link-Layer Address: %s)" % address
                            proto_type = "Type: Destination Link-Layer Address (2)"
                        first_return.append(transport)
                        next_layer.append(proto_type)
                        length = packet[packet_class].len
                        next_layer.append(
                            "Length: %d (%d bytes)" % (length, length << 3))
                        next_layer.append("Link-Layer Address: %s" % address)
                    # Prefix Information
                    elif proto_type == 3:
                        packet_prefix = packet[packet_class].prefix
                        transport += "Prefix Information: %s)" % packet_prefix
                        proto_type = "Type: Prefix Information (3)"
                        first_return.append(transport)
                        next_layer.append(proto_type)
                        length = packet[packet_class].len
                        next_layer.append(
                            "Length: %d (%d bytes)" % (length, length << 3))
                        next_layer.append("Prefix Length: %d" %
                                          packet[packet_class].prefixlen)
                        set_str = "Set (1)"
                        not_set_str = "Not set (0)"
                        next_layer.append("On-link flag (L): %s" %
                                          set_str if packet[packet_class].L ==
                                          1 else not_set_str)
                        next_layer.append(
                            "Autonomous address-configuration flag (A): %s" %
                            set_str if packet[packet_class].A ==
                            1 else not_set_str)
                        next_layer.append("Router address flag(R): %s" %
                                          set_str if packet[packet_class].R ==
                                          1 else not_set_str)
                        next_layer.append("Valid Lifetime: %d" %
                                          packet[packet_class].validlifetime)
                        next_layer.append(
                            "Preferred Lifetime: %d" %
                            packet[packet_class].preferredlifetime)
                        next_layer.append(
                            "Reserverd: %d" % packet[packet_class].res2)
                        next_layer.append("Prefix: %s" % packet_prefix)
                    # MTU
                    elif proto_type == 5:
                        packet_mtu = packet[packet_class].mtu
                        transport += "MTU: %d)" % packet_mtu
                        proto_type = "Type: MTU (5)"
                        first_return.append(transport)
                        next_layer.append(proto_type)
                        length = packet[packet_class].len
                        next_layer.append(
                            "Length: %d (%d bytes)" % (length, length << 3))
                        next_layer.append(
                            "Reserverd: %d" % packet[packet_class].res)
                        next_layer.append("MTU: %d" % packet_mtu)
                    else:
                        # 不识别，直接返回
                        return first_return, second_return
            # 第五层: 应用层
            # TLS
            else:
                https = packet.__bytes__().hex()
                total_length = len(https)
                temp_length = 0
                while len(https) >= 10:
                    if https[2:4] == '03' and https[
                            0:2] in content_type and https[4:6] in version:
                        protocol = version[https[4:6]]
                        cont_type = content_type[https[0:2]]
                        first_return.append("%s : %s" % (protocol, cont_type))
                        next_layer.append("Content Type: %s (%d)" %
                                          (cont_type, int(https[0:2], 16)))
                        next_layer.append(
                            "Version: %s (0x%s)" % (protocol, https[2:6]))
                        length = int(https[6:10], 16)
                        next_layer.append("Length: %d" % length)
                        # 如果有数据
                        if length > 0:
                            this_layer_len = 10 + (length << 1)
                            next_layer.append(
                                "Data: %s" % https[10:this_layer_len])
                            temp_length += this_layer_len
                            if total_length != temp_length:
                                https = https[this_layer_len:]
                                second_return.append(next_layer.copy())
                                next_layer.clear()
                            else:
                                break
                    else:
                        break
            if next_layer:
                second_return.append(next_layer)
            first_temp, second_temp = self.get_next_layer(packet.payload)
            first_return += first_temp
            second_return += second_temp
        except:
            # 未知数据包
            first_return.clear()
            second_return.clear()
        return first_return, second_return

    def flow_count(self, netcard=None):
        """
        刷新下载速度、上传速度、发包速度和收包速度
        """
        if netcard and platform == 'Windows':
            # 反转键值对
            my_dict = dict(zip(netcards.values(), netcards.keys()))
            netcard = my_dict[netcard]
        while not stop_capturing_thread.is_set():
            recv_bytes, sent_bytes, recv_pak, sent_pak = get_formal_rate(
                get_rate(netcard))
            if not self.pause_flag:
                self.main_window.comNum.setText('下载速度：' + recv_bytes)
                self.main_window.baudNum.setText('上传速度：' + sent_bytes)
                self.main_window.getSpeed.setText('收包速度：' + recv_pak)
                self.main_window.sendSpeed.setText('发包速度：' + sent_pak)
        self.main_window.comNum.setText('下载速度：0 B/s')
        self.main_window.baudNum.setText('上传速度：0 B/s')
        self.main_window.getSpeed.setText('收包速度：0 pak/s')
        self.main_window.sendSpeed.setText('发包速度：0 pak/s')

    def capture_packet(self, netcard, filters):
        """
        抓取数据包
        """
        stop_capturing_thread.clear()
        # 第一个参数可以传入文件对象或者文件名字
        writer = PcapWriter(self.temp_file, append=True, sync=True)
        thread = Thread(target=self.flow_count, daemon=True, args=(netcard, ))
        thread.start()
        # sniff中的store=False 表示不保存在内存中，防止内存使用过高
        sniff(
            iface=netcard,
            prn=(lambda x: self.process_packet(x, writer)),
            filter=filters,
            stop_filter=(lambda x: stop_capturing_thread.is_set()),
            store=False)
        # 执行完成关闭writer
        writer.close()

    def start_capture(self, netcard=None, filters=None):
        """
        开启新线程进行抓包
        :parma netcard: 选择的网卡, "any"为全选
        :parma filters: 过滤器条件
        """
        # 如果已开始抓包，则不能进行操作
        if self.start_flag:
            return
        # 如果已经停止且未保存数据包，则提示是否保存数据包
        if self.stop_flag:
            if not self.save_flag and self.packet_id > 1:
                resault = QMessageBox.question(
                    None,
                    "提示",
                    "是否保存已抓取的数据包？",
                    QMessageBox.Yes,
                    QMessageBox.Cancel,
                )
                if resault == QMessageBox.Yes:
                    self.save_captured_to_pcap()
            self.stop_flag = False
            self.save_flag = False
            self.pause_flag = False
            self.packet_id = 1
            self.clean_out()
            temp = NamedTemporaryFile(
                suffix=".pcap", prefix=str(int(time.time())), delete=False)
            self.temp_file = temp.name
            temp.close()
        # 如果从暂停开始
        elif self.pause_flag:
            # 继续显示抓到的包显示
            self.pause_flag = False
            self.start_flag = True
            return
        # 开启新线程进行抓包
        thread = Thread(
            target=self.capture_packet,
            daemon=True,
            name="capture_packet",
            args=(netcard, filters))
        thread.start()
        self.start_flag = True

    def pause_capture(self):
        """
        暂停抓包, 抓包函数仍在进行，只是不更新
        """
        self.pause_flag = True
        self.start_flag = False

    def stop_capture(self):
        """
        停止抓包，关闭线程
        """
        # 通过设置终止线程，停止抓包
        stop_capturing_thread.set()
        self.stop_flag = True
        self.pause_flag = False
        self.start_flag = False

    def restart_capture(self, netcard=None, filters=None):
        """
        重新开始抓包
        """
        self.stop_capture()
        self.start_capture(netcard, filters)

    def save_captured_to_pcap(self):
        """
        将抓到的数据包保存为pcap格式的文件
        """
        if self.packet_id == 1:
            QMessageBox.warning(None, "警告", "没有可保存的数据包！")
            return
        # 选择保存名称
        filename, _ = QFileDialog.getSaveFileName(
            parent=None,
            caption="保存文件",
            directory=os.getcwd(),
            filter="All Files (*);;Pcap Files (*.pcap)",
        )
        if filename == "":
            QMessageBox.warning(None, "警告", "保存失败！")
            return
        # 如果没有设置后缀名（保险起见，默认是有后缀的）
        if filename.find(".pcap") == -1:
            # 默认文件格式为 pcap
            filename = filename + ".pcap"
        shutil.copy(self.temp_file, filename)
        os.chmod(filename, 0o0400 | 0o0200 | 0o0040 | 0o0004)
        QMessageBox.information(None, "提示", "保存成功！")
        self.save_flag = True

    def open_pcap_file(self):
        """
        打开pcap格式的文件
        """
        if self.stop_flag and not self.save_flag:
            reply = QMessageBox.question(
                None,
                "提示",
                "是否保存已抓取的数据包？",
                QMessageBox.Yes,
                QMessageBox.Cancel,
            )
            if reply == QMessageBox.Yes:
                self.save_captured_to_pcap()
        filename, _ = QFileDialog.getOpenFileName(
            parent=None,
            caption="打开文件",
            directory=os.getcwd(),
            filter="All Files (*);;Pcap Files (*.pcap)",
        )
        if filename == "":
            return
        self.main_window.info_tree.clear()
        self.main_window.treeWidget.clear()
        self.main_window.set_hex_text("")
        # 如果没有设置后缀名（保险起见，默认是有后缀的）
        if filename.find(".pcap") == -1:
            # 默认文件格式为 pcap
            filename = filename + ".pcap"
        self.packet_id = 1
        self.main_window.info_tree.setUpdatesEnabled(False)
        shutil.copy(filename, self.temp_file)
        sniff(
            prn=(lambda x: self.process_packet(x, None)),
            store=False,
            offline=self.temp_file)
        self.main_window.info_tree.setUpdatesEnabled(True)
        self.stop_flag = True
        self.save_flag = True

    def clean_out(self):
        '''
        清除临时文件
        '''
        try:
            os.remove(self.temp_file)
        except PermissionError:
            pass
        # 将字典中的值初始化为0
        self.counter = {}.fromkeys(list(self.counter.keys()), 0)

    def get_transport_count(self):
        """
        获取传输层数据包的数量
        """
        the_keys = ['tcp', 'udp', 'icmp', 'arp']
        counter_copy = self.counter.copy()
        return_dict = {}
        for key, value in counter_copy.items():
            if key in the_keys:
                return_dict.update({key: value})
        return return_dict

    def get_network_count(self):
        """
        获取网络层数据包的数量
        """
        the_keys = ['ipv4', 'ipv6']
        counter_copy = self.counter.copy()
        return_dict = {}
        for key, value in counter_copy.items():
            if key in the_keys:
                return_dict.update({key: value})
        return return_dict

    def read_packet(self, location):
        '''
        读取硬盘中的pcap数据
        :parma location: 数据包位置
        :return: 返回参数列表[上一个数据包的时间，数据包]
        '''
        # 数据包时间是否为纳秒级
        nano = False
        # 打开文件
        f = open(self.temp_file, "rb")
        # 获取Pcap格式 magic
        head = f.read(24)
        magic = head[:4]
        linktype = head[20:]
        if magic == b"\xa1\xb2\xc3\xd4":  # big endian
            endian = ">"
            nano = False
        elif magic == b"\xd4\xc3\xb2\xa1":  # little endian
            endian = "<"
            nano = False
        elif magic == b"\xa1\xb2\x3c\x4d":  # big endian, nanosecond-precision
            endian = ">"
            nano = True
        elif magic == b"\x4d\x3c\xb2\xa1":  # little endian, nanosecond-precision
            endian = "<"
            nano = True
        else:
            # 不是pcap文件，弹出错误

            f.close()
            return
        linktype = struct.unpack(endian + "I", linktype)[0]
        try:
            LLcls = conf.l2types[linktype]
        except KeyError:
            # 未知 LinkType
            LLcls = conf.raw_layer
        sec, usec, caplen = [0, 0, 0]
        for _ in range(location):
            packet_head = f.read(16)
            if len(packet_head) < 16:
                f.close()
                return None
            sec, usec, caplen = struct.unpack(endian + "III", packet_head[:12])
            # f.seek(offset=?, whence=?)
            # :parma offset: 偏移量
            # :parma whence: 开始的位置 0从头开始 1从当前位置 2从文件末尾
            f.seek(caplen, 1)
        previous_time = sec + (0.000000001 if nano else 0.000001) * usec
        packet_head = f.read(16)
        sec, usec, caplen, wirelen = struct.unpack(endian + "IIII",
                                                   packet_head)
        rp = f.read(caplen)[:0xFFFF]
        if not rp:
            f.close()
            return None
        try:
            p = LLcls(rp)
        except:
            p = conf.raw_layer(rp)
        p.time = sec + (0.000000001 if nano else 0.000001) * usec
        p.wirelen = wirelen
        f.close()
        return previous_time, p
