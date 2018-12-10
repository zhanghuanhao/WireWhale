# -*- coding: utf-8 -*-
""" 流量监测系统 """
from threading import Thread, Event
from scapy.sendrecv import sniff
from scapy.layers.inet import *
import psutil


class Monitor:
    """
    流量监测
    """
    # 程序使用的端口
    process_ports = []
    # 监测系统是否开始
    start_flag = Event()
    window = None

    def __init__(self, window):
        self.window = window
        self.start_flag.set()

    def getProcessList(self):
        """
        获取有网络连接的进程列表
        :return :返回进程列表
        """
        process_list = set()
        for process in psutil.process_iter():
            connections = process.connections()
            if connections:
                process_list.add(process.name())
        return list(process_list)

    def getProcessConnections(self):
        """
        获取进程使用的网络连接
        :return : 返回进程名字列表和进程对应的连接列表
        """
        process_name = set()
        process_conn = {}
        for process in psutil.process_iter():
            connections = process.connections()
            if connections:
                process_name.add(process.name())
                for con in connections:
                    if con.type == 1:  # TCP
                        protocol = 'TCP'
                    elif con.type == 2:  # UDP
                        protocol = 'UDP'
                    # 本地使用的IP及端口
                    laddr = "%s:%d" % (con.laddr[0], con.laddr[1])
                    if con.raddr:
                        raddr = "%s:%d" % (con.raddr[0], con.raddr[1])
                    elif con.family.value == 2:
                        # IPv4
                        raddr = "0.0.0.0:0"
                    elif con.family.value == 23:
                        # IPv6
                        raddr = "[::]:0"
                    else:
                        raddr = "*:*"
                    info = "%s\t%s\nLocal: %s\nRemote: %s\n" % (
                        protocol, con.status, laddr, raddr)
                    process_conn.setdefault(process.name(), set()).add(info)
        return list(process_name), process_conn

    def getPortList(self, process_name):
        """
        用于刷新某个进程的端口列表的函数
        将获得的端口列表设置到self.process_ports
        :parma process_name: 输入为程序的名字
        """
        ports = set()
        while not self.start_flag.is_set():
            ports.clear()
            for process in psutil.process_iter():
                connections = process.connections()
                if process.name() == process_name and connections:
                    for con in connections:
                        if con.laddr:
                            ports.add(con.laddr[1])
                        if con.raddr:
                            ports.add(con.raddr[1])
            if ports:
                self.process_ports = list(ports)
            else:
                # 进程已不存在
                self.window.stop()
                self.window.refresh_process()
                self.window.alert("进程%s已停止运行!" % process_name)

    def getConnections(self, pak):
        """
        获取应用的连接信息
        :parma pak: 数据包
        """
        try:
            src = pak.payload.src
            dst = pak.payload.dst
            length = len(pak)
            if src == dst:
                # 相同源地址和目的地址，可能为Land攻击
                self.window.alert("数据包源地址与目的地址相同, 疑为Land攻击!")
            elif len(pak.payload) > 65535:
                # IP数据包的最大长度大于64KB(即65535B), 若大于, 则疑为Ping of Death攻击
                self.window.alert("收到IP数据包长度大于64KB, 疑为Ping拒绝服务攻击!")
            else:
                protocol = pak.payload.payload.name
                if protocol != 'ICMP':
                    sport = pak.payload.payload.sport
                    dport = pak.payload.payload.dport
                    if sport in self.process_ports and dport in self.process_ports:
                        info = "%-7s%s:%d -> %s:%d%7d" % (protocol, src, sport,
                                                          dst, dport, length)
                        if protocol == 'TCP':
                            info += '%5s' % str(pak.payload.payload.flags)
                        self.window.conList.addItem(info)
                else:
                    # ICMP报文
                    self.window.conList.addItem(
                        "%-7s%s -> %s%7d" % (protocol, src, dst, length))
        except:
            pass

    def capture_packet(self):
        """
        设置过滤器, 只接收IP、IPv6、TCP、UDP
        """
        sniff(
            store=False,
            filter="(tcp or udp or icmp) and (ip6 or ip)",
            prn=lambda x: self.getConnections(x),
            stop_filter=lambda x: self.start_flag.is_set())

    def start(self, process_name):
        """
        开始对某一进程的流量监视
        :parma process_name: 进程的名字
        """
        # 开启刷新程序端口的线程
        self.start_flag.clear()
        self.window.conList.clear()
        Thread(
            target=self.getPortList, daemon=True,
            args=(process_name, )).start()
        Thread(target=self.capture_packet, daemon=True).start()

    def stop(self):
        """
        停止监测
        """
        self.start_flag.set()
