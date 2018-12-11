# -*- coding: utf-8 -*-

from PyQt5 import QtCore, QtGui, QtWidgets
from scapy.sendrecv import sr, sr1, srloop
import scapy
from scapy.layers.inet import *
import sys
import threading


"""获取控制台内容"""
class EmittingStream(QtCore.QObject):
    textWritten = QtCore.pyqtSignal(str)  # 定义一个发送str的信号

    def write(self, text):
        self.textWritten.emit(str(text))


class Ui_Form(object):
    Form = None

    def setupUi(self, Form):
        init_Ether = Ether()
        init_IP = IP()
        init_TCP = TCP()
        init_ICMP = ICMP()
        init_UDP = UDP()
        init_ARP = ARP()

        self.forged_packet = None
        Form.setWindowTitle("伪造数据包")
        Form.resize(600, 380)
        Form.setFixedSize(Form.width(), Form.height())
        self.horizontalLayoutWidget = QtWidgets.QWidget(Form)
        self.horizontalLayoutWidget.setGeometry(QtCore.QRect(0, 0, 600, 380))
        self.horizontalLayout = QtWidgets.QHBoxLayout(
            self.horizontalLayoutWidget)
        self.left = QtWidgets.QFrame(self.horizontalLayoutWidget)
        self.left.setFrameShape(QtWidgets.QFrame.StyledPanel)
        self.left.setFrameShadow(QtWidgets.QFrame.Raised)
        """左边菜单栏"""
        self.treeWidget = QtWidgets.QTreeWidget(self.left)
        self.treeWidget.setGeometry(QtCore.QRect(0, 0, 148, 379))
        self.treeWidget.setMidLineWidth(0)
        self.treeWidget.setSortingEnabled(False)
        self.treeWidget.clicked.connect(self.treeWidget_onclicked)

        font = QtGui.QFont()
        font.setFamily("Lucida Sans Typewriter")
        font.setPointSize(10)
        font9 = QtGui.QFont()
        font9.setPointSize(9)
        font11 = QtGui.QFont()
        font11.setPointSize(10)
        font14 = QtGui.QFont()
        font14.setPointSize(14)
        """Ether"""
        item_0 = QtWidgets.QTreeWidgetItem(self.treeWidget)
        item_0.setText(0, "Ether")
        item_0.setFont(0, font11)
        item_1 = QtWidgets.QTreeWidgetItem(item_0)
        item_1.setText(0, "ARP")
        item_1.setFont(0, font11)
        item_1 = QtWidgets.QTreeWidgetItem(item_0)
        item_1.setText(0, "IP")
        item_1.setFont(0, font11)

        item_2 = QtWidgets.QTreeWidgetItem(item_1)
        item_2.setText(0, "TCP")
        item_2.setFont(0, font11)

        item_2 = QtWidgets.QTreeWidgetItem(item_1)
        item_2.setText(0, "ICMP")
        item_2.setFont(0, font11)

        item_2 = QtWidgets.QTreeWidgetItem(item_1)
        item_2.setFont(0, font11)
        item_2.setText(0, "UDP")
        item_0 = QtWidgets.QTreeWidgetItem(self.treeWidget)
        item_0.setText(0, "发送")
        item_0.setFont(0, font11)
        item_0 = QtWidgets.QTreeWidgetItem(self.treeWidget)
        item_0.setText(0, "发收包详情")
        item_0.setFont(0, font11)
        self.treeWidget.expandAll()
        self.treeWidget.header().setVisible(False)
        self.horizontalLayout.addWidget(self.left)
        self.right = QtWidgets.QFrame(self.horizontalLayoutWidget)
        self.right.setFrameShape(QtWidgets.QFrame.StyledPanel)
        self.right.setFrameShadow(QtWidgets.QFrame.Raised)
        self.stackedWidget = QtWidgets.QStackedWidget(self.right)
        self.stackedWidget.setGeometry(QtCore.QRect(0, 0, 445, 380))

        self.Ether_page = QtWidgets.QWidget()

        self.EtherDst = QtWidgets.QLabel(self.Ether_page)
        self.EtherDst.setGeometry(QtCore.QRect(70, 90, 80, 12))
        self.EtherDst.setText("目标MAC地址：")
        self.EtherDst.setFont(font11)

        self.EtherDstEdit = QtWidgets.QLineEdit(self.Ether_page)
        self.EtherDstEdit.setText(init_Ether.dst)
        self.EtherDstEdit.setGeometry(QtCore.QRect(160, 90, 161, 21))

        self.EtherSrc = QtWidgets.QLabel(self.Ether_page)
        self.EtherSrc.setGeometry(QtCore.QRect(70, 150, 80, 12))
        self.EtherSrc.setText("源MAC地址：")
        self.EtherSrc.setFont(font11)

        self.EtherSrcEdit = QtWidgets.QLineEdit(self.Ether_page)
        self.EtherSrcEdit.setText(init_Ether.src)
        self.EtherSrcEdit.setGeometry(QtCore.QRect(160, 150, 161, 21))

        self.label_2 = QtWidgets.QLabel(self.Ether_page)
        self.label_2.setText("类型：")
        self.label_2.setGeometry(QtCore.QRect(90, 210, 54, 16))
        self.label_2.setFont(font11)

        self.EtherType = QtWidgets.QComboBox(self.Ether_page)
        self.EtherType.addItem("IPv4: 0x0800")
        self.EtherType.addItem("ARP:0x0806")
        self.EtherType.setGeometry(QtCore.QRect(140, 210, 161, 21))

        self.Ether_load = QtWidgets.QLineEdit(self.Ether_page)
        self.Ether_load.setPlaceholderText("请输入Ether协议载荷")
        self.Ether_load.setGeometry(QtCore.QRect(90, 250, 250, 21))
        """Ether转下一步按钮"""
        self.EtherNext = QtWidgets.QPushButton(self.Ether_page)
        self.EtherNext.setGeometry(QtCore.QRect(230, 300, 75, 23))
        self.EtherNext.setText("下一步")
        self.EtherNext.clicked.connect(self.EtherNext_onclicked)

        self.EtherSkip = QtWidgets.QPushButton(self.Ether_page)
        self.EtherSkip.setGeometry(QtCore.QRect(80, 300, 75, 23))
        self.EtherSkip.setText("跳过")
        self.EtherSkip.clicked.connect(
            lambda: self.stackedWidget.setCurrentIndex(1))

        self.label_14 = QtWidgets.QLabel(self.Ether_page)
        self.label_14.setGeometry(QtCore.QRect(150, 30, 151, 21))
        self.label_14.setText("Ether协议字段")
        self.label_14.setFont(font14)

        self.stackedWidget.addWidget(self.Ether_page)

        self.IP_page = QtWidgets.QWidget()
        self.label_3 = QtWidgets.QLabel(self.IP_page)
        self.label_3.setGeometry(QtCore.QRect(20, 60, 71, 16))
        self.label_3.setText("版本：")
        self.label_3.setFont(font11)
        self.IP_version = QtWidgets.QLineEdit(self.IP_page)
        """由于IPv6比较复杂，因此暂且只允许构造IPv4包"""
        self.IP_version.setDisabled(True)
        self.IP_version.setText('4')
        self.IP_version.setGeometry(QtCore.QRect(90, 60, 91, 20))
        self.IP_version.setFont(font9)

        self.label_4 = QtWidgets.QLabel(self.IP_page)
        self.label_4.setGeometry(QtCore.QRect(220, 60, 61, 21))
        self.label_4.setText("首部长度：")
        self.label_4.setFont(font11)
        self.IP_ihl = QtWidgets.QLineEdit(self.IP_page)
        self.IP_ihl.setText('0')
        self.IP_ihl.setGeometry(QtCore.QRect(280, 60, 101, 20))
        self.IP_ihl.setFont(font9)

        self.label_5 = QtWidgets.QLabel(self.IP_page)
        self.label_5.setGeometry(QtCore.QRect(20, 100, 61, 16))
        self.label_5.setText("服务类型：")
        self.label_5.setFont(font11)
        self.IP_tos = QtWidgets.QLineEdit(self.IP_page)
        self.IP_tos.setGeometry(QtCore.QRect(90, 100, 91, 20))
        self.IP_tos.setText(str(init_IP.tos))

        self.label_6 = QtWidgets.QLabel(self.IP_page)
        self.label_6.setGeometry(QtCore.QRect(220, 100, 61, 21))
        self.label_6.setText("总长度：")
        self.label_6.setFont(font11)

        self.IP_len = QtWidgets.QLineEdit(self.IP_page)
        self.IP_len.setText('0')
        self.IP_len.setGeometry(QtCore.QRect(280, 100, 101, 20))

        self.label_7 = QtWidgets.QLabel(self.IP_page)
        self.label_7.setGeometry(QtCore.QRect(20, 140, 61, 21))
        self.label_7.setText("标识符：")
        self.label_7.setFont(font11)

        self.IP_id = QtWidgets.QLineEdit(self.IP_page)
        self.IP_id.setGeometry(QtCore.QRect(90, 140, 91, 20))
        self.IP_id.setText(str(init_IP.id))

        self.label_8 = QtWidgets.QLabel(self.IP_page)
        self.label_8.setGeometry(QtCore.QRect(220, 140, 61, 21))
        self.label_8.setText("分片偏移：")
        self.label_8.setFont(font11)

        self.IP_frag = QtWidgets.QLineEdit(self.IP_page)
        self.IP_frag.setGeometry(QtCore.QRect(280, 140, 101, 20))
        self.IP_frag.setText(str(init_IP.frag))

        self.label_9 = QtWidgets.QLabel(self.IP_page)
        self.label_9.setGeometry(QtCore.QRect(20, 180, 61, 21))
        self.label_9.setText("生存时间：")
        self.label_9.setFont(font11)
        self.IP_ttl = QtWidgets.QLineEdit(self.IP_page)
        self.IP_ttl.setText(str(init_IP.ttl))
        self.IP_ttl.setGeometry(QtCore.QRect(90, 180, 91, 20))

        self.label_10 = QtWidgets.QLabel(self.IP_page)
        self.label_10.setGeometry(QtCore.QRect(220, 180, 61, 16))
        self.label_10.setText("协议：")
        self.label_10.setFont(font11)
        self.IP_proto = QtWidgets.QComboBox(self.IP_page)
        self.IP_proto.addItem("tcp")
        self.IP_proto.addItem("icmp")
        self.IP_proto.addItem("udp")
        self.IP_proto.setGeometry(QtCore.QRect(280, 180, 101, 20))

        self.label_11 = QtWidgets.QLabel(self.IP_page)
        self.label_11.setText("校验和：")
        self.label_11.setGeometry(QtCore.QRect(20, 220, 61, 16))
        self.label_11.setFont(font11)
        self.IP_chksum = QtWidgets.QLineEdit(self.IP_page)
        self.IP_chksum.setGeometry(QtCore.QRect(90, 220, 91, 20))
        self.IP_chksum.setText(init_IP.chksum)

        self.label_12 = QtWidgets.QLabel(self.IP_page)
        self.label_12.setText("源IP地址：")
        self.label_12.setGeometry(QtCore.QRect(20, 260, 54, 12))
        self.label_12.setFont(font11)
        self.IP_src = QtWidgets.QLineEdit(self.IP_page)
        self.IP_src.setGeometry(QtCore.QRect(80, 260, 111, 20))
        self.IP_src.setText(init_IP.src)

        self.label_13 = QtWidgets.QLabel(self.IP_page)
        self.label_13.setText("目的IP地址：")
        self.label_13.setGeometry(QtCore.QRect(220, 260, 70, 16))
        self.label_13.setFont(font11)
        self.IP_dst = QtWidgets.QLineEdit(self.IP_page)
        self.IP_dst.setGeometry(QtCore.QRect(300, 260, 131, 20))
        self.IP_dst.setText(init_IP.dst)

        self.IP_load = QtWidgets.QLineEdit(self.IP_page)
        self.IP_load.setPlaceholderText("请输入IP协议载荷")
        self.IP_load.setGeometry(QtCore.QRect(90, 295, 250, 20))
        """IP下一步按钮"""
        self.IP_Next_button = QtWidgets.QPushButton(self.IP_page)
        self.IP_Next_button.setText("下一步")
        self.IP_Next_button.setGeometry(QtCore.QRect(150, 320, 75, 23))
        self.IP_Next_button.clicked.connect(self.IP_Next_button_clicked)
        """IP跳过按钮"""
        self.IP_skip_button = QtWidgets.QPushButton(self.IP_page)
        self.IP_skip_button.setText("跳过")
        self.IP_skip_button.setGeometry(QtCore.QRect(300, 320, 75, 23))
        self.IP_skip_button.clicked.connect(
            lambda: self.treeWidget.setCurrentIndex(2))

        self.label = QtWidgets.QLabel(self.IP_page)
        self.label.setGeometry(QtCore.QRect(150, 20, 131, 21))
        self.label.setText("IP协议字段")
        self.label.setFont(font14)
        self.stackedWidget.addWidget(self.IP_page)
        self.TCP_page = QtWidgets.QWidget()
        """TCP页面"""
        self.label_15 = QtWidgets.QLabel(self.TCP_page)
        self.label_15.setText("TCP协议字段")
        self.label_15.setGeometry(QtCore.QRect(150, 30, 111, 31))
        self.label_15.setFont(font14)

        self.label_16 = QtWidgets.QLabel(self.TCP_page)
        self.label_16.setGeometry(QtCore.QRect(20, 70, 51, 16))
        self.label_16.setText("源端口：")
        self.label_16.setFont(font11)

        self.TCP_sport = QtWidgets.QLineEdit(self.TCP_page)
        self.TCP_sport.setText(str(init_TCP.sport))
        self.TCP_sport.setGeometry(QtCore.QRect(80, 70, 113, 20))

        self.label_17 = QtWidgets.QLabel(self.TCP_page)
        self.label_17.setText("目的端口：")
        self.label_17.setGeometry(QtCore.QRect(230, 70, 61, 21))
        self.label_17.setFont(font11)
        self.TCP_dport = QtWidgets.QLineEdit(self.TCP_page)
        self.TCP_dport.setText(str(init_TCP.dport))
        self.TCP_dport.setGeometry(QtCore.QRect(290, 70, 113, 20))

        self.label_18 = QtWidgets.QLabel(self.TCP_page)
        self.label_18.setText("序列号：")
        self.label_18.setGeometry(QtCore.QRect(20, 120, 51, 16))
        self.label_18.setFont(font11)
        self.TCP_seq = QtWidgets.QLineEdit(self.TCP_page)
        self.TCP_seq.setText("0")
        self.TCP_seq.setGeometry(QtCore.QRect(80, 120, 113, 20))

        self.label_19 = QtWidgets.QLabel(self.TCP_page)
        self.label_19.setText("确认号：")
        self.label_19.setGeometry(QtCore.QRect(230, 120, 54, 12))
        self.label_19.setFont(font11)
        self.TCP_ack = QtWidgets.QLineEdit(self.TCP_page)
        self.TCP_ack.setText('0')
        self.TCP_ack.setGeometry(QtCore.QRect(290, 120, 113, 20))

        self.label_20 = QtWidgets.QLabel(self.TCP_page)
        self.label_20.setText("偏移量：")
        self.label_20.setGeometry(QtCore.QRect(20, 170, 81, 16))
        self.label_20.setFont(font11)
        self.TCP_reserved = QtWidgets.QLineEdit(self.TCP_page)
        self.TCP_reserved.setText('0')
        self.TCP_reserved.setGeometry(QtCore.QRect(100, 170, 91, 20))

        self.label_21 = QtWidgets.QLabel(self.TCP_page)
        self.label_21.setText('窗口：')
        self.label_21.setGeometry(QtCore.QRect(230, 170, 61, 16))
        self.label_21.setFont(font11)
        self.TCP_window = QtWidgets.QLineEdit(self.TCP_page)
        self.TCP_window.setText(str(init_TCP.window))
        self.TCP_window.setGeometry(QtCore.QRect(290, 170, 113, 20))

        self.label_22 = QtWidgets.QLabel(self.TCP_page)
        self.label_22.setText("校验和：")
        self.label_22.setGeometry(QtCore.QRect(20, 220, 61, 16))
        self.label_22.setFont(font11)
        self.TCP_chksum = QtWidgets.QLineEdit(self.TCP_page)
        self.TCP_chksum.setText(str(init_TCP.chksum))
        self.TCP_chksum.setGeometry(QtCore.QRect(80, 220, 111, 20))

        self.label_23 = QtWidgets.QLabel(self.TCP_page)
        self.label_23.setText("紧急指针：")
        self.label_23.setGeometry(QtCore.QRect(230, 220, 61, 16))
        self.label_23.setFont(font11)
        self.TCP_urgptr = QtWidgets.QComboBox(self.TCP_page)
        self.TCP_urgptr.addItem('0')
        self.TCP_urgptr.addItem('1')
        self.TCP_urgptr.setGeometry(QtCore.QRect(290, 220, 113, 20))

        self.TCP_load = QtWidgets.QLineEdit(self.TCP_page)
        self.TCP_load.setPlaceholderText("请输入TCP协议载荷")
        self.TCP_load.setGeometry(QtCore.QRect(90, 270, 250, 16))

        self.TCP_send = QtWidgets.QPushButton(self.TCP_page)
        self.TCP_send.setText("确认")
        self.TCP_send.clicked.connect(self.TCP_send_clicked)
        self.TCP_send.setGeometry(QtCore.QRect(150, 320, 75, 23))
        self.stackedWidget.addWidget(self.TCP_page)

        """ICMP协议页面"""
        self.ICMP_page = QtWidgets.QWidget()
        self.label_29 = QtWidgets.QLabel(self.ICMP_page)
        self.label_29.setGeometry(QtCore.QRect(140, 20, 131, 21))
        self.label_29.setText("ICMP协议字段")
        self.label_29.setFont(font14)

        self.label_30 = QtWidgets.QLabel(self.ICMP_page)
        self.label_30.setGeometry(QtCore.QRect(80, 80, 54, 16))
        self.label_30.setText("类型:")
        self.label_30.setFont(font11)

        self.ICMP_type = QtWidgets.QLineEdit(self.ICMP_page)
        self.ICMP_type.setText(str(init_ICMP.type))
        self.ICMP_type.setGeometry(QtCore.QRect(140, 80, 113, 20))

        self.label_31 = QtWidgets.QLabel(self.ICMP_page)
        self.label_31.setText("代码：")
        self.label_31.setGeometry(QtCore.QRect(80, 130, 54, 12))
        self.label_31.setFont(font11)

        self.ICMP_code = QtWidgets.QLineEdit(self.ICMP_page)
        self.ICMP_code.setText(str(init_ICMP.code))
        self.ICMP_code.setGeometry(QtCore.QRect(140, 130, 113, 20))

        self.label_32 = QtWidgets.QLabel(self.ICMP_page)
        self.label_32.setText("校验和：")
        self.label_32.setGeometry(QtCore.QRect(80, 180, 61, 16))
        self.label_32.setFont(font11)

        self.ICMP_chksum = QtWidgets.QLineEdit(self.ICMP_page)
        self.ICMP_chksum.setText(init_ICMP.chksum)
        self.ICMP_chksum.setGeometry(QtCore.QRect(140, 180, 113, 20))

        self.label_33 = QtWidgets.QLabel(self.ICMP_page)
        self.label_33.setText("id:")
        self.label_33.setGeometry(QtCore.QRect(80, 230, 54, 12))
        self.label_33.setFont(font11)
        self.ICMP_id = QtWidgets.QLineEdit(self.ICMP_page)
        self.ICMP_id.setText(str(init_ICMP.id))
        self.ICMP_id.setGeometry(QtCore.QRect(140, 230, 113, 20))

        self.label_34 = QtWidgets.QLabel(self.ICMP_page)
        self.label_34.setText("序列号：")
        self.label_34.setGeometry(QtCore.QRect(80, 270, 54, 16))
        self.label_34.setFont(font11)
        self.ICMP_seq = QtWidgets.QLineEdit(self.ICMP_page)
        self.ICMP_seq.setGeometry(QtCore.QRect(140, 270, 113, 20))
        self.ICMP_seq.setText(str(init_ICMP.seq))

        self.ICMP_load = QtWidgets.QLineEdit(self.ICMP_page)
        self.ICMP_load.setPlaceholderText("请输入ICMP协议载荷")
        self.ICMP_load.setGeometry(QtCore.QRect(90, 305, 250, 20))

        self.ICMP_send_button = QtWidgets.QPushButton(self.ICMP_page)
        self.ICMP_send_button.setText("发送")
        self.ICMP_send_button.clicked.connect(self.ICMP_send_button_clicked)
        self.ICMP_send_button.setGeometry(QtCore.QRect(150, 335, 75, 23))
        self.stackedWidget.addWidget(self.ICMP_page)


        """UDP协议页面"""
        self.UDP_page = QtWidgets.QWidget()
        self.label_24 = QtWidgets.QLabel(self.UDP_page)
        self.label_24.setGeometry(QtCore.QRect(140, 40, 121, 21))
        self.label_24.setText("UDP协议字段")
        self.label_24.setFont(font14)
        self.label_25 = QtWidgets.QLabel(self.UDP_page)
        self.label_25.setGeometry(QtCore.QRect(80, 100, 51, 16))
        self.label_25.setText("源端口：")
        self.label_25.setFont(font11)
        self.UDP_sport = QtWidgets.QLineEdit(self.UDP_page)
        self.UDP_sport.setText(str(init_UDP.sport))
        self.UDP_sport.setGeometry(QtCore.QRect(160, 100, 121, 20))

        self.label_26 = QtWidgets.QLabel(self.UDP_page)
        self.label_26.setGeometry(QtCore.QRect(80, 160, 51, 16))
        self.label_26.setText("目的端口：")
        self.label_26.setFont(font11)
        self.UDP_dport = QtWidgets.QLineEdit(self.UDP_page)
        self.UDP_dport.setText(str(init_UDP.dport))
        self.UDP_dport.setGeometry(QtCore.QRect(160, 160, 121, 20))

        self.label_27 = QtWidgets.QLabel(self.UDP_page)
        self.label_27.setGeometry(QtCore.QRect(80, 210, 54, 12))
        self.label_27.setText("长度：")
        self.label_27.setFont(font11)
        self.UDP_len = QtWidgets.QLineEdit(self.UDP_page)
        self.UDP_len.setText('0')
        self.UDP_len.setGeometry(QtCore.QRect(160, 210, 121, 20))

        self.label_28 = QtWidgets.QLabel(self.UDP_page)
        self.label_28.setGeometry(QtCore.QRect(80, 260, 61, 16))
        self.label_28.setText("校验和：")
        self.label_28.setFont(font11)
        self.UDP_chksum = QtWidgets.QLineEdit(self.UDP_page)
        self.UDP_chksum.setText(init_UDP.chksum)
        self.UDP_chksum.setGeometry(QtCore.QRect(160, 260, 121, 20))

        self.UDP_load = QtWidgets.QLineEdit(self.UDP_page)
        self.UDP_load.setPlaceholderText("请输入UDP协议载荷")
        self.UDP_load.setGeometry(QtCore.QRect(80, 300, 260, 20))

        self.UDP_send = QtWidgets.QPushButton(self.UDP_page)
        self.UDP_send.setText("发送")
        self.UDP_send.clicked.connect(self.UDP_send_click)
        self.UDP_send.setGeometry(QtCore.QRect(170, 325, 75, 23))
        self.stackedWidget.addWidget(self.UDP_page)

        """ARP协议页面"""
        self.ARP_page = QtWidgets.QWidget()
        self.label_35 = QtWidgets.QLabel(self.ARP_page)
        self.label_35.setGeometry(QtCore.QRect(150, 40, 131, 31))
        self.label_35.setText("ARP协议字段")
        self.label_35.setFont(font14)

        self.label_36 = QtWidgets.QLabel(self.ARP_page)
        self.label_36.setGeometry(QtCore.QRect(30, 90, 61, 16))
        self.label_36.setText("硬件类型：")
        self.label_36.setFont(font11)
        self.ARP_hwtype = QtWidgets.QLineEdit(self.ARP_page)
        self.ARP_hwtype.setText(str(init_ARP.hwtype))
        self.ARP_hwtype.setGeometry(QtCore.QRect(90, 90, 113, 20))

        self.label_37 = QtWidgets.QLabel(self.ARP_page)
        self.label_37.setGeometry(QtCore.QRect(230, 90, 51, 16))
        self.label_37.setText("协议类型：")
        self.label_37.setFont(font11)
        self.ARP_ptype = QtWidgets.QLineEdit(self.ARP_page)
        self.ARP_ptype.setText(str(init_ARP.ptype))
        self.ARP_ptype.setGeometry(QtCore.QRect(290, 90, 113, 20))

        self.label_38 = QtWidgets.QLabel(self.ARP_page)
        self.label_38.setGeometry(QtCore.QRect(10, 140, 80, 12))
        self.label_38.setText("硬件地址长度：")
        self.label_38.setFont(font11)
        self.ARP_hwlen = QtWidgets.QLineEdit(self.ARP_page)
        self.ARP_hwlen.setText(str(init_ARP.hwlen))
        self.ARP_hwlen.setGeometry(QtCore.QRect(90, 140, 113, 20))

        self.label_39 = QtWidgets.QLabel(self.ARP_page)
        self.label_39.setGeometry(QtCore.QRect(230, 140, 51, 16))
        self.label_39.setText("协议地址长度：")
        self.label_39.setFont(font11)
        self.ARP_plen = QtWidgets.QLineEdit(self.ARP_page)
        self.ARP_plen.setText(str(init_ARP.plen))
        self.ARP_plen.setGeometry(QtCore.QRect(300, 140, 113, 20))

        self.label_40 = QtWidgets.QLabel(self.ARP_page)
        self.label_40.setGeometry(QtCore.QRect(30, 180, 51, 16))
        self.label_40.setText("op:")
        self.label_40.setFont(font11)
        self.ARP_op = QtWidgets.QLineEdit(self.ARP_page)
        self.ARP_op.setText(str(init_ARP.op))
        self.ARP_op.setGeometry(QtCore.QRect(90, 180, 113, 20))

        self.label_41 = QtWidgets.QLabel(self.ARP_page)
        self.label_41.setText("源以太网地址：")
        self.label_41.setGeometry(QtCore.QRect(210, 180, 85, 12))
        self.label_41.setFont(font11)
        self.ARP_hwsrc = QtWidgets.QLineEdit(self.ARP_page)
        self.ARP_hwsrc.setGeometry(QtCore.QRect(310, 180, 113, 20))
        self.ARP_hwsrc.setText(init_ARP.hwsrc)

        self.label_42 = QtWidgets.QLabel(self.ARP_page)
        self.label_42.setGeometry(QtCore.QRect(20, 220, 60, 16))
        self.label_42.setText("源IP地址：")
        self.label_42.setFont(font11)
        self.ARP_psrc = QtWidgets.QLineEdit(self.ARP_page)
        self.ARP_psrc.setText(init_ARP.psrc)
        self.ARP_psrc.setGeometry(QtCore.QRect(90, 220, 113, 20))

        self.label_43 = QtWidgets.QLabel(self.ARP_page)
        self.label_43.setGeometry(QtCore.QRect(210, 220, 90, 12))
        self.label_43.setText("目的以太网地址：")
        self.label_43.setFont(font11)
        self.ARP_hwdst = QtWidgets.QLineEdit(self.ARP_page)
        self.ARP_hwdst.setText(init_ARP.hwdst)
        self.ARP_hwdst.setGeometry(QtCore.QRect(310, 220, 113, 20))

        self.label_44 = QtWidgets.QLabel(self.ARP_page)
        self.label_44.setGeometry(QtCore.QRect(30, 260, 65, 16))
        self.label_44.setText("目的IP地址：")
        self.label_44.setFont(font11)
        self.ARP_pdst = QtWidgets.QLineEdit(self.ARP_page)
        self.ARP_pdst.setText(init_ARP.pdst)
        self.ARP_pdst.setGeometry(QtCore.QRect(110, 260, 113, 20))

        self.ARP_load = QtWidgets.QLineEdit(self.ARP_page)
        self.ARP_load.setPlaceholderText("请输入ARP协议载荷")
        self.ARP_load.setGeometry(QtCore.QRect(80, 295, 260, 20))

        self.ARP_send = QtWidgets.QPushButton(self.ARP_page)
        self.ARP_send.setText("发送")
        self.ARP_send.clicked.connect(self.ARP_send_click)
        self.ARP_send.setGeometry(QtCore.QRect(160, 320, 75, 23))
        self.stackedWidget.addWidget(self.ARP_page)
        self.horizontalLayout.addWidget(self.right)
        self.horizontalLayout.setStretch(0, 1)
        self.horizontalLayout.setStretch(1, 3)

        """确认页面"""
        self.page = QtWidgets.QWidget()
        self.packet_browser = QtWidgets.QTextBrowser(self.page)
        self.packet_browser.setFont(font)
        self.packet_browser.setGeometry(QtCore.QRect(60, 80, 351, 211))

        self.label_45 = QtWidgets.QLabel(self.page)
        self.label_45.setGeometry(QtCore.QRect(60, 20, 300, 21))
        self.label_45.setText("您已构造的包如下，请选择发包方式并且是否确认发送：")

        """选择发送方式"""
        self.choose_way = QtWidgets.QComboBox(self.page)
        self.choose_way.setFont(font)
        self.choose_way.setGeometry(QtCore.QRect(60, 45, 200, 23))
        self.choose_way.addItem("在第三层发送，无接收")
        self.choose_way.addItem("在第二层发送，无接收")
        self.choose_way.addItem("在第三层发送，有接收")
        self.choose_way.addItem("在第三层发送，只接收第一个")
        self.choose_way.addItem("在第三层工作")

        self.send_button = QtWidgets.QPushButton(self.page)
        self.send_button.setGeometry(QtCore.QRect(100, 320, 75, 23))
        self.send_button.setText("发送")
        self.send_button.clicked.connect(self.send_button_click)
        self.cancel_button = QtWidgets.QPushButton(self.page)
        self.cancel_button.setGeometry(QtCore.QRect(260, 320, 75, 23))
        self.cancel_button.setText("取消")
        self.cancel_button.clicked.connect(self.cancel_button_click)
        self.stackedWidget.addWidget(self.page)
        """输出页面"""
        self.output_page = QtWidgets.QWidget()
        self.output_page.setFont(font)
        self.output_browser = QtWidgets.QTextBrowser(self.output_page)
        self.output_browser.setGeometry(QtCore.QRect(10, 10, 425, 360))
        # 下面将输出重定向到textEdit中
        sys.stdout = EmittingStream(textWritten=self.outputWritten)
        sys.stderr = EmittingStream(textWritten=self.outputWritten)
        self.stackedWidget.addWidget(self.output_page)

        self.stackedWidget.setCurrentIndex(0)
        QtCore.QMetaObject.connectSlotsByName(Form)

    #页面索引
    protcol_index = {
        "Ether": 0,
        "IP": 1,
        "tcp": 2,
        "icmp": 3,
        "udp": 4,
        "TCP": 2,
        "ICMP": 3,
        "UDP": 4,
        "ARP": 5,
        "发送": 6,
        "发收包详情": 7
    }

    flag = 0

    def treeWidget_onclicked(self):
        choose = self.treeWidget.currentItem().text(0)
        now_index = self.protcol_index[choose]
        self.stackedWidget.setCurrentIndex(now_index)

    """构造Ether包"""
    def EtherNext_onclicked(self):
        NextProtocal = self.EtherType.currentText()
        if "IP" in NextProtocal:
            self.stackedWidget.setCurrentIndex(1)
        else:
            self.stackedWidget.setCurrentIndex(5)
        self.forged_packet = Ether(
            src=self.EtherSrcEdit.text(), dst=self.EtherDstEdit.text())
        if self.Ether_load.text() is not "":
            self.forged_packet = self.forged_packet/self.Ether_load.text()
        self.flag = 1

    """构造IP包"""
    def IP_Next_button_clicked(self):
        choose = self.IP_proto.currentText()
        self.stackedWidget.setCurrentIndex(self.protcol_index[choose])
        temp = IP(
            ihl=int(self.IP_ihl.text()),
            tos=int(self.IP_tos.text()),
            len=int(self.IP_len.text()),
            id=int(self.IP_id.text()),
            frag=int(self.IP_frag.text()),
            ttl=int(self.IP_ttl.text()),
            chksum=self.IP_chksum.text(),
            src=self.IP_src.text(),
            dst=self.IP_dst.text())
        if self.flag == 1:
            self.forged_packet = self.forged_packet / temp
        else:
            self.forged_packet = temp
            self.flag = 1
        if self.IP_load.text() is not "":
            self.forged_packet = self.forged_packet/self.IP_load.text()

    """构造TCP包"""
    def TCP_send_clicked(self):
        self.stackedWidget.setCurrentIndex(6)
        temp = TCP(
            sport=int(self.TCP_sport.text()),
            dport=int(self.TCP_dport.text()),
            seq=int(self.TCP_seq.text()),
            ack=int(self.TCP_ack.text()),
            reserved=int(self.TCP_reserved.text()),
            window=int(self.TCP_window.text()),
            chksum=self.TCP_chksum.text(),
            urgptr=int(self.TCP_urgptr.currentText()))
        if self.flag == 1:
            self.forged_packet = self.forged_packet / temp
        else:
            self.forged_packet = temp
            flag = 1
        if self.TCP_load.text() is not "":
            self.forged_packet = self.forged_packet/self.TCP_load.text()
        self.packet_browser.setText(self.forged_packet.show(dump=True))

    """构造ICMP包"""
    def ICMP_send_button_clicked(self):
        self.stackedWidget.setCurrentIndex(6)
        temp = ICMP(
            type=int(self.ICMP_type.text()),
            code=int(self.ICMP_code.text()),
            chksum=self.ICMP_chksum.text(),
            id=int(self.ICMP_id.text()),
            seq=int(self.ICMP_seq.text()))
        if self.flag == 1:
            self.forged_packet = self.forged_packet / temp
        else:
            self.forged_packet = temp
            flag = 1
        if self.ICMP_load.text() is not "":
            self.forged_packet = self.forged_packet/self.ICMP_load.text()
        self.packet_browser.setText(self.forged_packet.show(dump=True))

    """构造UDP包"""
    def UDP_send_click(self):
        self.stackedWidget.setCurrentIndex(6)
        temp = UDP(
            sport=int(self.UDP_sport.text()),
            dport=int(self.UDP_dport.text()),
            chksum=self.UDP_chksum.text(),
            len=int(self.UDP_len.text()))
        if self.flag == 1:
            self.forged_packet = self.forged_packet / temp
        else:
            self.forged_packet = temp
            self.flag = 1
        if self.UDP_load.text() is not "":
            self.forged_packet = self.forged_packet/self.UDP_load.text()
        self.packet_browser.setText(self.forged_packet.show(dump=True))

    """构造ARP包"""
    def ARP_send_click(self):
        self.stackedWidget.setCurrentIndex(6)
        temp = ARP(
            hwtype=int(self.ARP_hwtype.text()),
            ptype=int(self.ARP_ptype.text()),
            hwlen=int(self.ARP_hwlen.text()),
            plen=int(self.ARP_plen.text()),
            op=int(self.ARP_op.text()),
            hwsrc=self.ARP_hwsrc.text(),
            psrc=self.ARP_psrc.text(),
            hwdst=self.ARP_hwdst.text(),
            pdst=self.ARP_pdst.text())
        if self.flag == 1:
            self.forged_packet = self.forged_packet / temp
        else:
            self.forged_packet = temp
            self.flag = 1
        if self.ARP_load.text() is not "":
            self.forged_packet = self.forged_packet/self.ARP_load.text()
        self.packet_browser.setText(self.forged_packet.show(dump=True))

    """发送包"""
    def send_button_click(self):
        if self.flag == 1:
            self.stackedWidget.setCurrentIndex(7)
            self.output_browser.clear()
            self.flag = 0
            t1 = threading.Thread(target=self.send_packet)
            t1.start()
        else:
            QtWidgets.QMessageBox.warning(self.Form, "警告", "您还没有构造数据包！")
            return

    """发包方式"""
    def send_packet(self):
        choose_way = self.choose_way.currentIndex()
        if choose_way == 0:
            send(self.forged_packet)
        elif choose_way == 1:
            sendp(self.forged_packet)
        elif choose_way == 2:
            sr(self.forged_packet)
        elif choose_way == 2:
            sr1(self.forged_packet)
        elif choose_way == 3:
            srloop(self.forged_packet)



    def cancel_button_click(self):
        exit()

    # 接收信号str的信号槽
    def outputWritten(self, text):
        cursor = self.output_browser.textCursor()
        cursor.movePosition(QtGui.QTextCursor.End)
        cursor.insertText(text)
        self.output_browser.setTextCursor(cursor)
        self.output_browser.ensureCursorVisible()


def startForged():
    app = QtWidgets.QApplication(sys.argv)
    widget = QtWidgets.QWidget()
    ui = Ui_Form()
    ui.setupUi((widget))
    widget.show()
    app.exec_()

if __name__ == '__main__':
    startForged()
