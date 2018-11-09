# -*- coding: utf-8 -*-
from time import time

start = time()

import sys
from PyQt5.QtWidgets import *
from PyQt5.QtGui import *
from PyQt5.QtCore import *
from get_nic import get_nic_list
from Capture import Core
# 使用matplotlib绘制柱状图
import numpy as np
import matplotlib.pyplot as plt

# 设置全局字体，以支持中文
plt.rcParams['font.sans-serif'] = ['SimHei']
# 解决‘-’表现为方块的问题
plt.rcParams['axes.unicode_minus'] = False
ColumnWidth = [110,160,160,110,110,300]
FrameLength_List = []
FrameList = []
platform, netcards = get_nic_list()
keys = list(netcards.keys())

class Ui_MainWindow(QMainWindow):
    #核心
    core = None
    this_MainWindow = None
    notSelected = True
    # info_tableView_model = QStandardItemModel()   #数据模型

    def setupUi(self):
        self.setWindowTitle("NetworkCap")
        self.setObjectName("MainWindow")
        self.resize(950, 580)
        icon = QIcon()
        icon.addPixmap(QPixmap("img/shark.jpg"), QIcon.Normal, QIcon.Off)
        self.setWindowIcon(icon)
        self.setIconSize(QSize(20, 20))

        #背景图片
        window_pale = QPalette()
        window_pale.setBrush(self.backgroundRole(), QBrush(QPixmap("img/Whale.jpg")))
        self.setPalette(window_pale)

        self.opacityEffect = QGraphicsOpacityEffect()
        self.opacityEffect.setOpacity(0.5)

        self.centralWidget = QWidget(self)
        self.centralWidget.setObjectName("centralWidget")

        #栅栏布局，使得窗口自适应
        self.gridLayout = QGridLayout(self.centralWidget)
        self.gridLayout.setContentsMargins(0, 0, 0, 0)
        self.gridLayout.setSpacing(6)
        self.gridLayout.setObjectName("gridLayout")

        #顶部控件布局
        self.horizontalLayout = QHBoxLayout()
        self.horizontalLayout.setContentsMargins(10, 2, 10, 1)
        self.horizontalLayout.setSpacing(20)
        self.horizontalLayout.setObjectName("horizontalLayout")

        #三个显示区布局
        self.verticalLayout = QVBoxLayout()
        self.verticalLayout.setContentsMargins(10, 0, 3, 10)
        self.verticalLayout.setSpacing(6)
        self.verticalLayout.setObjectName("verticalLayout")

        #初始主窗口字体
        font = QFont()
        font.setFamily("Arial")
        font.setPointSize(11)

        #数据包显示框                                                #********把tableview换成treewidget
        self.info_tree = QTreeWidget(self.centralWidget)
        self.info_tree.setObjectName("info_tree")
        self.info_tree.setFrameStyle(QFrame.Box | QFrame.Plain)
        # self.info_tree.setHeaderHidden(True)
        self.info_tree.setAutoScroll(True)
        self.info_tree.setRootIsDecorated(False)
        self.info_tree.setFont(font)
        self.info_tree.setColumnCount(7)    #设置表格为7列
        #设置表头
        self.info_tree.headerItem().setText(0, "No.")
        self.info_tree.headerItem().setText(1, "Time")
        self.info_tree.headerItem().setText(2, "Source")
        self.info_tree.headerItem().setText(3, "Destination")
        self.info_tree.headerItem().setText(4, "Protocol")
        self.info_tree.headerItem().setText(5, "Length")
        self.info_tree.headerItem().setText(6, "Info")

        self.info_tree.setSelectionBehavior(QTreeWidget.SelectRows)        #设置选中时为整行选中
        self.info_tree.setSelectionMode(QTreeWidget.SingleSelection)        #设置只能选中一行

        self.info_tree.clicked.connect(self.on_tableview_clicked)

        #数据包详细内容显示框
        self.treeWidget =  QTreeWidget(self.centralWidget)
        self.treeWidget.setAutoScroll(True)
        self.treeWidget.setTextElideMode(Qt.ElideMiddle)
        self.treeWidget.setObjectName("treeWidget")
        self.treeWidget.header().setSortIndicatorShown(False)
        self.treeWidget.header().setStretchLastSection(True)
        self.treeWidget.header().hide()
        self.treeWidget.setFont(font)
        # 设为只有一列
        self.treeWidget.setColumnCount(1)
        self.treeWidget.setFrameStyle(QFrame.Box | QFrame.Plain)


        #hex显示区域
        self.hexBrowser = QTextBrowser(self.centralWidget)
        self.hexBrowser.setObjectName("hexText")
        self.hexBrowser.setText("")
        self.hexBrowser.setFont(font)
        self.hexBrowser.setFrameStyle(QFrame.Box | QFrame.Plain)


        # 允许用户通过拖动三个显示框的边界来控制子组件的大小
        self.splitter = QSplitter(Qt.Vertical)
        self.splitter.addWidget(self.info_tree)
        self.splitter.addWidget(self.treeWidget)
        self.splitter.addWidget(self.hexBrowser)
        self.verticalLayout.addWidget(self.splitter)

        self.gridLayout.addLayout(self.verticalLayout, 1, 0, 1, 1)


        #过滤器
        self.Filer = QLineEdit(self.centralWidget)
        self.Filer.setEnabled(True)
        self.Filer.setInputMask("")
        self.Filer.setObjectName("Filer")
        self.Filer.setPlaceholderText("Apply a capture filter … ")
        self.horizontalLayout.addWidget(self.Filer)


        #过滤器显示按钮
        self.FilerButton = QPushButton(self.centralWidget)
        self.FilerButton.setText("开始")
        icon1 = QIcon()
        icon1.addPixmap(QPixmap("img/go.png"), QIcon.Normal, QIcon.Off)
        self.FilerButton.setIcon(icon1)
        self.FilerButton.setIconSize(QSize(20, 20))
        self.FilerButton.setObjectName("FilerButton")
        self.FilerButton.clicked.connect(self.on_start_action_clicked)
        self.horizontalLayout.addWidget(self.FilerButton)


        """
           网卡选择框
        """
        self.choose_nicbox = QComboBox(self.centralWidget)
        self.choose_nicbox.setObjectName("choose_nicbox")
        self.horizontalLayout.addWidget(self.choose_nicbox)

        self.horizontalLayout.setStretch(0, 8)
        self.horizontalLayout.setStretch(1, 1)
        self.horizontalLayout.setStretch(2, 4)
        self.gridLayout.addLayout(self.horizontalLayout, 0, 0, 1, 1)

        row_num = len(keys)
        self.choose_nicbox.addItem("All")
        for i in range(row_num):
            self.choose_nicbox.addItem(keys[i])


        #self.choose_nicbox.activated[str].connect(self.onActivated)

        self.info_tree.raise_()
        self.treeWidget.raise_()
        self.Filer.raise_()
        self.FilerButton.raise_()
        self.choose_nicbox.raise_()
        self.hexBrowser.raise_()

        self.setCentralWidget(self.centralWidget)




        """
           顶部菜单栏
        """
        self.menuBar = QMenuBar(self)
        self.menuBar.setGeometry(QRect(0, 0, 953, 23))
        self.menuBar.setAccessibleName("")
        self.menuBar.setDefaultUp(True)
        self.menuBar.setObjectName("menuBar")
        self.menu_F = QMenu(self.menuBar)
        self.menu_F.setTitle("文件(F)")
        self.menu_F.setObjectName("menu_F")

        self.edit_menu = QMenu(self.menuBar)
        self.edit_menu.setTitle("编辑(E)")
        self.edit_menu.setObjectName("edit_menu")

        self.capture_menu = QMenu(self.menuBar)
        self.capture_menu.setTitle("捕获(C)")
        self.capture_menu.setObjectName("capture_menu")


        self.menu_H = QMenu(self.menuBar)
        self.menu_H.setTitle("帮助(H)")
        self.menu_H.setObjectName("menu_H")

        self.menu_Analysis = QMenu(self.menuBar)
        self.menu_Analysis.setTitle("分析(A)")
        self.menu_Analysis.setObjectName("menu_Analysis")

        self.menu_Statistic = QMenu(self.menuBar)
        self.menu_Statistic.setTitle("统计(S)")
        self.menu_Statistic.setObjectName("menu_Statistic")
        self.setMenuBar(self.menuBar)

        #顶部工具栏
        self.mainToolBar = QToolBar(self)
        self.mainToolBar.setObjectName("mainToolBar")
        self.addToolBar(Qt.TopToolBarArea, self.mainToolBar)
        self.statusBar = QStatusBar(self)
        #self.statusBar.
        self.statusBar.setObjectName("statusBar")
        self.setStatusBar(self.statusBar)

        #字体设置键
        font_set = QAction(self)
        font_set.setObjectName("font_set")
        font_set.setText("主窗口字体")
        font_set.triggered.connect(self.on_font_set_clicked)

        #背景图片设置
        change_border = QAction(self)
        change_border.setText("背景图片")
        change_border.setObjectName("change_border")
        change_border.triggered.connect(self.on_change_border_clicked)

        #开始键
        self.start_action = QAction(self)
        icon2 = QIcon()
        icon2.addPixmap(QPixmap("img/start.png"), QIcon.Normal, QIcon.Off)
        self.start_action.setIcon(icon2)
        self.start_action.setText("开始")
        self.start_action.setObjectName("start_action")
        self.start_action.setCheckable(True)
        self.start_action.triggered.connect(self.on_start_action_clicked)

        #停止键
        self.stop_action = QAction(self)
        icon3 = QIcon()
        icon3.addPixmap(QPixmap("img/stop.png"), QIcon.Normal, QIcon.Off)
        self.stop_action.setIcon(icon3)
        self.stop_action.setText("停止")
        self.stop_action.setObjectName("self.stop_action")
        self.stop_action.setDisabled(True)     #开始时该按钮不可点击
        self.stop_action.triggered.connect(self.on_stop_action_clicked)

        #暂停键
        self.pause_action = QAction(self)
        p_icon = QIcon()
        p_icon.addPixmap(QPixmap("img/pause.jpg"), QIcon.Normal, QIcon.Off)
        self.pause_action.setIcon(p_icon)
        self.pause_action.setText("暂停")
        self.pause_action.setObjectName("self.pause_action")
        self.pause_action.setDisabled(True)  # 开始时该按钮不可点击
        self.pause_action.triggered.connect(self.on_pause_action_clicked)

        #重新开始键
        self.actionRestart = QAction(self)
        icon4 = QIcon()
        icon4.addPixmap(QPixmap("img/restart.png"), QIcon.Normal, QIcon.Off)
        self.actionRestart.setIcon(icon4)
        self.actionRestart.setText("重新开始")
        self.actionRestart.setObjectName("self.actionRestart")
        self.actionRestart.setDisabled(True)  # 开始时该按钮不可点击
        self.actionRestart.triggered.connect(self.on_actionRestart_clicked)

        #帮助文档
        action_readme = QAction(self)
        action_readme.setText("说明文档")
        action_readme.setObjectName("action_readme")
        action_about = QAction(self)
        action_about.setText("关于")
        action_about.setObjectName("action_about")

        #打开文件键
        action_openfile = QAction(self)
        action_openfile.setText("打开")
        action_openfile.setObjectName("action_openfile")
        action_openfile.triggered.connect(self.on_action_openfile_clicked)

        #保存文件键
        action_savefile = QAction(self)
        action_savefile.setText("保存")
        action_savefile.setObjectName("action_savefile")
        action_savefile.triggered.connect(self.on_action_savefile_clicked)

        #退出键
        self.action_exit = QAction(self)
        self.action_exit.setCheckable(False)
        self.action_exit.setText("退出")
        self.action_exit.setShortcut("Ctr+Q")
        self.action_exit.setObjectName("action_exit")
        self.action_exit.triggered.connect(self.on_action_exit_clicked)

        action = QAction(self)
        action.setText("显示过滤器")
        action.setObjectName("action")

        #追踪流
        self.action_track = QAction(self)
        self.action_track.setText("追踪流")
        self.action_track.setObjectName("action_track")
        self.action_track.triggered.connect(self.on_action_track_clicked)

        #IP地址类型统计图
        self.IP_statistics = QAction(self)
        self.IP_statistics.setText("IP地址类型统计")
        self.IP_statistics.setObjectName("IP_statistics")
        self.IP_statistics.triggered.connect(self.on_IP_statistics_clicked)

        #报文类型统计图
        self.message_statistics = QAction(self)
        self.message_statistics.setText("报文类型统计")
        self.message_statistics.setObjectName("message_statisctics")
        self.message_statistics.triggered.connect(self.on_message_statistics_clicked)

        """
           添加工具栏：开始，暂停，停止，重新开始
        """
        self.mainToolBar.addAction(self.start_action)
        self.mainToolBar.addAction(self.pause_action)
        self.mainToolBar.addAction(self.stop_action)
        self.mainToolBar.addAction(self.actionRestart)

        self.menu_F.addAction(action_openfile)
        self.menu_F.addAction(action_savefile)
        self.menu_F.addAction(self.action_exit)

        self.edit_menu.addAction(font_set)
        self.edit_menu.addAction(change_border)

        #捕获菜单栏添加子菜单
        self.capture_menu.addAction(self.start_action)
        self.capture_menu.addAction(self.pause_action)
        self.capture_menu.addAction(self.stop_action)
        self.capture_menu.addAction(self.actionRestart)

        self.menu_H.addAction(action_readme)
        self.menu_H.addAction(action_about)
        self.menu_Analysis.addAction(action)
        self.menu_Analysis.addAction(self.action_track)

        self.menu_Statistic.addAction(self.IP_statistics)
        self.menu_Statistic.addAction(self.message_statistics)

        self.menuBar.addAction(self.menu_F.menuAction())
        self.menuBar.addAction(self.edit_menu.menuAction())
        self.menuBar.addAction(self.capture_menu.menuAction())
        self.menuBar.addAction(self.menu_Analysis.menuAction())
        self.menuBar.addAction(self.menu_Statistic.menuAction())
        self.menuBar.addAction(self.menu_H.menuAction())


        # self.retranslateUi()
        QMetaObject.connectSlotsByName(self)
        self.core = Core(self)
        # self.this_MainWindow = MainWindow
        self.show()


    def closeEvent(self, QCloseEvent):
        reply = QMessageBox.question(self, 'Message',
                                     "Are you sure to quit?", QMessageBox.Yes |
                                     QMessageBox.No, QMessageBox.No)
        if reply == QMessageBox.Yes:
            # 已停止未保存
            if self.core.start_flag is True or self.core.pause_flag is True:
                self.core.stop_capture()
            if self.core.stop_flag is True and self.core.save_flag is False:
                reply = QMessageBox.question(self, 'Message',
                             "Do you want to save as pcap?", QMessageBox.Yes |
                             QMessageBox.No, QMessageBox.No)
                if reply == QMessageBox.Yes:
                    self.on_action_savefile_clicked()
            sys.exit()
        else:
            QCloseEvent.ignore()

    """
       数据包视图 数据记录点击事件
       点击列表中一条记录时，在下面的frame框中显示帧的详细信息
    """
    def on_tableview_clicked(self):
        selected_row = self.info_tree.currentIndex().row()   #当前选择的行号
        #表格停止追踪更新
        self.notSelected = False
        """
           清空Frame Information内容
        """
        self.treeWidget.clear()

        """
           添加树节点
           Item1: 第一层树节点
           Item1_1: 第二层树节点，Item1的子节点
           QTreeWidgetItem(parentNode, text)   parentNode:父节点  text：当前节点内容
        """
        parentList, childList = self.core.on_click_item(selected_row)
        p_num = len(parentList)
        for i in range(p_num):
            item1 = QTreeWidgetItem(self.treeWidget)
            item1.setText(0, parentList[i])
            c_num = len(childList[i])
            for j in range(c_num):
                item1_1 = QTreeWidgetItem(item1)
                item1_1.setText(0, childList[i][j])
        self.set_hex_text(self.core.get_hex(selected_row))

    """
       表格添加行
    """
    def add_tableview_row(self, mylist):
        item = QTreeWidgetItem(self.info_tree)
        """
            添加行内容
        """
        for i in range(7):
            item.setText(i, mylist[i])
        """
            根据协议类型不同设置颜色
        """
        if mylist[4] == "UDP":
            for i in range(7):
                item.setBackground(i, QBrush(QColor("#CCFFFF")))
        elif mylist[4] == "HTTPS":
            for i in range(7):
                item.setBackground(i, QBrush(QColor("#FFCCCC")))
        elif mylist[4] == "HTTPSv6":
            for i in range(7):
                item.setBackground(i, QBrush(QColor("#FFFFCC")))
        elif mylist[4] == "DNS":
            for i in range(7):
                item.setBackground(i, QBrush(QColor("#CCFF99")))
        elif mylist[4] == "TCP":
            for i in range(7):
                item.setBackground(i, QBrush(QColor("#FFCC33")))
        elif mylist[4] == "ICMPv6":
            for i in range(7):
                item.setBackground(i, QBrush(QColor("#FFCC99")))
        else:
            pass

    """
       选择网卡点击事件
       显示当前选择的网卡的详细信息
    """
    def onActivated(self):
        title = self.choose_nicbox.currentText()

    """
       获取当前选择的网卡
    """
    def get_choose_nic(self):
        card = self.choose_nicbox.currentText()
        if(card=='All'):
            a = None
        elif platform == 'Windows':
            a = netcards[card]
        elif platform == 'Linux':
            a = card
        else: a = None
        return a

    """
       设置hex区文本
    """
    def set_hex_text(self, text):
        self.hexBrowser.setText(text)

    """
        设置字体点击事件
    """
    def on_font_set_clicked(self):
        font, ok = QFontDialog.getFont()
        if ok:
            self.info_tree.setFont(font)
            self.treeWidget.setFont(font)
            self.hexBrowser.setFont(font)

    """
        设置背景图片
    """
    def on_change_border_clicked(self):
        imgName, imgType = QFileDialog.getOpenFileName(self, "打开图片", "C:/", "*.jpg;;*.png;;All Files(*)")
        window_pale = QPalette()
        window_pale.setBrush(self.backgroundRole(), QBrush(QPixmap(imgName)))
        self.setPalette(window_pale)

    """
       开始键点击事件
    """
    def on_start_action_clicked(self):
        if self.core.stop_flag == True:
            # 重新开始清空面板内容
            # self.table_view_clear()
            self.info_tree.clear()
            self.treeWidget.clear()
            self.set_hex_text("")
        self.notSelected = True
        self.core.start_capture(self.get_choose_nic(), self.Filer.text())
        """
           点击开始后，过滤器不可编辑，开始按钮、网卡选择框全部设为不可选
           激活暂停、停止键、重新开始键
        """
        self.start_action.setDisabled(True)
        self.Filer.setEnabled(False) 
        self.FilerButton.setEnabled(False) 
        self.choose_nicbox.setEnabled(False)
        self.actionRestart.setDisabled(False)
        self.pause_action.setEnabled(True)
        self.stop_action.setEnabled(True)



    """
       暂停事件点击事件
    """
    def on_pause_action_clicked(self):
        self.core.pause_capture()

        """
           激活开始、停止、重新开始键、过滤器、网卡选择框
        """
        self.start_action.setDisabled(False)
        self.stop_action.setDisabled(False)
        self.actionRestart.setDisabled(False)
        self.Filer.setDisabled(False)
        self.FilerButton.setDisabled(False)
        self.choose_nicbox.setDisabled(False)    
        self.pause_action.setDisabled(True)


    """
           菜单栏停止键点击事件
    """
    def on_stop_action_clicked(self):
        self.core.stop_capture()
        """
            激活开始键、重新开始键、过滤器、网卡选择框
        """
        self.stop_action.setDisabled(True)
        self.pause_action.setDisabled(True)
        self.start_action.setDisabled(False)
        self.Filer.setDisabled(False)
        self.FilerButton.setDisabled(False)
        self.choose_nicbox.setDisabled(False)


    """
       重新开始键响应事件
    """
    def on_actionRestart_clicked(self):
        # 重新开始清空面板内容
        self.info_tree.clear()
        self.treeWidget.clear()
        self.set_hex_text("")
        self.notSelected = True
        self.core.restart_capture(self.get_choose_nic(), self.Filer.text())
        """
           点击开始后，过滤器不可编辑，开始按钮，网卡选择框全部设为不可选
           激活暂停、停止键、重新开始键
        """
        self.actionRestart.setDisabled(False)
        self.start_action.setDisabled(True)
        self.Filer.setEnabled(False)
        self.FilerButton.setEnabled(False)
        self.choose_nicbox.setEnabled(False)
        self.pause_action.setEnabled(True)
        self.stop_action.setEnabled(True)

    """
        IP地址类型统计图绘制
    """
    def on_IP_statistics_clicked(self):
        IP = self.core.get_network_count()
        IPv4_count = IP["ipv4"]
        IPv6_count = IP["ipv6"]
        IP_count = IPv4_count + IPv6_count
        if IP_count == 0:
            reply = QMessageBox.information(self,
                                    "提示",  
                                    "你还没有抓包！",  
                                    QMessageBox.Cancel)

        else:
            IPv4_fre = IPv4_count/IP_count
            IPv6_fre = IPv6_count/IP_count
            data = {
                'IPv4': (IPv4_fre, '#7199cf'),
                'IPv6': (IPv6_fre, '#4fc4aa'),
            }

            fig = plt.figure(figsize=(6, 4))

            # 创建绘图区域
            ax1 = fig.add_subplot(111)
            ax1.set_title('IPv4 & IPv6 统计图')

            # 生成x轴的每个元素的位置，列表是[1,2,3,4]
            xticks = np.arange(1, 3)

            # 自定义柱状图的每个柱的宽度
            bar_width = 0.6

            IP_type = data.keys()
            values = [x[0] for x in data.values()]
            colors = [x[1] for x in data.values()]

            # 画柱状图，设置柱的边缘为透明
            bars = ax1.bar(xticks, values, width=bar_width, edgecolor='none')

            # 设置x,y轴的标签
            ax1.set_xlabel('IP地址类型')
            ax1.set_ylabel('比例')

            ax1.set_xticks(xticks)
            ax1.set_xticklabels(IP_type)

            # 设置x,y轴的范围
            ax1.set_xlim([0, 3.5])
            ax1.set_ylim([0, 1])

            # 给每一个bar分配颜色
            for bar, color in zip(bars, colors):
                bar.set_color(color)
            # plt.savefig('bar.jpg')
            plt.show()

    """
        数据包类型数量统计
    """
    def on_message_statistics_clicked(self):
        trans = self.core.get_transport_count()

        TCP_count = trans["tcp"]
        UDP_count = trans["udp"]
        ARP_count = trans["arp"]
        ICMP_count = trans["icmp"]

        if TCP_count + UDP_count + ARP_count + ICMP_count == 0:
            reply = QMessageBox.information(self,
                                    "提示",  
                                    "你还没有抓包！",  
                                    QMessageBox.Cancel)
        
        else:
            labels = 'TCP', 'ICMP', 'UDP', 'ARP'
            fracs = [TCP_count, ICMP_count, UDP_count, ARP_count]
            explode = [0.1, 0.1, 0.1, 0.1]  # 0.1 凸出这部分，
            plt.axes(aspect=1)  # set this , Figure is round, otherwise it is an ellipse
            # autopct ，show percet
            plt.pie(x=fracs, labels=labels, explode=explode, autopct='%3.1f %%',
                    shadow=True, labeldistance=1.1, startangle=90, pctdistance=0.6
                    )
            plt.show()


    """
        打开文件事件
    """

    def on_action_openfile_clicked(self):
        self.core.open_pcap_file()

    """
       保存文件点击事件
    """

    def on_action_savefile_clicked(self):
        self.core.save_captured_to_pcap()



    """
       菜单栏追踪流键点击事件
    """

    def on_action_track_clicked(self):
        QMessageBox.about(MainWindow, "About", "Track flow")

    """
       退出点击事件
    """

    def on_action_exit_clicked(self, event):
        reply = QMessageBox.question(self, 'Message',
                                     "Are you sure to quit?", QMessageBox.Yes |
                                     QMessageBox.No, QMessageBox.No)
        if reply == QMessageBox.Yes:
            # 已停止未保存
            if self.core.stop_flag == True and self.core.save_flag == False:
                reply = QMessageBox.question(self, 'Message',
                             "Do you want to save as pcap?", QMessageBox.Yes |
                             QMessageBox.No, QMessageBox.No)
                if reply == QMessageBox.Yes:
                    self.on_action_savefile_clicked()
            sys.exit()


    # """
    #    数据包表格清空
    # """
    # def table_view_clear(self):
    #     row_count = self.info_tableView_model.rowCount()
    #     for i in range(0, row_count)[::-1]:
    #         self.info_tableView_model.removeRow(i)


if __name__ == "__main__":
    app = QApplication(sys.argv)
    ui = Ui_MainWindow()
    ui.setupUi()
    stop = time()
    print(stop - start)
    sys.exit(app.exec_())

