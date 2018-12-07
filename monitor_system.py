# -*- coding: utf-8 -*-
from threading import Thread
from PyQt5 import QtCore, QtGui, QtWidgets
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.backends.backend_qt5 import NavigationToolbar2QT as NavigationToolbar
import matplotlib.pyplot as plt
from tools import get_rate
from flow_monitor import Monitor

# 设置全局字体，以支持中文
plt.rcParams['font.sans-serif'] = ['SimHei']
# 解决‘-’表现为方块的问题
plt.rcParams['axes.unicode_minus'] = False


class Ui_Form(object):
    def setupUi(self, Form):
        Form.setWindowTitle("流量监测系统")
        Form.resize(550, 630)
        self.horizontalLayoutWidget = QtWidgets.QWidget(Form)
        self.horizontalLayoutWidget.setGeometry(QtCore.QRect(10, 10, 500, 30))
        self.horizontalLayout = QtWidgets.QHBoxLayout(
            self.horizontalLayoutWidget)
        self.horizontalLayout.setContentsMargins(0, 0, 0, 0)
        self.horizontalLayout.setSpacing(20)
        Form.setFixedSize(Form.width(), Form.height())
        self.monitor = Monitor(self)
        """主字体"""
        font = QtGui.QFont()
        font.setFamily("Lucida Sans Typewriter")
        font.setPointSize(10)
        """应用选择框"""
        self.comboBox = QtWidgets.QComboBox(self.horizontalLayoutWidget)
        self.comboBox.setFont(font)
        self.horizontalLayout.addWidget(self.comboBox)

        self.start_button = QtWidgets.QPushButton(self.horizontalLayoutWidget)
        self.start_button.setText("开始监测")
        self.start_button.clicked.connect(self.start)
        self.horizontalLayout.addWidget(self.start_button)

        self.stop_button = QtWidgets.QPushButton(self.horizontalLayoutWidget)
        self.stop_button.setText("停止监测")
        self.stop_button.clicked.connect(self.stop)
        self.horizontalLayout.addWidget(self.stop_button)

        self.update_button = QtWidgets.QPushButton(self.horizontalLayoutWidget)
        self.update_button.setText("更新列表")
        self.horizontalLayout.addWidget(self.update_button)
        self.horizontalLayout.setStretch(0, 2)
        self.horizontalLayout.setStretch(1, 1)
        self.horizontalLayout.setStretch(2, 1)
        self.horizontalLayout.setStretch(3, 1)
        self.update_button.clicked.connect(self.refresh_process)

        self.verticalLayoutWidget = QtWidgets.QWidget(Form)
        self.verticalLayoutWidget.setGeometry(QtCore.QRect(10, 60, 530, 570))
        self.verticalLayout = QtWidgets.QVBoxLayout(self.verticalLayoutWidget)
        self.verticalLayout.setContentsMargins(0, 0, 0, 0)

        self.conList = QtWidgets.QListWidget(self.verticalLayoutWidget)
        self.conList.setFont(font)
        self.conList.setMinimumSize(421, 200)
        self.verticalLayout.addWidget(self.conList)

        self.figure = plt.figure(figsize=(6, 3))
        self.upload_plot = self.figure.add_subplot(1, 1, 1)
        self.upload_plot.set_xlabel("Time (s)")
        self.upload_plot.set_ylabel("Speed (kB/s)")
        self.figure.tight_layout()
        self.canvas = FigureCanvas(self.figure)
        self.toolbar = NavigationToolbar(self.canvas,
                                         self.verticalLayoutWidget)
        self.toolbar.hide()
        self.verticalLayout.addWidget(self.toolbar)
        self.verticalLayout.addWidget(self.canvas)
        QtCore.QMetaObject.connectSlotsByName(Form)
        self.comboBox.addItems(self.monitor.getProcessList())

    def refresh_process(self):
        """
        刷新进程列表
        """
        self.comboBox.clear()
        self.comboBox.addItems(self.monitor.getProcessList())

    def setSpeed(self):
        """
        设置速度图
        """
        upload = []
        download = []
        while not self.monitor.start_flag.is_set():
            info = get_rate(None)
            plt.cla()
            self.upload_plot.set_xlabel("Time (s)")
            self.upload_plot.set_ylabel("Speed (kB/s)")
            upload.append(info[1] >> 10)
            download.append(info[0] >> 10)
            if len(upload) >= 60:
                upload.pop(0)
                download.pop(0)
            self.upload_plot.plot(upload, '-r', label="上传速度")
            self.upload_plot.legend(loc='upper right')
            self.upload_plot.plot(download, '-b', label="下载速度")
            self.upload_plot.legend(loc='upper right')
            self.canvas.draw()

    def start(self):
        """
        开始检测
        """
        if self.monitor.start_flag.is_set():
            self.monitor.start(self.comboBox.currentText())
            Thread(target=self.setSpeed, daemon=True).start()

    def stop(self):
        """
        停止检测
        """
        if not self.monitor.start_flag.is_set():
            self.monitor.stop()


def start_monitor():
    """
    调用监测系统
    """
    app = QtWidgets.QApplication([])
    widget = QtWidgets.QWidget()
    ui = Ui_Form()
    ui.setupUi(widget)
    widget.show()
    app.exec()


if __name__ == "__main__":
    start_monitor()
