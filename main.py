from the_ui import *


if __name__ == "__main__":
    app = QApplication(sys.argv)
    ui = Ui_MainWindow()
    ui.setupUi()
    stop = time()
    print(stop - start)
    sys.exit(app.exec_())
