from idaapi import PluginForm
from PyQt5 import QtCore, QtGui, QtWidgets
from PyQt5.QtCore import Qt

from ui import *
from appdirs import user_data_dir
from distutils.dir_util import mkpath

import manage
import os
import json

config_file = os.path.join(user_data_dir("IDAngr", "IDA Pro"), "gui_init.json")

class IDAngrConnectDialog(QtWidgets.QDialog):
    
    def __init__(self):
        QtWidgets.QDialog.__init__(self)
        
        self.ui = Ui_IDAngrConnectDialog()
        self.ui.setupUi(self)
        
        host = "localhost"
        port = manage.DEFAULT_SERVER_PORT
        
        try:
            if os.path.exists(config_file):
                with open(config_file) as f:
                    config = json.load(f)
                host = config["host"]
                port = config["port"]
                self.ui.saveBox.setChecked(config["save"])
                self.ui.localBox.setChecked(config["local"])
        except: pass
        
        self.ui.hostTxt.setPlainText(host)
        self.ui.portTxt.setPlainText(str(port))
        
    
    @staticmethod
    def go():
        dialog = IDAngrConnectDialog()
        r = dialog.exec_()
        if r == QtWidgets.QDialog.Accepted:
            if dialog.ui.saveBox.isChecked():
                config = {
                    "host": dialog.ui.hostTxt.toPlainText(),
                    "port": int(dialog.ui.portTxt.toPlainText()),
                    "save": True,
                    "local": dialog.ui.localBox.isChecked()
                }
                mkpath(user_data_dir("IDAngr", "IDA Pro"))
                with open(config_file, "w") as f:
                    json.dump(config, f, indent=4)
            
            if dialog.ui.localBox.isChecked():
                manage.init()
            else:
                manage.init(True, dialog.ui.hostTxt.toPlainText(), int(dialog.ui.portTxt.toPlainText()))
            return True
        return False


def setup_loop():
    if not manage.is_initialized():
        while not IDAngrConnectDialog.go():
            pass




