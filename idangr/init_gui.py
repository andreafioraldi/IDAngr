######################################################
# Author: Andrea Fioraldi <andreafioraldi@gmail.com> #
# License: BSD 2-Clause                              #
######################################################

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
        
        self.ui.hostTxt.setText(host)
        self.ui.portTxt.setText(str(port))
        
    
    @staticmethod
    def go():
        dialog = IDAngrConnectDialog()
        r = dialog.exec_()
        if r == QtWidgets.QDialog.Accepted:
            if dialog.ui.saveBox.isChecked():
                config = {
                    "host": dialog.ui.hostTxt.displayText(),
                    "port": int(dialog.ui.portTxt.displayText()),
                    "save": True,
                    "local": dialog.ui.localBox.isChecked()
                }
                mkpath(user_data_dir("IDAngr", "IDA Pro"))
                with open(config_file, "w") as f:
                    json.dump(config, f, indent=4)
            
            try:
                if dialog.ui.localBox.isChecked():
                    manage.init(use_pin=dialog.ui.pinBox.isChecked())
                else:
                    manage.init(True, dialog.ui.hostTxt.displayText(), int(dialog.ui.portTxt.displayText()), use_pin=dialog.ui.pinBox.isChecked())
            except Exception as ee:
                QtWidgets.QMessageBox(QtWidgets.QMessageBox.Critical, 'IDAngr init error', str(ee)).exec_()
                return False
            
            return True
        return False



