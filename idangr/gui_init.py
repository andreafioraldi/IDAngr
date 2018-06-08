from idaapi import PluginForm
from PyQt5 import QtCore, QtGui, QtWidgets
from PyQt5.QtCore import Qt

from ui import *

import manage

class IDAngrConnectDialog(QtWidgets.QDialog):
    
    def __init__(self):
        QtWidgets.QDialog.__init__(self)
        
        self.ui = Ui_IDAngrConnectDialog()
        self.ui.setupUi(self)
        
        self.ui.hostTxt.setPlainText("localhost")
        self.ui.portTxt.setPlainText(str(manage.DEFAULT_SERVER_PORT))
        
    
    @staticmethod
    def go():
        dialog = IDAngrConnectDialog()
        r = dialog.exec_()
        if r == QtWidgets.QDialog.Accepted:
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
