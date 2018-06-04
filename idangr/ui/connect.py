# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'connect.ui'
#
# Created by: PyQt5 UI code generator 5.10.1
#
# WARNING! All changes made in this file will be lost!

from PyQt5 import QtCore, QtGui, QtWidgets

class Ui_IDAngrConnectDialog(object):
    def setupUi(self, IDAngrConnectDialog):
        IDAngrConnectDialog.setObjectName("IDAngrConnectDialog")
        IDAngrConnectDialog.resize(471, 258)
        self.buttonBox = QtWidgets.QDialogButtonBox(IDAngrConnectDialog)
        self.buttonBox.setGeometry(QtCore.QRect(130, 220, 331, 32))
        self.buttonBox.setOrientation(QtCore.Qt.Horizontal)
        self.buttonBox.setStandardButtons(QtWidgets.QDialogButtonBox.Cancel|QtWidgets.QDialogButtonBox.Ok)
        self.buttonBox.setObjectName("buttonBox")
        self.hostTxt = QtWidgets.QPlainTextEdit(IDAngrConnectDialog)
        self.hostTxt.setGeometry(QtCore.QRect(10, 40, 451, 31))
        self.hostTxt.setObjectName("hostTxt")
        self.label = QtWidgets.QLabel(IDAngrConnectDialog)
        self.label.setGeometry(QtCore.QRect(10, 10, 67, 17))
        self.label.setObjectName("label")
        self.portTxt = QtWidgets.QPlainTextEdit(IDAngrConnectDialog)
        self.portTxt.setGeometry(QtCore.QRect(10, 110, 451, 31))
        self.portTxt.setObjectName("portTxt")
        self.label_2 = QtWidgets.QLabel(IDAngrConnectDialog)
        self.label_2.setGeometry(QtCore.QRect(10, 80, 67, 17))
        self.label_2.setObjectName("label_2")
        self.saveBox = QtWidgets.QCheckBox(IDAngrConnectDialog)
        self.saveBox.setGeometry(QtCore.QRect(20, 160, 181, 22))
        self.saveBox.setObjectName("saveBox")
        self.localBox = QtWidgets.QCheckBox(IDAngrConnectDialog)
        self.localBox.setGeometry(QtCore.QRect(20, 190, 181, 22))
        self.localBox.setObjectName("localBox")

        self.retranslateUi(IDAngrConnectDialog)
        self.buttonBox.accepted.connect(IDAngrConnectDialog.accept)
        self.buttonBox.rejected.connect(IDAngrConnectDialog.reject)
        QtCore.QMetaObject.connectSlotsByName(IDAngrConnectDialog)

    def retranslateUi(self, IDAngrConnectDialog):
        _translate = QtCore.QCoreApplication.translate
        IDAngrConnectDialog.setWindowTitle(_translate("IDAngrConnectDialog", "Dialog"))
        self.label.setText(_translate("IDAngrConnectDialog", "Host:"))
        self.label_2.setText(_translate("IDAngrConnectDialog", "Port:"))
        self.saveBox.setText(_translate("IDAngrConnectDialog", "Save configuration"))
        self.localBox.setText(_translate("IDAngrConnectDialog", "Use local angr"))

