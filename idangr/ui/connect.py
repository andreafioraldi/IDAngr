# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'connect.ui'
#
# Created by: PyQt5 UI code generator 5.10.1
#
# WARNING! All changes made in this file will be lost!

from PyQt5 import QtCore, QtGui, QtWidgets

class Ui_Dialog(object):
    def setupUi(self, Dialog):
        Dialog.setObjectName("Dialog")
        Dialog.resize(471, 258)
        self.buttonBox = QtWidgets.QDialogButtonBox(Dialog)
        self.buttonBox.setGeometry(QtCore.QRect(130, 220, 331, 32))
        self.buttonBox.setOrientation(QtCore.Qt.Horizontal)
        self.buttonBox.setStandardButtons(QtWidgets.QDialogButtonBox.Cancel|QtWidgets.QDialogButtonBox.Ok)
        self.buttonBox.setObjectName("buttonBox")
        self.hostTxt = QtWidgets.QPlainTextEdit(Dialog)
        self.hostTxt.setGeometry(QtCore.QRect(10, 40, 451, 31))
        self.hostTxt.setObjectName("hostTxt")
        self.label = QtWidgets.QLabel(Dialog)
        self.label.setGeometry(QtCore.QRect(10, 10, 67, 17))
        self.label.setObjectName("label")
        self.portTxt = QtWidgets.QPlainTextEdit(Dialog)
        self.portTxt.setGeometry(QtCore.QRect(10, 110, 451, 31))
        self.portTxt.setObjectName("portTxt")
        self.label_2 = QtWidgets.QLabel(Dialog)
        self.label_2.setGeometry(QtCore.QRect(10, 80, 67, 17))
        self.label_2.setObjectName("label_2")
        self.saveBox = QtWidgets.QCheckBox(Dialog)
        self.saveBox.setGeometry(QtCore.QRect(20, 160, 181, 22))
        self.saveBox.setObjectName("saveBox")
        self.localBox = QtWidgets.QCheckBox(Dialog)
        self.localBox.setGeometry(QtCore.QRect(20, 190, 181, 22))
        self.localBox.setObjectName("localBox")

        self.retranslateUi(Dialog)
        self.buttonBox.accepted.connect(Dialog.accept)
        self.buttonBox.rejected.connect(Dialog.reject)
        QtCore.QMetaObject.connectSlotsByName(Dialog)

    def retranslateUi(self, Dialog):
        _translate = QtCore.QCoreApplication.translate
        Dialog.setWindowTitle(_translate("Dialog", "Dialog"))
        self.label.setText(_translate("Dialog", "Host:"))
        self.label_2.setText(_translate("Dialog", "Port:"))
        self.saveBox.setText(_translate("Dialog", "Save configuration"))
        self.localBox.setText(_translate("Dialog", "Use local angr"))

