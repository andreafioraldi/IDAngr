# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'addmem.ui'
#
# Created by: PyQt5 UI code generator 5.5.1
#
# WARNING! All changes made in this file will be lost!

from PyQt5 import QtCore, QtGui, QtWidgets

class Ui_IDAngrAddMem(object):
    def setupUi(self, IDAngrAddMem):
        IDAngrAddMem.setObjectName("IDAngrAddMem")
        IDAngrAddMem.resize(464, 284)
        self.buttonBox = QtWidgets.QDialogButtonBox(IDAngrAddMem)
        self.buttonBox.setGeometry(QtCore.QRect(90, 231, 361, 41))
        self.buttonBox.setOrientation(QtCore.Qt.Horizontal)
        self.buttonBox.setStandardButtons(QtWidgets.QDialogButtonBox.Cancel|QtWidgets.QDialogButtonBox.Ok)
        self.buttonBox.setObjectName("buttonBox")
        self.addrTextEdit = QtWidgets.QPlainTextEdit(IDAngrAddMem)
        self.addrTextEdit.setGeometry(QtCore.QRect(10, 50, 441, 41))
        self.addrTextEdit.setPlainText("")
        self.addrTextEdit.setObjectName("addrTextEdit")
        self.label = QtWidgets.QLabel(IDAngrAddMem)
        self.label.setGeometry(QtCore.QRect(10, 10, 108, 33))
        self.label.setObjectName("label")
        self.label_2 = QtWidgets.QLabel(IDAngrAddMem)
        self.label_2.setGeometry(QtCore.QRect(10, 110, 108, 33))
        self.label_2.setObjectName("label_2")
        self.lenTextEdit = QtWidgets.QPlainTextEdit(IDAngrAddMem)
        self.lenTextEdit.setGeometry(QtCore.QRect(10, 150, 441, 41))
        self.lenTextEdit.setPlainText("")
        self.lenTextEdit.setObjectName("lenTextEdit")

        self.retranslateUi(IDAngrAddMem)
        self.buttonBox.accepted.connect(IDAngrAddMem.accept)
        self.buttonBox.rejected.connect(IDAngrAddMem.reject)
        QtCore.QMetaObject.connectSlotsByName(IDAngrAddMem)

    def retranslateUi(self, IDAngrAddMem):
        _translate = QtCore.QCoreApplication.translate
        IDAngrAddMem.setWindowTitle(_translate("IDAngrAddMem", "Add Symbolic Memory"))
        self.label.setText(_translate("IDAngrAddMem", "Address:"))
        self.label_2.setText(_translate("IDAngrAddMem", "Length:"))

