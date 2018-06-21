# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'addmem.ui'
#
# Created by: PyQt5 UI code generator 5.10.1
#
# WARNING! All changes made in this file will be lost!

from PyQt5 import QtCore, QtGui, QtWidgets

class Ui_IDAngrAddMem(object):
    def setupUi(self, IDAngrAddMem):
        IDAngrAddMem.setObjectName("IDAngrAddMem")
        IDAngrAddMem.resize(440, 251)
        self.gridLayout_2 = QtWidgets.QGridLayout(IDAngrAddMem)
        self.gridLayout_2.setObjectName("gridLayout_2")
        self.gridLayout = QtWidgets.QGridLayout()
        self.gridLayout.setObjectName("gridLayout")
        self.label = QtWidgets.QLabel(IDAngrAddMem)
        self.label.setObjectName("label")
        self.gridLayout.addWidget(self.label, 0, 0, 1, 1)
        self.addrTextEdit = QtWidgets.QLineEdit(IDAngrAddMem)
        self.addrTextEdit.setObjectName("addrTextEdit")
        self.gridLayout.addWidget(self.addrTextEdit, 1, 0, 1, 1)
        self.label_2 = QtWidgets.QLabel(IDAngrAddMem)
        self.label_2.setObjectName("label_2")
        self.gridLayout.addWidget(self.label_2, 2, 0, 1, 1)
        self.lenTextEdit = QtWidgets.QLineEdit(IDAngrAddMem)
        self.lenTextEdit.setObjectName("lenTextEdit")
        self.gridLayout.addWidget(self.lenTextEdit, 3, 0, 1, 1)
        self.gridLayout_2.addLayout(self.gridLayout, 0, 0, 1, 1)
        spacerItem = QtWidgets.QSpacerItem(20, 79, QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Expanding)
        self.gridLayout_2.addItem(spacerItem, 1, 0, 1, 1)
        self.buttonBox = QtWidgets.QDialogButtonBox(IDAngrAddMem)
        self.buttonBox.setOrientation(QtCore.Qt.Horizontal)
        self.buttonBox.setStandardButtons(QtWidgets.QDialogButtonBox.Cancel|QtWidgets.QDialogButtonBox.Ok)
        self.buttonBox.setObjectName("buttonBox")
        self.gridLayout_2.addWidget(self.buttonBox, 2, 0, 1, 1)

        self.retranslateUi(IDAngrAddMem)
        self.buttonBox.accepted.connect(IDAngrAddMem.accept)
        self.buttonBox.rejected.connect(IDAngrAddMem.reject)
        QtCore.QMetaObject.connectSlotsByName(IDAngrAddMem)

    def retranslateUi(self, IDAngrAddMem):
        _translate = QtCore.QCoreApplication.translate
        IDAngrAddMem.setWindowTitle(_translate("IDAngrAddMem", "Add Symbolic Memory"))
        self.label.setText(_translate("IDAngrAddMem", "Address:"))
        self.label_2.setText(_translate("IDAngrAddMem", "Length:"))

