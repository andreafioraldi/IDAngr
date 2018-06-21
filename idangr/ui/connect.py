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
        IDAngrConnectDialog.resize(589, 301)
        self.gridLayout_2 = QtWidgets.QGridLayout(IDAngrConnectDialog)
        self.gridLayout_2.setObjectName("gridLayout_2")
        spacerItem = QtWidgets.QSpacerItem(20, 73, QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Expanding)
        self.gridLayout_2.addItem(spacerItem, 2, 0, 1, 1)
        self.buttonBox = QtWidgets.QDialogButtonBox(IDAngrConnectDialog)
        self.buttonBox.setOrientation(QtCore.Qt.Horizontal)
        self.buttonBox.setStandardButtons(QtWidgets.QDialogButtonBox.Cancel|QtWidgets.QDialogButtonBox.Ok)
        self.buttonBox.setObjectName("buttonBox")
        self.gridLayout_2.addWidget(self.buttonBox, 3, 0, 1, 1)
        self.gridLayout = QtWidgets.QGridLayout()
        self.gridLayout.setSizeConstraint(QtWidgets.QLayout.SetMaximumSize)
        self.gridLayout.setObjectName("gridLayout")
        self.portTxt = QtWidgets.QLineEdit(IDAngrConnectDialog)
        self.portTxt.setObjectName("portTxt")
        self.gridLayout.addWidget(self.portTxt, 3, 0, 1, 1)
        self.label = QtWidgets.QLabel(IDAngrConnectDialog)
        self.label.setMaximumSize(QtCore.QSize(16777215, 23))
        self.label.setObjectName("label")
        self.gridLayout.addWidget(self.label, 0, 0, 1, 1)
        self.hostTxt = QtWidgets.QLineEdit(IDAngrConnectDialog)
        self.hostTxt.setObjectName("hostTxt")
        self.gridLayout.addWidget(self.hostTxt, 1, 0, 1, 1)
        self.label_2 = QtWidgets.QLabel(IDAngrConnectDialog)
        self.label_2.setMaximumSize(QtCore.QSize(16777215, 23))
        self.label_2.setObjectName("label_2")
        self.gridLayout.addWidget(self.label_2, 2, 0, 1, 1)
        self.saveBox = QtWidgets.QCheckBox(IDAngrConnectDialog)
        self.saveBox.setMaximumSize(QtCore.QSize(16777215, 23))
        self.saveBox.setChecked(False)
        self.saveBox.setObjectName("saveBox")
        self.gridLayout.addWidget(self.saveBox, 4, 0, 1, 1)
        self.localBox = QtWidgets.QCheckBox(IDAngrConnectDialog)
        self.localBox.setMaximumSize(QtCore.QSize(16777215, 23))
        self.localBox.setObjectName("localBox")
        self.gridLayout.addWidget(self.localBox, 5, 0, 1, 1)
        self.gridLayout_2.addLayout(self.gridLayout, 1, 0, 1, 1)

        self.retranslateUi(IDAngrConnectDialog)
        self.buttonBox.accepted.connect(IDAngrConnectDialog.accept)
        self.buttonBox.rejected.connect(IDAngrConnectDialog.reject)
        QtCore.QMetaObject.connectSlotsByName(IDAngrConnectDialog)

    def retranslateUi(self, IDAngrConnectDialog):
        _translate = QtCore.QCoreApplication.translate
        IDAngrConnectDialog.setWindowTitle(_translate("IDAngrConnectDialog", "IDAngr init"))
        self.label.setText(_translate("IDAngrConnectDialog", "Host:"))
        self.label_2.setText(_translate("IDAngrConnectDialog", "Port:"))
        self.saveBox.setText(_translate("IDAngrConnectDialog", "Save configuration"))
        self.localBox.setText(_translate("IDAngrConnectDialog", "Use local angr"))

