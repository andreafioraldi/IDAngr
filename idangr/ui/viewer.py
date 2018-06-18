# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'viewer.ui'
#
# Created by: PyQt5 UI code generator 5.10.1
#
# WARNING! All changes made in this file will be lost!

from PyQt5 import QtCore, QtGui, QtWidgets

class Ui_IDAngrTextViewer(object):
    def setupUi(self, IDAngrTextViewer):
        IDAngrTextViewer.setObjectName("IDAngrTextViewer")
        IDAngrTextViewer.resize(812, 612)
        self.gridLayout = QtWidgets.QGridLayout(IDAngrTextViewer)
        self.gridLayout.setObjectName("gridLayout")
        self.horizontalLayout = QtWidgets.QHBoxLayout()
        self.horizontalLayout.setObjectName("horizontalLayout")
        self.plainBox = QtWidgets.QRadioButton(IDAngrTextViewer)
        self.plainBox.setChecked(True)
        self.plainBox.setObjectName("plainBox")
        self.horizontalLayout.addWidget(self.plainBox)
        self.hexBox = QtWidgets.QRadioButton(IDAngrTextViewer)
        self.hexBox.setObjectName("hexBox")
        self.horizontalLayout.addWidget(self.hexBox)
        self.pyBox = QtWidgets.QRadioButton(IDAngrTextViewer)
        self.pyBox.setObjectName("pyBox")
        self.horizontalLayout.addWidget(self.pyBox)
        self.gridLayout.addLayout(self.horizontalLayout, 0, 0, 1, 1)
        self.plainTextEdit = QtWidgets.QPlainTextEdit(IDAngrTextViewer)
        self.plainTextEdit.setReadOnly(True)
        self.plainTextEdit.setPlainText("")
        self.plainTextEdit.setObjectName("plainTextEdit")
        self.gridLayout.addWidget(self.plainTextEdit, 1, 0, 1, 1)

        self.retranslateUi(IDAngrTextViewer)
        QtCore.QMetaObject.connectSlotsByName(IDAngrTextViewer)

    def retranslateUi(self, IDAngrTextViewer):
        _translate = QtCore.QCoreApplication.translate
        self.plainBox.setText(_translate("IDAngrTextViewer", "Plain text"))
        self.hexBox.setText(_translate("IDAngrTextViewer", "HEX"))
        self.pyBox.setText(_translate("IDAngrTextViewer", "Python"))

