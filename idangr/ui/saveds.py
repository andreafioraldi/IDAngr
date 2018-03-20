# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'saveds.ui'
#
# Created by: PyQt5 UI code generator 5.5.1
#
# WARNING! All changes made in this file will be lost!

from PyQt5 import QtCore, QtGui, QtWidgets

class Ui_IDAngrSavedsDialog(object):
    def setupUi(self, IDAngrSavedsDialog):
        IDAngrSavedsDialog.setObjectName("IDAngrSavedsDialog")
        IDAngrSavedsDialog.resize(1287, 859)
        self.buttonBox = QtWidgets.QDialogButtonBox(IDAngrSavedsDialog)
        self.buttonBox.setGeometry(QtCore.QRect(920, 810, 341, 41))
        self.buttonBox.setMaximumSize(QtCore.QSize(16777215, 48))
        self.buttonBox.setOrientation(QtCore.Qt.Horizontal)
        self.buttonBox.setStandardButtons(QtWidgets.QDialogButtonBox.Cancel|QtWidgets.QDialogButtonBox.Ok)
        self.buttonBox.setObjectName("buttonBox")
        self.selectorList = QtWidgets.QListWidget(IDAngrSavedsDialog)
        self.selectorList.setGeometry(QtCore.QRect(10, 20, 351, 771))
        self.selectorList.setObjectName("selectorList")
        self.codeView = QtWidgets.QPlainTextEdit(IDAngrSavedsDialog)
        self.codeView.setGeometry(QtCore.QRect(380, 20, 881, 771))
        self.codeView.setObjectName("codeView")

        self.retranslateUi(IDAngrSavedsDialog)
        self.buttonBox.accepted.connect(IDAngrSavedsDialog.accept)
        self.buttonBox.rejected.connect(IDAngrSavedsDialog.reject)
        QtCore.QMetaObject.connectSlotsByName(IDAngrSavedsDialog)

    def retranslateUi(self, IDAngrSavedsDialog):
        _translate = QtCore.QCoreApplication.translate
        IDAngrSavedsDialog.setWindowTitle(_translate("IDAngrSavedsDialog", "Dialog"))

