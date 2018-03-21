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
        self.buttonBox.setGeometry(QtCore.QRect(120, 800, 1141, 41))
        self.buttonBox.setMaximumSize(QtCore.QSize(16777215, 48))
        self.buttonBox.setOrientation(QtCore.Qt.Horizontal)
        self.buttonBox.setStandardButtons(QtWidgets.QDialogButtonBox.Cancel|QtWidgets.QDialogButtonBox.Ok)
        self.buttonBox.setObjectName("buttonBox")
        self.selectorList = QtWidgets.QListView(IDAngrSavedsDialog)
        self.selectorList.setGeometry(QtCore.QRect(10, 20, 351, 761))
        self.selectorList.setMaximumSize(QtCore.QSize(16777215, 16777215))
        self.selectorList.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        self.selectorList.setObjectName("selectorList")
        self.codeView = QtWidgets.QPlainTextEdit(IDAngrSavedsDialog)
        self.codeView.setGeometry(QtCore.QRect(380, 20, 881, 761))
        self.codeView.setReadOnly(True)
        self.codeView.setObjectName("codeView")

        self.retranslateUi(IDAngrSavedsDialog)
        self.buttonBox.accepted.connect(IDAngrSavedsDialog.accept)
        self.buttonBox.rejected.connect(IDAngrSavedsDialog.reject)
        QtCore.QMetaObject.connectSlotsByName(IDAngrSavedsDialog)

    def retranslateUi(self, IDAngrSavedsDialog):
        _translate = QtCore.QCoreApplication.translate
        IDAngrSavedsDialog.setWindowTitle(_translate("IDAngrSavedsDialog", "Dialog"))

