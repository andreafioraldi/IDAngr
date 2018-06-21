# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'saveds.ui'
#
# Created by: PyQt5 UI code generator 5.10.1
#
# WARNING! All changes made in this file will be lost!

from PyQt5 import QtCore, QtGui, QtWidgets

class Ui_IDAngrSavedsDialog(object):
    def setupUi(self, IDAngrSavedsDialog):
        IDAngrSavedsDialog.setObjectName("IDAngrSavedsDialog")
        IDAngrSavedsDialog.resize(941, 569)
        self.gridLayout = QtWidgets.QGridLayout(IDAngrSavedsDialog)
        self.gridLayout.setObjectName("gridLayout")
        self.splitter = QtWidgets.QSplitter(IDAngrSavedsDialog)
        self.splitter.setOrientation(QtCore.Qt.Horizontal)
        self.splitter.setObjectName("splitter")
        self.selectorList = QtWidgets.QListView(self.splitter)
        self.selectorList.setMaximumSize(QtCore.QSize(270, 16777215))
        self.selectorList.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        self.selectorList.setObjectName("selectorList")
        self.codeView = QtWidgets.QPlainTextEdit(self.splitter)
        self.codeView.setReadOnly(True)
        self.codeView.setObjectName("codeView")
        self.gridLayout.addWidget(self.splitter, 0, 0, 1, 1)
        self.buttonBox = QtWidgets.QDialogButtonBox(IDAngrSavedsDialog)
        self.buttonBox.setMaximumSize(QtCore.QSize(16777215, 48))
        self.buttonBox.setOrientation(QtCore.Qt.Horizontal)
        self.buttonBox.setStandardButtons(QtWidgets.QDialogButtonBox.Cancel|QtWidgets.QDialogButtonBox.Ok)
        self.buttonBox.setObjectName("buttonBox")
        self.gridLayout.addWidget(self.buttonBox, 1, 0, 1, 1)

        self.retranslateUi(IDAngrSavedsDialog)
        self.buttonBox.accepted.connect(IDAngrSavedsDialog.accept)
        self.buttonBox.rejected.connect(IDAngrSavedsDialog.reject)
        QtCore.QMetaObject.connectSlotsByName(IDAngrSavedsDialog)

    def retranslateUi(self, IDAngrSavedsDialog):
        _translate = QtCore.QCoreApplication.translate
        IDAngrSavedsDialog.setWindowTitle(_translate("IDAngrSavedsDialog", "Dialog"))

