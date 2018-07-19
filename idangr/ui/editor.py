# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'editor.ui'
#
# Created by: PyQt5 UI code generator 5.10.1
#
# WARNING! All changes made in this file will be lost!

from PyQt5 import QtCore, QtGui, QtWidgets

class Ui_IDAngrEditorDialog(object):
    def setupUi(self, IDAngrEditorDialog):
        IDAngrEditorDialog.setObjectName("IDAngrEditorDialog")
        IDAngrEditorDialog.resize(750, 604)
        self.gridLayout = QtWidgets.QGridLayout(IDAngrEditorDialog)
        self.gridLayout.setObjectName("gridLayout")
        self.codeEdit = QtWidgets.QPlainTextEdit(IDAngrEditorDialog)
        self.codeEdit.setObjectName("codeEdit")
        self.gridLayout.addWidget(self.codeEdit, 0, 0, 1, 1)
        self.buttonBox = QtWidgets.QDialogButtonBox(IDAngrEditorDialog)
        self.buttonBox.setOrientation(QtCore.Qt.Horizontal)
        self.buttonBox.setStandardButtons(QtWidgets.QDialogButtonBox.Cancel|QtWidgets.QDialogButtonBox.Ok)
        self.buttonBox.setObjectName("buttonBox")
        self.gridLayout.addWidget(self.buttonBox, 1, 0, 1, 1)

        self.retranslateUi(IDAngrEditorDialog)
        self.buttonBox.accepted.connect(IDAngrEditorDialog.accept)
        self.buttonBox.rejected.connect(IDAngrEditorDialog.reject)
        QtCore.QMetaObject.connectSlotsByName(IDAngrEditorDialog)

    def retranslateUi(self, IDAngrEditorDialog):
        _translate = QtCore.QCoreApplication.translate
        IDAngrEditorDialog.setWindowTitle(_translate("IDAngrEditorDialog", "Editor"))

