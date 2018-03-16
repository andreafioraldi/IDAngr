# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'constraints.ui'
#
# Created by: PyQt5 UI code generator 5.5.1
#
# WARNING! All changes made in this file will be lost!

from PyQt5 import QtCore, QtGui, QtWidgets

class Ui_IDAngrConstraintsDialog(object):
    def setupUi(self, IDAngrConstraintsDialog):
        IDAngrConstraintsDialog.setObjectName("IDAngrConstraintsDialog")
        IDAngrConstraintsDialog.resize(1168, 875)
        self.gridLayout = QtWidgets.QGridLayout(IDAngrConstraintsDialog)
        self.gridLayout.setObjectName("gridLayout")
        self.constrEdit = QtWidgets.QPlainTextEdit(IDAngrConstraintsDialog)
        self.constrEdit.setEnabled(True)
        self.constrEdit.setObjectName("constrEdit")
        self.gridLayout.addWidget(self.constrEdit, 0, 0, 1, 1)
        self.buttonBox = QtWidgets.QDialogButtonBox(IDAngrConstraintsDialog)
        self.buttonBox.setMinimumSize(QtCore.QSize(0, 48))
        self.buttonBox.setOrientation(QtCore.Qt.Horizontal)
        self.buttonBox.setStandardButtons(QtWidgets.QDialogButtonBox.Cancel|QtWidgets.QDialogButtonBox.Ok)
        self.buttonBox.setObjectName("buttonBox")
        self.gridLayout.addWidget(self.buttonBox, 1, 0, 1, 1)

        self.retranslateUi(IDAngrConstraintsDialog)
        self.buttonBox.accepted.connect(IDAngrConstraintsDialog.accept)
        self.buttonBox.rejected.connect(IDAngrConstraintsDialog.reject)
        QtCore.QMetaObject.connectSlotsByName(IDAngrConstraintsDialog)

    def retranslateUi(self, IDAngrConstraintsDialog):
        _translate = QtCore.QCoreApplication.translate
        IDAngrConstraintsDialog.setWindowTitle(_translate("IDAngrConstraintsDialog", "Edit Constraints"))

