# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'constraints.ui'
#
# Created by: PyQt5 UI code generator 5.10.1
#
# WARNING! All changes made in this file will be lost!

from PyQt5 import QtCore, QtGui, QtWidgets

class Ui_IDAngrConstraintsDialog(object):
    def setupUi(self, IDAngrConstraintsDialog):
        IDAngrConstraintsDialog.setObjectName("IDAngrConstraintsDialog")
        IDAngrConstraintsDialog.resize(811, 599)
        self.gridLayout_2 = QtWidgets.QGridLayout(IDAngrConstraintsDialog)
        self.gridLayout_2.setObjectName("gridLayout_2")
        self.constrEdit = QtWidgets.QPlainTextEdit(IDAngrConstraintsDialog)
        self.constrEdit.setEnabled(True)
        self.constrEdit.setObjectName("constrEdit")
        self.gridLayout_2.addWidget(self.constrEdit, 0, 0, 1, 1)
        self.gridLayout = QtWidgets.QGridLayout()
        self.gridLayout.setObjectName("gridLayout")
        self.savedsBtn = QtWidgets.QPushButton(IDAngrConstraintsDialog)
        self.savedsBtn.setEnabled(True)
        self.savedsBtn.setObjectName("savedsBtn")
        self.gridLayout.addWidget(self.savedsBtn, 0, 0, 1, 1)
        self.buttonBox = QtWidgets.QDialogButtonBox(IDAngrConstraintsDialog)
        self.buttonBox.setMinimumSize(QtCore.QSize(0, 48))
        self.buttonBox.setOrientation(QtCore.Qt.Horizontal)
        self.buttonBox.setStandardButtons(QtWidgets.QDialogButtonBox.Cancel|QtWidgets.QDialogButtonBox.Ok)
        self.buttonBox.setObjectName("buttonBox")
        self.gridLayout.addWidget(self.buttonBox, 0, 1, 1, 1)
        self.gridLayout_2.addLayout(self.gridLayout, 1, 0, 1, 1)

        self.retranslateUi(IDAngrConstraintsDialog)
        self.buttonBox.accepted.connect(IDAngrConstraintsDialog.accept)
        self.buttonBox.rejected.connect(IDAngrConstraintsDialog.reject)
        QtCore.QMetaObject.connectSlotsByName(IDAngrConstraintsDialog)

    def retranslateUi(self, IDAngrConstraintsDialog):
        _translate = QtCore.QCoreApplication.translate
        IDAngrConstraintsDialog.setWindowTitle(_translate("IDAngrConstraintsDialog", "Edit Constraints"))
        self.savedsBtn.setText(_translate("IDAngrConstraintsDialog", "Predefined constraints"))

