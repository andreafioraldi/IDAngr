# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'exec.ui'
#
# Created by: PyQt5 UI code generator 5.5.1
#
# WARNING! All changes made in this file will be lost!

from PyQt5 import QtCore, QtGui, QtWidgets

class Ui_IDAngrExecDialog(object):
    def setupUi(self, IDAngrExecDialog):
        IDAngrExecDialog.setObjectName("IDAngrExecDialog")
        IDAngrExecDialog.resize(1251, 1013)
        self.gridLayout_3 = QtWidgets.QGridLayout(IDAngrExecDialog)
        self.gridLayout_3.setObjectName("gridLayout_3")
        self.splitter = QtWidgets.QSplitter(IDAngrExecDialog)
        self.splitter.setOrientation(QtCore.Qt.Vertical)
        self.splitter.setObjectName("splitter")
        self.widget = QtWidgets.QWidget(self.splitter)
        self.widget.setObjectName("widget")
        self.gridLayout = QtWidgets.QGridLayout(self.widget)
        self.gridLayout.setObjectName("gridLayout")
        self.useFindCondBox = QtWidgets.QCheckBox(self.widget)
        self.useFindCondBox.setObjectName("useFindCondBox")
        self.gridLayout.addWidget(self.useFindCondBox, 0, 0, 1, 1)
        self.findCondEdit = QtWidgets.QPlainTextEdit(self.widget)
        self.findCondEdit.setEnabled(False)
        self.findCondEdit.setObjectName("findCondEdit")
        self.gridLayout.addWidget(self.findCondEdit, 1, 0, 1, 1)
        self.layoutWidget = QtWidgets.QWidget(self.splitter)
        self.layoutWidget.setObjectName("layoutWidget")
        self.gridLayout_2 = QtWidgets.QGridLayout(self.layoutWidget)
        self.gridLayout_2.setObjectName("gridLayout_2")
        self.useAvoidCondBox = QtWidgets.QCheckBox(self.layoutWidget)
        self.useAvoidCondBox.setObjectName("useAvoidCondBox")
        self.gridLayout_2.addWidget(self.useAvoidCondBox, 0, 0, 1, 1)
        self.findAvoidCondEdit = QtWidgets.QPlainTextEdit(self.layoutWidget)
        self.findAvoidCondEdit.setEnabled(False)
        self.findAvoidCondEdit.setObjectName("findAvoidCondEdit")
        self.gridLayout_2.addWidget(self.findAvoidCondEdit, 1, 0, 1, 1)
        self.gridLayout_3.addWidget(self.splitter, 1, 0, 1, 1)
        self.buttonBox = QtWidgets.QDialogButtonBox(IDAngrExecDialog)
        self.buttonBox.setMaximumSize(QtCore.QSize(16777215, 48))
        self.buttonBox.setOrientation(QtCore.Qt.Horizontal)
        self.buttonBox.setStandardButtons(QtWidgets.QDialogButtonBox.Cancel|QtWidgets.QDialogButtonBox.Ok)
        self.buttonBox.setObjectName("buttonBox")
        self.gridLayout_3.addWidget(self.buttonBox, 2, 0, 1, 1)
        self.horizontalLayout = QtWidgets.QHBoxLayout()
        self.horizontalLayout.setObjectName("horizontalLayout")
        self.verytestingBox = QtWidgets.QCheckBox(IDAngrExecDialog)
        self.verytestingBox.setObjectName("verytestingBox")
        self.horizontalLayout.addWidget(self.verytestingBox)
        self.gridLayout_3.addLayout(self.horizontalLayout, 0, 0, 1, 1)

        self.retranslateUi(IDAngrExecDialog)
        self.buttonBox.accepted.connect(IDAngrExecDialog.accept)
        self.buttonBox.rejected.connect(IDAngrExecDialog.reject)
        QtCore.QMetaObject.connectSlotsByName(IDAngrExecDialog)

    def retranslateUi(self, IDAngrExecDialog):
        _translate = QtCore.QCoreApplication.translate
        IDAngrExecDialog.setWindowTitle(_translate("IDAngrExecDialog", "Exec"))
        self.useFindCondBox.setText(_translate("IDAngrExecDialog", "use find condition and not find addresses list"))
        self.useAvoidCondBox.setText(_translate("IDAngrExecDialog", "use avoid condition and not avoid addresses list"))
        self.verytestingBox.setText(_translate("IDAngrExecDialog", "verytesting"))

