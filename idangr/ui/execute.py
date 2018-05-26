# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'execute.ui'
#
# Created by: PyQt5 UI code generator 5.10.1
#
# WARNING! All changes made in this file will be lost!

from PyQt5 import QtCore, QtGui, QtWidgets

class Ui_IDAngrExecDialog(object):
    def setupUi(self, IDAngrExecDialog):
        IDAngrExecDialog.setObjectName("IDAngrExecDialog")
        IDAngrExecDialog.resize(994, 634)
        self.gridLayout_4 = QtWidgets.QGridLayout(IDAngrExecDialog)
        self.gridLayout_4.setObjectName("gridLayout_4")
        self.gridLayout_3 = QtWidgets.QGridLayout()
        self.gridLayout_3.setObjectName("gridLayout_3")
        self.simprocsBox = QtWidgets.QRadioButton(IDAngrExecDialog)
        self.simprocsBox.setChecked(True)
        self.simprocsBox.setObjectName("simprocsBox")
        self.gridLayout_3.addWidget(self.simprocsBox, 0, 0, 1, 1)
        self.gotloaderBox = QtWidgets.QRadioButton(IDAngrExecDialog)
        self.gotloaderBox.setEnabled(True)
        self.gotloaderBox.setChecked(False)
        self.gotloaderBox.setObjectName("gotloaderBox")
        self.gridLayout_3.addWidget(self.gotloaderBox, 0, 1, 1, 1)
        self.textloaderBox = QtWidgets.QRadioButton(IDAngrExecDialog)
        self.textloaderBox.setChecked(False)
        self.textloaderBox.setObjectName("textloaderBox")
        self.gridLayout_3.addWidget(self.textloaderBox, 1, 0, 1, 1)
        self.execallBox = QtWidgets.QRadioButton(IDAngrExecDialog)
        self.execallBox.setObjectName("execallBox")
        self.gridLayout_3.addWidget(self.execallBox, 1, 1, 1, 1)
        self.gridLayout_4.addLayout(self.gridLayout_3, 0, 0, 1, 1)
        self.splitter = QtWidgets.QSplitter(IDAngrExecDialog)
        self.splitter.setOrientation(QtCore.Qt.Vertical)
        self.splitter.setObjectName("splitter")
        self.layoutWidget = QtWidgets.QWidget(self.splitter)
        self.layoutWidget.setObjectName("layoutWidget")
        self.gridLayout = QtWidgets.QGridLayout(self.layoutWidget)
        self.gridLayout.setContentsMargins(0, 0, 0, 0)
        self.gridLayout.setObjectName("gridLayout")
        self.useFindCondBox = QtWidgets.QCheckBox(self.layoutWidget)
        self.useFindCondBox.setObjectName("useFindCondBox")
        self.gridLayout.addWidget(self.useFindCondBox, 0, 0, 1, 1)
        self.findCondEdit = QtWidgets.QPlainTextEdit(self.layoutWidget)
        self.findCondEdit.setEnabled(True)
        self.findCondEdit.setObjectName("findCondEdit")
        self.gridLayout.addWidget(self.findCondEdit, 1, 0, 1, 1)
        self.layoutWidget1 = QtWidgets.QWidget(self.splitter)
        self.layoutWidget1.setObjectName("layoutWidget1")
        self.gridLayout_2 = QtWidgets.QGridLayout(self.layoutWidget1)
        self.gridLayout_2.setContentsMargins(0, 0, 0, 0)
        self.gridLayout_2.setObjectName("gridLayout_2")
        self.useAvoidCondBox = QtWidgets.QCheckBox(self.layoutWidget1)
        self.useAvoidCondBox.setObjectName("useAvoidCondBox")
        self.gridLayout_2.addWidget(self.useAvoidCondBox, 0, 0, 1, 1)
        self.avoidCondEdit = QtWidgets.QPlainTextEdit(self.layoutWidget1)
        self.avoidCondEdit.setEnabled(True)
        self.avoidCondEdit.setObjectName("avoidCondEdit")
        self.gridLayout_2.addWidget(self.avoidCondEdit, 1, 0, 1, 1)
        self.gridLayout_4.addWidget(self.splitter, 1, 0, 1, 1)
        self.buttonBox = QtWidgets.QDialogButtonBox(IDAngrExecDialog)
        self.buttonBox.setMaximumSize(QtCore.QSize(16777215, 48))
        self.buttonBox.setOrientation(QtCore.Qt.Horizontal)
        self.buttonBox.setStandardButtons(QtWidgets.QDialogButtonBox.Cancel|QtWidgets.QDialogButtonBox.Ok)
        self.buttonBox.setObjectName("buttonBox")
        self.gridLayout_4.addWidget(self.buttonBox, 2, 0, 1, 1)

        self.retranslateUi(IDAngrExecDialog)
        self.buttonBox.accepted.connect(IDAngrExecDialog.accept)
        self.buttonBox.rejected.connect(IDAngrExecDialog.reject)
        QtCore.QMetaObject.connectSlotsByName(IDAngrExecDialog)

    def retranslateUi(self, IDAngrExecDialog):
        _translate = QtCore.QCoreApplication.translate
        IDAngrExecDialog.setWindowTitle(_translate("IDAngrExecDialog", "Exec"))
        self.simprocsBox.setToolTip(_translate("IDAngrExecDialog", "<html><head/><body><p>The default memory mode.</p><p>The .got is populated with a mixture of simprocedures and resolved library addresses.</p><p>Simprocedures are used when possible.</p><p>The best option for ELF executables.</p></body></html>"))
        self.simprocsBox.setText(_translate("IDAngrExecDialog", "use simprocs in got when possible"))
        self.gotloaderBox.setToolTip(_translate("IDAngrExecDialog", "<html><head/><body><p>Get only the .got section from the angr loader to use default simprocedures insted of executing library code.</p></body></html>"))
        self.gotloaderBox.setText(_translate("IDAngrExecDialog", "get entire .got from CLE"))
        self.textloaderBox.setToolTip(_translate("IDAngrExecDialog", "<html><head/><body><p>Load the executable memory (.text, .rodata, .got ...) from the angr loader, faster but can\'t work with self modifying code and libraries loaded from the debugger will be not executed.</p></body></html>"))
        self.textloaderBox.setText(_translate("IDAngrExecDialog", "get .text and .got from CLE"))
        self.execallBox.setToolTip(_translate("IDAngrExecDialog", "<html><head/><body><p>Load all from debugger so default simprocedures will not be executed. Can be slow and not supported under certain condition (not fully tested).</p></body></html>"))
        self.execallBox.setText(_translate("IDAngrExecDialog", "full debugger memory"))
        self.useFindCondBox.setText(_translate("IDAngrExecDialog", "use find condition and not find addresses list (do not overwrite function name)"))
        self.useAvoidCondBox.setText(_translate("IDAngrExecDialog", "use avoid condition and not avoid addresses list (do not overwrite function name)"))

