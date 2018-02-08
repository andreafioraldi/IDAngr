# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'idangr_panel.ui'
#
# Created by: PyQt5 UI code generator 5.5.1
#
# WARNING! All changes made in this file will be lost!

from PyQt5 import QtCore, QtGui, QtWidgets

class Ui_IDAngrPanel(object):
    def setupUi(self, IDAngrPanel):
        IDAngrPanel.setObjectName("IDAngrPanel")
        IDAngrPanel.resize(1614, 1321)
        IDAngrPanel.setLayoutDirection(QtCore.Qt.LeftToRight)
        self.gridLayout_3 = QtWidgets.QGridLayout(IDAngrPanel)
        self.gridLayout_3.setObjectName("gridLayout_3")
        self.resetBtn = QtWidgets.QPushButton(IDAngrPanel)
        self.resetBtn.setObjectName("resetBtn")
        self.gridLayout_3.addWidget(self.resetBtn, 0, 0, 1, 1)
        self.todbgBtn = QtWidgets.QPushButton(IDAngrPanel)
        self.todbgBtn.setEnabled(False)
        self.todbgBtn.setObjectName("todbgBtn")
        self.gridLayout_3.addWidget(self.todbgBtn, 0, 1, 1, 1)
        spacerItem = QtWidgets.QSpacerItem(1352, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.gridLayout_3.addItem(spacerItem, 0, 2, 1, 1)
        self.splitter = QtWidgets.QSplitter(IDAngrPanel)
        self.splitter.setOrientation(QtCore.Qt.Horizontal)
        self.splitter.setObjectName("splitter")
        self.layoutWidget = QtWidgets.QWidget(self.splitter)
        self.layoutWidget.setObjectName("layoutWidget")
        self.gridLayout = QtWidgets.QGridLayout(self.layoutWidget)
        self.gridLayout.setVerticalSpacing(20)
        self.gridLayout.setObjectName("gridLayout")
        self.label_2 = QtWidgets.QLabel(self.layoutWidget)
        self.label_2.setObjectName("label_2")
        self.gridLayout.addWidget(self.label_2, 0, 0, 1, 1)
        self.memoryView = QtWidgets.QTableView(self.layoutWidget)
        self.memoryView.setObjectName("memoryView")
        self.gridLayout.addWidget(self.memoryView, 1, 0, 1, 1)
        self.layoutWidget1 = QtWidgets.QWidget(self.splitter)
        self.layoutWidget1.setObjectName("layoutWidget1")
        self.gridLayout_2 = QtWidgets.QGridLayout(self.layoutWidget1)
        self.gridLayout_2.setObjectName("gridLayout_2")
        self.label = QtWidgets.QLabel(self.layoutWidget1)
        self.label.setObjectName("label")
        self.gridLayout_2.addWidget(self.label, 0, 0, 1, 1)
        self.regsView = QtWidgets.QTableView(self.layoutWidget1)
        self.regsView.setObjectName("regsView")
        self.gridLayout_2.addWidget(self.regsView, 1, 0, 1, 2)
        self.registerChooser = QtWidgets.QComboBox(self.layoutWidget1)
        self.registerChooser.setObjectName("registerChooser")
        self.gridLayout_2.addWidget(self.registerChooser, 0, 1, 1, 1)
        self.gridLayout_3.addWidget(self.splitter, 1, 0, 1, 3)

        self.retranslateUi(IDAngrPanel)
        QtCore.QMetaObject.connectSlotsByName(IDAngrPanel)

    def retranslateUi(self, IDAngrPanel):
        _translate = QtCore.QCoreApplication.translate
        IDAngrPanel.setWindowTitle(_translate("IDAngrPanel", "IDAngr Panel"))
        self.resetBtn.setText(_translate("IDAngrPanel", "RESET"))
        self.todbgBtn.setText(_translate("IDAngrPanel", "TO DBG"))
        self.label_2.setText(_translate("IDAngrPanel", "   Symbolic memory"))
        self.label.setText(_translate("IDAngrPanel", "   Symbolic registers"))

