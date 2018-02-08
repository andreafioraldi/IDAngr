# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'idangr_panel.ui'
#
# Created by: PyQt5 UI code generator 5.5.1
#
# WARNING! All changes made in this file will be lost!

from PyQt5 import QtCore, QtGui, QtWidgets

class Ui_Form(object):
    def setupUi(self, Form):
        Form.setObjectName("Form")
        Form.resize(1614, 1321)
        self.gridLayout_3 = QtWidgets.QGridLayout(Form)
        self.gridLayout_3.setObjectName("gridLayout_3")
        self.resetBtn = QtWidgets.QPushButton(Form)
        self.resetBtn.setObjectName("resetBtn")
        self.gridLayout_3.addWidget(self.resetBtn, 0, 0, 1, 1)
        self.resetBtn_2 = QtWidgets.QPushButton(Form)
        self.resetBtn_2.setObjectName("resetBtn_2")
        self.gridLayout_3.addWidget(self.resetBtn_2, 0, 1, 1, 1)
        spacerItem = QtWidgets.QSpacerItem(1352, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.gridLayout_3.addItem(spacerItem, 0, 2, 1, 1)
        self.splitter = QtWidgets.QSplitter(Form)
        self.splitter.setOrientation(QtCore.Qt.Horizontal)
        self.splitter.setObjectName("splitter")
        self.widget = QtWidgets.QWidget(self.splitter)
        self.widget.setObjectName("widget")
        self.gridLayout_2 = QtWidgets.QGridLayout(self.widget)
        self.gridLayout_2.setObjectName("gridLayout_2")
        self.label = QtWidgets.QLabel(self.widget)
        self.label.setObjectName("label")
        self.gridLayout_2.addWidget(self.label, 0, 0, 1, 1)
        self.registerChooser = QtWidgets.QComboBox(self.widget)
        self.registerChooser.setObjectName("registerChooser")
        self.gridLayout_2.addWidget(self.registerChooser, 0, 1, 1, 1)
        self.regsView = QtWidgets.QTableView(self.widget)
        self.regsView.setObjectName("regsView")
        self.gridLayout_2.addWidget(self.regsView, 1, 0, 1, 2)
        self.widget1 = QtWidgets.QWidget(self.splitter)
        self.widget1.setObjectName("widget1")
        self.gridLayout = QtWidgets.QGridLayout(self.widget1)
        self.gridLayout.setVerticalSpacing(20)
        self.gridLayout.setObjectName("gridLayout")
        self.label_2 = QtWidgets.QLabel(self.widget1)
        self.label_2.setObjectName("label_2")
        self.gridLayout.addWidget(self.label_2, 0, 0, 1, 1)
        self.memoryView = QtWidgets.QTableView(self.widget1)
        self.memoryView.setObjectName("memoryView")
        self.gridLayout.addWidget(self.memoryView, 1, 0, 1, 1)
        self.gridLayout_3.addWidget(self.splitter, 1, 0, 1, 3)

        self.retranslateUi(Form)
        QtCore.QMetaObject.connectSlotsByName(Form)

    def retranslateUi(self, Form):
        _translate = QtCore.QCoreApplication.translate
        Form.setWindowTitle(_translate("Form", "Form"))
        self.resetBtn.setText(_translate("Form", "RESET"))
        self.resetBtn_2.setText(_translate("Form", "TO DBG"))
        self.label.setText(_translate("Form", "   Symbolic registers"))
        self.label_2.setText(_translate("Form", "   Symbolic memory"))

