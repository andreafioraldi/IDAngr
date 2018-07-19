from PyQt5 import QtCore, QtGui, QtWidgets
from PyQt5.QtCore import Qt

from ui import *

from angrdbg import *

import angr
import claripy

import idaapi
import idc
import idautils

import glob
import os

import manage
import context_gui as ctx

class IDAngrTextViewerForm(QtWidgets.QDialog):
    
    def __init__(self, text, title):
        QtWidgets.QDialog.__init__(self)
        self.text = text
        self.ui = Ui_IDAngrTextViewer()
        self.ui.setupUi(self)
        if title:
            self.setWindowTitle(title)
        self.ui.plainTextEdit.setPlainText(str(text))
        self.ui.plainBox.toggled.connect(self.plain_toggled)
        self.ui.hexBox.toggled.connect(self.hex_toggled)
        self.ui.pyBox.toggled.connect(self.py_toggled)

    def plain_toggled(self, enabled):
        if enabled:
            self.ui.plainTextEdit.setPlainText(str(self.text))
    
    def hex_toggled(self, enabled):
        if enabled:
            self.ui.plainTextEdit.setPlainText(str(self.text).encode("hex"))
    
    def py_toggled(self, enabled):
        if self.ui.pyBox.isChecked():
            self.ui.plainTextEdit.setPlainText(repr(self.text))
    
    @staticmethod
    def show_text(text, title=None):
        frm = IDAngrTextViewerForm(text, title)
        frm.exec_()


class IDAngrEditorDialog(QtWidgets.QDialog):
    
    def __init__(self, title, text=""):
        QtWidgets.QDialog.__init__(self)
        
        self.ui = Ui_IDAngrEditorDialog()
        self.ui.setupUi(self)
        
        self.setWindowTitle("Editor - " + str(title))
        
        self.ui.codeEdit.setPlainText(text)
        self.h = PythonHighlighter(self.ui.codeEdit.document())
    
    @staticmethod
    def go(title, text=""):
        dialog = IDAngrConstraintsDialog(title, text)
        
        r = dialog.exec_()
        if r == QtWidgets.QDialog.Accepted:
            return dialog.ui.codeEdit.toPlainText()


class IDAngrHookDialog(IDAngrEditorDialog):
    
    def __init__(self, addr, text=""):
        if type(addr) in (int, long):
            addr = hex(addr).replace("L","")
        title = str(addr) + " Hook"
        
        IDAngrEditorDialog.__init__(self, title, text)
    
    @staticmethod
    def get_hook(addr):
        code = IDAngrHookDialog.go()
        if code is None:
            return None
        
        pass


class IDAngrAddMemDialog(QtWidgets.QDialog):
    
    def __init__(self):
        QtWidgets.QDialog.__init__(self)
        
        self.ui = Ui_IDAngrAddMem()
        self.ui.setupUi(self)
        
        self.ui.lenTextEdit.setText(str(load_project().arch.bits / 8))
        
    def set_addr(self, addr):
        if type(addr) == int or type(addr) == long:
            addr = "0x%x" % addr
        self.ui.addrTextEdit.setText(addr)
    
    @staticmethod
    def get_mem(addr):
        dialog = IDAngrAddMemDialog()
        dialog.set_addr(addr)
        r = dialog.exec_()
        if r == QtWidgets.QDialog.Accepted:
            addr = dialog.ui.addrTextEdit.displayText()
            try:
                addr = int(addr, 16)
            except:
                QtWidgets.QMessageBox(QtWidgets.QMessageBox.Critical, 'Error', "Address not in hex format").exec_()
                return None
            length = dialog.ui.lenTextEdit.displayText()
            try:
                length = int(length)
            except:
                QtWidgets.QMessageBox(QtWidgets.QMessageBox.Critical, 'Error', "Length not in dec format").exec_()
                return None
            return (addr, length)
        return None



class IDAngrSavedsDialog(QtWidgets.QDialog):
    
    def __init__(self, folder, title):
        QtWidgets.QDialog.__init__(self)
        
        self.ui = Ui_IDAngrSavedsDialog()
        self.ui.setupUi(self)
        
        self.setWindowTitle(title)
        self.h = PythonHighlighter(self.ui.codeView.document())
        
        self.folder = folder
        self.files_list = []
        for path in glob.glob(os.path.join(folder, "*.py")):
            self.files_list.append(os.path.basename(path)[:-3])
        
        self.ui.selectorList.setModel(QtCore.QStringListModel(self.files_list))
        self.model = self.ui.selectorList.selectionModel()
        self.model.selectionChanged.connect(self.selector_clicked)
        
    def selector_clicked(self):
        item = self.model.selection().indexes()[0]
        path = os.path.join(self.folder, item.data() + ".py")
        with open(path, "r") as f:
            code = f.read()
        self.ui.codeView.setPlainText(code)
        
    
    @staticmethod
    def go(folder, title="Saveds"):
        dialog = IDAngrSavedsDialog(folder, title)
        r = dialog.exec_()
        if r == QtWidgets.QDialog.Accepted:
            return dialog.ui.codeView.toPlainText()
        


class IDAngrConstraintsDialog(QtWidgets.QDialog):
    
    def __init__(self, item, text=""):
        QtWidgets.QDialog.__init__(self)
        
        self.ui = Ui_IDAngrConstraintsDialog()
        self.ui.setupUi(self)
        
        if type(item) in (int, long):
            item = hex(item).replace("L","")
        
        self.ui.constrEdit.setPlainText(text)
        self.setWindowTitle("Edit Constraints - " + str(item))
        self.h = PythonHighlighter(self.ui.constrEdit.document())
        
        self.ui.savedsBtn.clicked.connect(self.saveds_clicked)
        
    def saveds_clicked(self):
        code = IDAngrSavedsDialog.go(os.path.join(os.path.dirname(__file__), "saveds", "constraints"), "Predefined Constraints")
        if code == None:
            return
        self.ui.constrEdit.setPlainText(code)
    
    @staticmethod
    def go(item):
        
        if item in ctx.constraints:
            dialog = IDAngrConstraintsDialog(item, ctx.constraints[item][0])
        else:
            dialog = IDAngrConstraintsDialog(item, "# add your constraints to the var 'sym' using the var 'state'\n")
        
        r = dialog.exec_()
        if r == QtWidgets.QDialog.Accepted:
            code = dialog.ui.constrEdit.toPlainText()
            func = "def constr_func(sym, state):\n"
            for line in code.split("\n"):
                func += "\t" + line + "\n"
            try:
                if manage.is_remote():
                    manage.remote_exec(func)
                else:
                    exec(func) in globals()
            except Exception as ee:
                QtWidgets.QMessageBox(QtWidgets.QMessageBox.Critical, 'Constraints Code - Python Error', str(ee)).exec_()
                return
            
            if manage.is_remote():
                ctx.constraints[item] = (code, manage.remote_eval("constr_func"))
            else:
                ctx.constraints[item] = (code, constr_func)
        
    
class IDAngrExecDialog(QtWidgets.QDialog):
    
    def __init__(self):
        QtWidgets.QDialog.__init__(self)
        
        self.ui = Ui_IDAngrExecDialog()
        self.ui.setupUi(self)
        
        if ctx.find_lambda:
            self.ui.findCondEdit.setPlainText(ctx.find_lambda)
        if ctx.avoid_lambda:
            self.ui.avoidCondEdit.setPlainText(ctx.avoid_lambda)

        self.ui.simprocsBox.setChecked(get_memory_type() == SIMPROCS_FROM_CLE)
        self.ui.textloaderBox.setChecked(get_memory_type() == USE_CLE_MEMORY)
        self.ui.gotloaderBox.setChecked(get_memory_type() == ONLY_GOT_FROM_CLE)
        self.ui.execallBox.setChecked(get_memory_type() == GET_ALL_DISCARD_CLE)
        
        self.fh = PythonHighlighter(self.ui.findCondEdit.document())
        self.ah = PythonHighlighter(self.ui.avoidCondEdit.document())
    
    @staticmethod
    def go():
        dialog = IDAngrExecDialog()
        r = dialog.exec_()
        if r == QtWidgets.QDialog.Accepted:
            if dialog.ui.simprocsBox.isChecked():
                set_memory_type(SIMPROCS_FROM_CLE)
            elif dialog.ui.textloaderBox.isChecked():
                set_memory_type(USE_CLE_MEMORY)
            elif dialog.ui.gotloaderBox.isChecked():
                set_memory_type(ONLY_GOT_FROM_CLE)
            elif dialog.ui.execallBox.isChecked():
                set_memory_type(GET_ALL_DISCARD_CLE)
            
            if dialog.ui.useFindCondBox.isChecked():
                code = dialog.ui.findCondEdit.toPlainText()
                ctx.find_lambda = code
                finds = ctx.find
                avoids = ctx.avoid
                try:
                    if manage.is_remote():
                        manage.remote_exec("finds = %s" % repr(finds))
                        manage.remote_exec("avoids = %s" % repr(finds))
                        manage.remote_exec(code)
                    else:
                        exec(code) in locals()
                except Exception as ee:
                    QtWidgets.QMessageBox(QtWidgets.QMessageBox.Critical, 'Find Condition - Python Error', str(ee)).exec_()
                    return None
                try:
                    if manage.is_remote():
                        find = manage.remote_eval("find_cond")
                    else:
                        find = find_cond
                except:
                    QtWidgets.QMessageBox(QtWidgets.QMessageBox.Critical, 'Error', "find_cond not defined").exec_()
                    return None
            else:
                find = ctx.find
            if dialog.ui.useAvoidCondBox.isChecked():
                code = dialog.ui.avoidCondEdit.toPlainText()
                ctx.avoid_lambda = code
                finds = ctx.find
                avoids = ctx.avoid
                try:
                    if manage.is_remote():
                        manage.remote_exec("finds = %s" % repr(finds))
                        manage.remote_exec("avoids = %s" % repr(finds))
                        manage.remote_exec(code)
                    else:
                        exec(code) in locals()
                except Exception as ee:
                    QtWidgets.QMessageBox(QtWidgets.QMessageBox.Critical, 'Avoid Condition - Python Error', str(ee)).exec_()
                    return None
                try:
                    if manage.is_remote():
                        avoid = manage.remote_eval("avoid_cond")
                    else:
                        avoid = avoid_cond
                except:
                    QtWidgets.QMessageBox(QtWidgets.QMessageBox.Critical, 'Error', "avoid_cond not defined").exec_()
                    return None
            else:
                avoid = ctx.avoid
            return (find, avoid)
        return None
            

