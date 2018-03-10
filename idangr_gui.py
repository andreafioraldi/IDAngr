from idaapi import PluginForm
from PyQt5 import QtCore, QtGui, QtWidgets
from PyQt5.QtCore import Qt

from ui import *
from idangr import *

import sip
import pickle

class IDAngrCtx(object):
    def __init__(self):
        self.find = []
        self.avoid = []
        self.find_lambda = "def find_cond(state):\n\tsol = state.solver.eval\n\tfor addr in finds:\n\t\tif sol(state.regs.pc) == addr: return True\n\treturn False"
        self.avoid_lambda = "def avoid_cond(state):\n\tsol = state.solver.eval\n\tfor addr in avoids:\n\t\tif sol(state.regs.pc) == addr: return True\n\treturn False"
        self.regs = []
        self.simregs = []
        self.simmem = []
        self.constraints = {} #{ item: (code string, lambda) }
        self.stateman = None
        self.foundstate = None
        self.simman = None

_idangr_ctx = IDAngrCtx()

def saveCtx(filename):
    global _idangr_ctx
    with open(filename, "wb") as fh:
        pickle.dump(_idangr_ctx, fh)

def loadCtx(filename):
    global _idangr_ctx
    with open(filename, "rb") as fh:
        _idangr_ctx = pickle.load(fh)


class IDAngrTextViewerForm(QtWidgets.QDialog):
    
    def __init__(self, text, title):
        QtWidgets.QDialog.__init__(self)
        self.text = text
        self.ui = Ui_IDAngrTextViewer()
        self.ui.setupUi(self)
        if title:
            self.setWindowTitle(title)
        self.ui.plainTextEdit.setPlainText(str(text))
        self.ui.plainBox.toggled.connect(self.plainToggled)
        self.ui.hexBox.toggled.connect(self.hexToggled)
        self.ui.pyBox.toggled.connect(self.pyToggled)

    def plainToggled(self, enabled):
        if enabled:
            self.ui.plainTextEdit.setPlainText(str(self.text))
    
    def hexToggled(self, enabled):
        if enabled:
            self.ui.plainTextEdit.setPlainText(str(self.text).encode("hex"))
    
    def pyToggled(self, enabled):
        if self.ui.pyBox.isChecked():
            self.ui.plainTextEdit.setPlainText(repr(self.text))
    
    @staticmethod
    def showText(text, title=None):
        frm = IDAngrTextViewerForm(text, title)
        frm.exec_()

class IDAngrAddMemDialog(QtWidgets.QDialog):
    
    def __init__(self):
        QtWidgets.QDialog.__init__(self)
        
        self.ui = Ui_IDAngrAddMem()
        self.ui.setupUi(self)
        
        self.ui.lenTextEdit.setPlainText(str(load_project().arch.bits / 8))
        
    def setAddr(self, addr):
        if type(addr) == int or type(addr) == long:
            addr = "0x%x" % addr
        self.ui.addrTextEdit.setPlainText(addr)
    
    @staticmethod
    def getMem(addr):
        dialog = IDAngrAddMemDialog()
        dialog.setAddr(addr)
        r = dialog.exec_()
        if r == QtWidgets.QDialog.Accepted:
            addr = dialog.ui.addrTextEdit.toPlainText()
            try:
                addr = int(addr, 16)
            except:
                QtWidgets.QMessageBox(QtWidgets.QMessageBox.Critical, 'Error', "Address not in hex format").exec_()
                return None
            length = dialog.ui.lenTextEdit.toPlainText()
            try:
                length = int(length)
            except:
                QtWidgets.QMessageBox(QtWidgets.QMessageBox.Critical, 'Error', "Length not in dec format").exec_()
                return None
            return (addr, length)
        return None


class IDAngrConstraintsDialog(QtWidgets.QDialog):
    
    def __init__(self, item, text=""):
        QtWidgets.QDialog.__init__(self)
        
        self.ui = Ui_IDAngrConstraintsDialog()
        self.ui.setupUi(self)
        
        if type(item) in (int, long):
            item = hex(item)
        
        self.ui.constrEdit.setPlainText(text)
        self.setWindowTitle("Edit Constraints - " + str(item))
        self.h = PythonHighlighter(self.ui.constrEdit.document())
    
    @staticmethod
    def go(item):
        global _idangr_ctx
        if item in _idangr_ctx.constraints:
            dialog = IDAngrConstraintsDialog(item, _idangr_ctx.constraints[item][0])
        else:
            dialog = IDAngrConstraintsDialog(item, "# add your constraints to the var 'sym' using the var 'state'\n")
        
        r = dialog.exec_()
        if r == QtWidgets.QDialog.Accepted:
            code = dialog.ui.constrEdit.toPlainText()
            func = "def constr_func(sym, state):\n"
            for line in code.split("\n"):
                func += "\t" + line + "\n"
            try:
                exec(func) in globals()
            except Exception as ee:
                QtWidgets.QMessageBox(QtWidgets.QMessageBox.Critical, 'Constraints Code - Python Error', str(ee)).exec_()
            _idangr_ctx.constraints[item] = (code, constr_func)
        
    
class IDAngrExecDialog(QtWidgets.QDialog):
    
    def __init__(self):
        global _idangr_ctx
        QtWidgets.QDialog.__init__(self)
        
        self.ui = Ui_IDAngrExecDialog()
        self.ui.setupUi(self)
        
        if _idangr_ctx.find_lambda:
            self.ui.findCondEdit.setPlainText(_idangr_ctx.find_lambda)
        if _idangr_ctx.avoid_lambda:
            self.ui.avoidCondEdit.setPlainText(_idangr_ctx.avoid_lambda)
        
        self.fh = PythonHighlighter(self.ui.findCondEdit.document())
        self.ah = PythonHighlighter(self.ui.avoidCondEdit.document())
    
    @staticmethod
    def go():
        global _idangr_ctx
        dialog = IDAngrExecDialog()
        r = dialog.exec_()
        if r == QtWidgets.QDialog.Accepted:
            if dialog.ui.useFindCondBox.isChecked():
                code = dialog.ui.findCondEdit.toPlainText()
                _idangr_ctx.find_lambda = code
                finds = _idangr_ctx.find
                avoids = _idangr_ctx.avoid
                try:
                    exec(code) in locals()
                except Exception as ee:
                    QtWidgets.QMessageBox(QtWidgets.QMessageBox.Critical, 'Find Condition - Python Error', str(ee)).exec_()
                    return None
                try:
                    find = find_cond
                except:
                    QtWidgets.QMessageBox(QtWidgets.QMessageBox.Critical, 'Error', "find_cond not defined").exec_()
                    return None
            else:
                find = _idangr_ctx.find
            if dialog.ui.useAvoidCondBox.isChecked():
                code = dialog.ui.avoidCondEdit.toPlainText()
                _idangr_ctx.avoid_lambda = code
                finds = _idangr_ctx.find
                avoids = _idangr_ctx.avoid
                try:
                    exec(code) in locals()
                except Exception as ee:
                    QtWidgets.QMessageBox(QtWidgets.QMessageBox.Critical, 'Avoid Condition - Python Error', str(ee)).exec_()
                    return None
                try:
                    avoid = avoid_cond
                except:
                    QtWidgets.QMessageBox(QtWidgets.QMessageBox.Critical, 'Error', "avoid_cond not defined").exec_()
                    return None
            else:
                avoid = _idangr_ctx.avoid
            return (find, avoid)
        return None
            

class IDAngrTableModel(QtCore.QAbstractTableModel):

    def __init__(self, datain, headerdata, parent=None):
        QtCore.QAbstractTableModel.__init__(self, parent)
        self.arraydata = datain
        self.headerdata = headerdata

    def rowCount(self, parent):
        return len(self.arraydata)

    def columnCount(self, parent):
        if len(self.arraydata) > 0: 
            return len(self.arraydata[0]) 
        return 0

    def data(self, index, role):
        if not index.isValid():
            return None
        elif role != Qt.DisplayRole:
            return None
        return self.arraydata[index.row()][index.column()]

    def headerData(self, col, orientation, role):
        if orientation == Qt.Horizontal and role == Qt.DisplayRole:
            return self.headerdata[col]
        return None


class IDAngrPanelForm(PluginForm):
    
    def onFindCtxMenu(self, point):
        m = QtWidgets.QMenu(self.ui.findView)
        def delete():
            model = self.ui.findView.model()
            for i in self.ui.findView.selectedIndexes():
                model.removeRow(i.row())
        def jumpto():
            global _idangr_ctx
            model = self.ui.findView.model()
            sel = self.ui.findView.selectedIndexes()
            if len(sel) > 0:
                idc.jumpto(_idangr_ctx.find[sel[0].row()])
        m.addAction('Jump to', jumpto)
        m.addAction('Delete', delete)
        m.exec_(self.ui.findView.viewport().mapToGlobal(point))
    
    def onAvoidCtxMenu(self, point):
        m = QtWidgets.QMenu(self.ui.avoidView)
        def delete():
            model = self.ui.avoidView.model()
            for i in self.ui.avoidView.selectedIndexes():
                model.removeRow(i.row())
        def jumpto():
            global _idangr_ctx
            model = self.ui.avoidView.model()
            sel = self.ui.avoidView.selectedIndexes()
            if len(sel) > 0:
                idc.jumpto(_idangr_ctx.avoid[sel[0].row()])
        m.addAction('Jump to', jumpto)
        m.addAction('Delete', delete)
        m.exec_(self.ui.avoidView.viewport().mapToGlobal(point))

    def addFind(self, addr):
        item = QtWidgets.QListWidgetItem("0x%x" % addr)
        self.ui.findView.addItem(item)
    
    def removeFind(self, addr):
        model = self.ui.findView.model()
        for item in self.ui.findView.findItems("0x%x" % addr, Qt.MatchExactly):
            i = self.ui.findView.indexFromItem(item)
            model.removeRow(i.row())
    
    def addAvoid(self, addr):
        item = QtWidgets.QListWidgetItem("0x%x" % addr)
        self.ui.avoidView.addItem(item)
    
    def removeAvoid(self, addr):
        model = self.ui.avoidView.model()
        for item in self.ui.avoidView.findItems("0x%x" % addr, Qt.MatchExactly):
            i = self.ui.avoidView.indexFromItem(item)
            model.removeRow(i.row())
    
    
    def resetClicked(self):
        global _idangr_ctx
        while len(_idangr_ctx.simregs) > 0:
            _idangr_ctx.simregs.pop()
        while len(_idangr_ctx.simmem) > 0:
            _idangr_ctx.simmem.pop()
        _idangr_ctx.find = []
        _idangr_ctx.avoid = []
        _idangr_ctx.stateman = None
        _idangr_ctx.simman = None
        _idangr_ctx.foundstate = None
        self.ui.regsView.model().layoutChanged.emit()
        self.ui.memoryView.model().layoutChanged.emit()
        self.ui.findView.clear()
        self.ui.avoidView.clear()
        self.ui.todbgBtn.setEnabled(False)
        self.ui.viewFileBtn.setEnabled(False)
        self.ui.nextBtn.setEnabled(False)
        
    
    def runClicked(self):
        global _idangr_ctx
        conds = IDAngrExecDialog.go()
        if conds == None:
            return
        
        #TODO check if debugger is running
        _idangr_ctx.stateman = StateManager()
        for e in _idangr_ctx.simregs:
            _idangr_ctx.stateman.sim(e[0])
            if e[0] in _idangr_ctx.constraints:
                try:
                    _idangr_ctx.constraints[e[0]][1](_idangr_ctx.stateman.symbolics[e[0]][0], _idangr_ctx.stateman.state)
                except Exception as ee:
                    QtWidgets.QMessageBox(QtWidgets.QMessageBox.Critical, 'Constraints on %s - Python Error' % str(e[0]), str(ee)).exec_()
                    return
        for e in _idangr_ctx.simmem:
            addr = int(e[0], 16)
            _idangr_ctx.stateman.sim(addr, int(e[1]))
            if addr in _idangr_ctx.constraints:
                try:
                    _idangr_ctx.constraints[addr][1](_idangr_ctx.stateman.symbolics[int(e[0], 16)][0], _idangr_ctx.stateman.state)
                except Exception as ee:
                    QtWidgets.QMessageBox(QtWidgets.QMessageBox.Critical, 'Constraints on %s - Python Error' % str(e[0]), str(ee)).exec_()
                    return
        
        sm = _idangr_ctx.stateman.simulation_manager()
        _idangr_ctx.simman = sm
        
        sm.explore(find=conds[0], avoid=conds[1])
        if len(sm.found) == 0:
            QtWidgets.QMessageBox(QtWidgets.QMessageBox.Warning, 'Not Found', "Valid state not found after exploration.\n" + str(_idangr_ctx.stateman) + "\n").exec_()
            return
        _idangr_ctx.foundstate = sm.found[0]
        conc = _idangr_ctx.stateman.concretize(_idangr_ctx.foundstate)
        for i in xrange(len(_idangr_ctx.simregs)):
            try:
                _idangr_ctx.simregs[i][2] = "0x%x" % conc[_idangr_ctx.simregs[i][0]]
            except: pass
        for i in xrange(len(_idangr_ctx.simmem)):
            try:
                _idangr_ctx.simmem[i][2] = repr(conc[int(_idangr_ctx.simmem[i][0], 16)])
            except: pass
        #print _idangr_ctx.simmem
        
        self.ui.filesBox.setRange(0, len(_idangr_ctx.foundstate.posix.files) -1)
        
        self.ui.regsView.model().layoutChanged.emit()
        self.ui.memoryView.model().layoutChanged.emit()
        self.ui.todbgBtn.setEnabled(True)
        self.ui.viewFileBtn.setEnabled(True)
        self.ui.nextBtn.setEnabled(True)
        
        QtWidgets.QMessageBox(QtWidgets.QMessageBox.Information, 'Done', "Valid state found").exec_()
    
    
    def nextClicked(self):
        global _idangr_ctx
        conds = IDAngrExecDialog.go()
        if conds == None:
            return
        
        #TODO check if debugger is running
        if _idangr_ctx.stateman == None:
            _idangr_ctx.stateman = StateManager()
            for e in _idangr_ctx.simregs:
                _idangr_ctx.stateman.sim(e[0])
                if e[0] in _idangr_ctx.constraints:
                    try:
                        _idangr_ctx.constraints[e[0]][1](_idangr_ctx.stateman.symbolics[e[0]], _idangr_ctx.stateman.state)
                    except Exception as ee:
                        QtWidgets.QMessageBox(QtWidgets.QMessageBox.Critical, 'Constraints on %s - Python Error' % str(e[0]), str(ee)).exec_()
                        return
            for e in _idangr_ctx.simmem:
                addr = int(e[0], 16)
                _idangr_ctx.stateman.sim(addr, int(e[1]))
                if addr in _idangr_ctx.constraints:
                    try:
                        _idangr_ctx.constraints[addr][1](_idangr_ctx.stateman.symbolics[int(e[0], 16)], _idangr_ctx.stateman.state)
                    except Exception as ee:
                        QtWidgets.QMessageBox(QtWidgets.QMessageBox.Critical, 'Constraints on %s - Python Error' % str(e[0]), str(ee)).exec_()
                        return
        
        if _idangr_ctx.simman == None:
            if _idangr_ctx.foundstate == None:
                sm = _idangr_ctx.stateman.simulation_manager()
            else:
                sm = load_project().factory.simulation_manager(_idangr_ctx.foundstate)
            _idangr_ctx.simman = sm
        else:
            sm = _idangr_ctx.simman
        
        sm.explore(find=conds[0], avoid=conds[1])
        if len(sm.found) == 0:
            QtWidgets.QMessageBox(QtWidgets.QMessageBox.Warning, 'Not Found', "Valid state not found after exploration.\n" + str(_idangr_ctx.stateman) + "\n").exec_()
            return
        _idangr_ctx.foundstate = sm.found[-1]
        conc = _idangr_ctx.stateman.concretize(_idangr_ctx.foundstate)
        for i in xrange(len(_idangr_ctx.simregs)):
            try:
                _idangr_ctx.simregs[i][2] = "0x%x" % conc[_idangr_ctx.simregs[i][0]]
            except: pass
        for i in xrange(len(_idangr_ctx.simmem)):
            try:
                _idangr_ctx.simmem[i][2] = repr(conc[int(_idangr_ctx.simmem[i][0], 16)])
            except: pass
        #print _idangr_ctx.simmem
        self.ui.filesBox.setRange(0, len(_idangr_ctx.foundstate.posix.files) -1)
        
        self.ui.regsView.model().layoutChanged.emit()
        self.ui.memoryView.model().layoutChanged.emit()
        
        QtWidgets.QMessageBox(QtWidgets.QMessageBox.Information, 'Done', "Valid state found").exec_()

    
    def todbgClicked(self):
        global _idangr_ctx
        _idangr_ctx.stateman.to_dbg(_idangr_ctx.foundstate)
    
    
    def onRegsCtxMenu(self, point):
        global _idangr_ctx
        m = QtWidgets.QMenu(self.ui.regsView)
        def delete():
            model = self.ui.regsView.model()
            for i in self.ui.regsView.selectedIndexes():
                _idangr_ctx.simregs.pop(i.row())
            self.ui.regsView.model().layoutChanged.emit()
        def jumpto():
            model = self.ui.regsView.model()
            sel = self.ui.regsView.selectedIndexes()
            if len(sel) > 0:
                try:
                    addr = int(_idangr_ctx.simregs[sel[0].row()][2], 16)
                    idc.jumpto(addr)
                except:
                    pass
        def copyval():
            model = self.ui.regsView.model()
            sel = self.ui.regsView.selectedIndexes()
            if len(sel) > 0:
                cb = QtWidgets.QApplication.clipboard()
                cb.clear(mode=cb.Clipboard)
                cb.setText(_idangr_ctx.simregs[sel[0].row()][2], mode=cb.Clipboard)
        def set_constr():
            model = self.ui.regsView.model()
            sel = self.ui.regsView.selectedIndexes()
            if len(sel) > 0:
                item = _idangr_ctx.simregs[sel[0].row()][0]
                IDAngrConstraintsDialog.go(item)    
        m.addAction('Jump to', jumpto)
        m.addAction('Copy value', copyval)
        m.addAction('Set constraints', set_constr)
        m.addAction('Delete', delete)
        m.exec_(self.ui.regsView.viewport().mapToGlobal(point))

    def onMemCtxMenu(self, point):
        global _idangr_ctx
        m = QtWidgets.QMenu(self.ui.memoryView)
        def delete():
            model = self.ui.memoryView.model()
            for i in self.ui.memoryView.selectedIndexes():
                _idangr_ctx.simmem.pop(i.row())
            self.ui.memoryView.model().layoutChanged.emit()
        def jumpto():
            model = self.ui.memoryView.model()
            sel = self.ui.memoryView.selectedIndexes()
            if len(sel) > 0:
                idc.jumpto(int(_idangr_ctx.simmem[sel[0].row()][0], 16))
        def copyval():
            model = self.ui.memoryView.model()
            sel = self.ui.memoryView.selectedIndexes()
            if len(sel) > 0:
                cb = QtWidgets.QApplication.clipboard()
                cb.clear(mode=cb.Clipboard)
                cb.setText(_idangr_ctx.simmem[sel[0].row()][2], mode=cb.Clipboard)
        def set_constr():
            model = self.ui.memoryView.model()
            sel = self.ui.memoryView.selectedIndexes()
            if len(sel) > 0:
                item = int(_idangr_ctx.simmem[sel[0].row()][0], 16)
                IDAngrConstraintsDialog.go(item)
        m.addAction('Jump to', jumpto)
        m.addAction('Copy value', copyval)
        m.addAction('Set constraints', set_constr)
        m.addAction('Delete', delete)
        m.exec_(self.ui.memoryView.viewport().mapToGlobal(point))

    
    def addReg(self, idx):
        global _idangr_ctx
        reg = _idangr_ctx.regs[idx]
        for row in _idangr_ctx.simregs: #don't add a reg twice
            if row[0] == reg:
                return
        _idangr_ctx.simregs.append([reg, load_project().arch.registers[reg][1], "?"])
        self.ui.regsView.model().layoutChanged.emit()
    
    def addMem(self, addr, size):
        global _idangr_ctx
        if type(addr) == int or type(addr) == long:
            addr = "0x%x" % addr
        _idangr_ctx.simmem.append([addr, size, "?"])
        self.ui.memoryView.model().layoutChanged.emit()
    
    def removeMem(self, addr):
        pass
    
    
    
    def viewFileClicked(self):
        global _idangr_ctx
        fd = self.ui.filesBox.value()
        IDAngrTextViewerForm.showText(_idangr_ctx.foundstate.posix.dumps(fd), "File %d Viewer" % fd)
    
    def loadClicked(self):
        global _idangr_ctx
        filename = QtWidgets.QFileDialog.getOpenFileName(self.parent, 'Open File')[0]
        if filename != "":
            self.resetClicked()
            loadCtx(filename)
            for addr in _idangr_ctx.find:
                self.addFind(addr)
            for addr in _idangr_ctx.avoid:
                self.addAvoid(addr)
                
            tablemodel = IDAngrTableModel(_idangr_ctx.simregs, ['Name', 'Size', 'Value'], self.parent)
            self.ui.regsView.setModel(tablemodel)
            self.ui.regsView.resizeColumnsToContents()
            
            tablemodel = IDAngrTableModel(_idangr_ctx.simmem, ['Address', 'Length', 'Value'], self.parent)
            self.ui.memoryView.setModel(tablemodel)
            self.ui.memoryView.resizeColumnsToContents()
        
    
    def saveClicked(self):
        global _idangr_ctx
        filename = QtWidgets.QFileDialog.getSaveFileName(self.parent, 'Save File')[0]
        if filename != "":
            saveCtx(filename)
    
    
    def OnCreate(self, form):
        """
        Called when the plugin form is created
        """
        global _idangr_ctx
        # Get parent widget
        self.parent = self.FormToPyQtWidget(form)
        
        self.ui = Ui_IDAngrPanel()
        self.ui.setupUi(self.parent)
        
        project = load_project()
        
        self.ui.findView.customContextMenuRequested.connect(self.onFindCtxMenu)
        self.ui.avoidView.customContextMenuRequested.connect(self.onAvoidCtxMenu)

        self.ui.resetBtn.clicked.connect(self.resetClicked)
        self.ui.runBtn.clicked.connect(self.runClicked)
        self.ui.nextBtn.clicked.connect(self.nextClicked)
        self.ui.todbgBtn.clicked.connect(self.todbgClicked)
        self.ui.viewFileBtn.clicked.connect(self.viewFileClicked)
        self.ui.loadBtn.clicked.connect(self.loadClicked)
        self.ui.saveBtn.clicked.connect(self.saveClicked)
        
        _idangr_ctx.regs = sorted(project.arch.registers, key=lambda x: project.arch.registers.get(x)[0])
        
        for reg in _idangr_ctx.regs:
            self.ui.registerChooser.addItem(reg)
        
        self.ui.registerChooser.setCurrentIndex(-1)
        self.ui.registerChooser.currentIndexChanged.connect(self.addReg)
        
        tablemodel = IDAngrTableModel(_idangr_ctx.simregs, ['Name', 'Size', 'Value'], self.parent)
        self.ui.regsView.setModel(tablemodel)
        self.ui.regsView.resizeColumnsToContents()
        
        tablemodel = IDAngrTableModel(_idangr_ctx.simmem, ['Address', 'Length', 'Value'], self.parent)
        self.ui.memoryView.setModel(tablemodel)
        self.ui.memoryView.resizeColumnsToContents()
        
        self.ui.regsView.customContextMenuRequested.connect(self.onRegsCtxMenu)
        self.ui.memoryView.customContextMenuRequested.connect(self.onMemCtxMenu)
        
        

    def OnClose(self, form):
        """
        Called when the plugin form is closed
        """
        global _idangr_panel
        del _idangr_panel


    def Show(self):
        """Creates the form is not created or focuses it if it was"""
        return PluginForm.Show(self,
                               "IDAngr Panel",
                               options = PluginForm.FORM_PERSIST)




class IDAngrActionHandler(idaapi.action_handler_t):

    def __init__(self, action):
        idaapi.action_handler_t.__init__(self)
        self.action = action
    
    def activate(self, ctx):
        global _idangr_ctx, _idangr_panel
        if self.action == "Find":
            addr = idaapi.get_screen_ea()
            if addr in _idangr_ctx.avoid:
                _idangr_ctx.avoid.remove(addr)
                _idangr_panel.removeAvoid(addr)
            if addr in _idangr_ctx.find:
                return
            _idangr_ctx.find.append(addr)
            _idangr_panel.addFind(addr)
        elif self.action == "Avoid":
            addr = idaapi.get_screen_ea()
            if addr in _idangr_ctx.find:
                _idangr_ctx.find.remove(addr)
                _idangr_panel.removeFind(addr)
            if addr in _idangr_ctx.avoid:
                return
            _idangr_ctx.avoid.append(addr)
            _idangr_panel.addAvoid(addr)
        elif self.action == "Symbolic":
            addr = idaapi.get_screen_ea()
            #if addr in _idangr_ctx.simmem:
            #    return
            m = IDAngrAddMemDialog.getMem(addr)
            if m != None:
                _idangr_panel.addMem(m[0], m[1])
                #_idangr_ctx.simmem.append(m)
        
        
    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS

class IDAngrHooks(idaapi.UI_Hooks):

    @staticmethod
    def finish_populating_tform_popup(form, popup):
        idaapi.attach_action_to_popup(form, popup, "Find", "IDAngr/")
        idaapi.attach_action_to_popup(form, popup, "Avoid", "IDAngr/")
        idaapi.attach_action_to_popup(form, popup, "Symbolic", "IDAngr/")


print "######### IDAngr GUI #########"

idaapi.register_action(idaapi.action_desc_t('Find', 'Find', IDAngrActionHandler("Find")))
idaapi.register_action(idaapi.action_desc_t('Avoid', 'Avoid', IDAngrActionHandler("Avoid")))
idaapi.register_action(idaapi.action_desc_t('Symbolic', 'Symbolic', IDAngrActionHandler("Symbolic")))

_idangr_hooks = IDAngrHooks()
_idangr_hooks.hook()

'''
try:
    _idangr_panel
except:
    _idangr_panel = IDAngrPanelForm()'''
_idangr_panel = IDAngrPanelForm()
_idangr_panel.Show()





