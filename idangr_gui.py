from idaapi import PluginForm
from PyQt5 import QtCore, QtGui, QtWidgets
from PyQt5.QtCore import Qt

from ui import *
from idangr import *

import sip

_idangr_find = []
_idangr_avoid = []
#_idangr_symset = SimbolicsSet()

_idangr_avalregs = []
_idangr_simregs = []
_idangr_simmem = []

_idangr_stateman = None
_idangr_foundstate = None


class IDAngrAddMemDialog(QtWidgets.QDialog):
    
    def __init__(self):
        QtWidgets.QDialog.__init__(self)
        
        self.ui = Ui_IDAngrAddMem()
        self.ui.setupUi(self)
        
        self.ui.lenTextEdit.setPlainText(str(project.arch.bits / 8))
        
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
        m.addAction('Delete', delete)
        m.exec_(self.ui.findView.viewport().mapToGlobal(point))
    
    def onAvoidCtxMenu(self, point):
        m = QtWidgets.QMenu(self.ui.avoidView)
        def delete():
            model = self.ui.avoidView.model()
            for i in self.ui.avoidView.selectedIndexes():
                model.removeRow(i.row())
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
        global _idangr_simregs, _idangr_simmem, _idangr_find, _idangr_avoid
        while len(_idangr_simregs) > 0:
            _idangr_simregs.pop()
        while len(_idangr_simmem) > 0:
            _idangr_simmem.pop()
        _idangr_find = []
        _idangr_avoid = []
        self.ui.regsView.model().layoutChanged.emit()
        self.ui.memoryView.model().layoutChanged.emit()
        self.ui.findView.clear()
        self.ui.avoidView.clear()
        self.ui.todbgBtn.setEnabled(False)
        #self.ui.runBtn.setEnabled(True)
        
    
    def runClicked(self):
        global _idangr_stateman, _idangr_find, _idangr_avoid, _idangr_simregs, _idangr_simmem, _idangr_foundstate
        #TODO check if debugger is running
        _idangr_stateman = StateManager()
        for e in _idangr_simregs:
            _idangr_stateman.sim(e[0])
        for e in _idangr_simmem:
            _idangr_stateman.sim(int(e[0], 16), int(e[1]))
        sm = _idangr_stateman.simulation_manager()
        sm.explore(find=_idangr_find, avoid=_idangr_avoid)
        if len(sm.found) == 0:
            QtWidgets.QMessageBox(QtWidgets.QMessageBox.Warning, 'Not Found', "Valid state not found after exploration.\n" + str(_idangr_stateman) + "\n").exec_()
            return
        _idangr_foundstate = sm.found[0]
        conc = _idangr_stateman.concretize(_idangr_foundstate)
        for i in xrange(len(_idangr_simregs)):
            try:
                _idangr_simregs[i][2] = conc[_idangr_simregs[i][0]]
            except: pass
        for i in xrange(len(_idangr_simmem)):
            try:
                _idangr_simmem[i][2] = conc[int(_idangr_simmem[i][0], 16)]
            except: pass
        print _idangr_simmem
        self.ui.regsView.model().layoutChanged.emit()
        self.ui.memoryView.model().layoutChanged.emit()
        self.ui.todbgBtn.setEnabled(True)
        
        
    def todbgClicked(self):
        global _idangr_stateman, _idangr_foundstate
        _idangr_stateman.to_dbg(_idangr_foundstate)
    
    
    def onRegsCtxMenu(self, point):
        m = QtWidgets.QMenu(self.ui.regsView)
        def delete():
            model = self.ui.regsView.model()
            for i in self.ui.regsView.selectedIndexes():
                _idangr_simregs.pop(i.row())
            self.ui.regsView.model().layoutChanged.emit()
        m.addAction('Delete', delete)
        m.exec_(self.ui.regsView.viewport().mapToGlobal(point))

    def onMemCtxMenu(self, point):
        m = QtWidgets.QMenu(self.ui.memoryView)
        def delete():
            model = self.ui.memoryView.model()
            for i in self.ui.memoryView.selectedIndexes():
                _idangr_simmem.pop(i.row())
            self.ui.memoryView.model().layoutChanged.emit()
        m.addAction('Delete', delete)
        m.exec_(self.ui.memoryView.viewport().mapToGlobal(point))

    
    def addReg(self, idx):
        global _idangr_simregs, project
        reg = _idangr_avalregs[idx]
        for row in _idangr_simregs: #don't add a reg twice
            if row[0] == reg:
                return
        _idangr_simregs.append([reg, project.arch.registers[reg][1], "?"])
        self.ui.regsView.model().layoutChanged.emit()
    
    def addMem(self, addr, size):
        global _idangr_simmem, project
        if type(addr) == int or type(addr) == long:
            addr = "0x%x" % addr
        _idangr_simmem.append([addr, size, "?"])
        self.ui.memoryView.model().layoutChanged.emit()
    
    def removeMem(self, addr):
        pass
    
    
    
    def OnCreate(self, form):
        """
        Called when the plugin form is created
        """
        global _idangr_simregs, _idangr_avalregs, project
        
        # Get parent widget
        self.parent = self.FormToPyQtWidget(form)
        
        self.ui = Ui_IDAngrPanel()
        self.ui.setupUi(self.parent)

        self.ui.findView.customContextMenuRequested.connect(self.onFindCtxMenu)
        self.ui.avoidView.customContextMenuRequested.connect(self.onAvoidCtxMenu)

        self.ui.resetBtn.clicked.connect(self.resetClicked)
        self.ui.runBtn.clicked.connect(self.runClicked)
        self.ui.todbgBtn.clicked.connect(self.todbgClicked)
        
        _idangr_avalregs = sorted(project.arch.registers, key=lambda x: project.arch.registers.get(x)[0])
        
        for reg in _idangr_avalregs:
            self.ui.registerChooser.addItem(reg)
        
        self.ui.registerChooser.currentIndexChanged.connect(self.addReg)
        
        tablemodel = IDAngrTableModel(_idangr_simregs, ['Name', 'Size', 'Value'], self.parent)
        self.ui.regsView.setModel(tablemodel)
        self.ui.regsView.resizeColumnsToContents()
        
        tablemodel = IDAngrTableModel(_idangr_simmem, ['Address', 'Length', 'Value'], self.parent)
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
        global _idangr_panel, _idangr_find, _idangr_avoid
        
        if self.action == "Find":
            addr = idaapi.get_screen_ea()
            if addr in _idangr_avoid:
                _idangr_avoid.remove(addr)
                _idangr_panel.removeAvoid(addr)
            if addr in _idangr_find:
                return
            _idangr_find.append(addr)
            _idangr_panel.addFind(addr)
        elif self.action == "Avoid":
            addr = idaapi.get_screen_ea()
            if addr in _idangr_find:
                _idangr_find.remove(addr)
                _idangr_panel.removeFind(addr)
            if addr in _idangr_avoid:
                return
            _idangr_avoid.append(addr)
            _idangr_panel.addAvoid(addr)
        elif self.action == "Symbolic":
            addr = idaapi.get_screen_ea()
            #if addr in _idangr_simmem:
            #    return
            m = IDAngrAddMemDialog.getMem(addr)
            if m != None:
                _idangr_panel.addMem(m[0], m[1])
                #_idangr_simmem.append(m)
        
        
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


