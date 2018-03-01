from idaapi import PluginForm
from PyQt5 import QtCore, QtGui, QtWidgets
from PyQt5.QtCore import Qt

from ui import *
from idangr import *

import sip

class IDAngrCtx(object):
    find = []
    avoid = []
    find_lambda = "def find_cond(state):\n\tsol = state.solver.eval\n\tfor addr in finds:\n\t\tif sol(state.regs.pc) == addr: return True\n\treturn False"
    avoid_lambda = "def avoid_cond(state):\n\tsol = state.solver.eval\n\tfor addr in avoids:\n\t\tif sol(state.regs.pc) == addr: return True\n\treturn False"
    regs = []
    simregs = []
    simmem = []
    stateman = None
    foundstate = None
    simman = None

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
            
class IDAngrExecDialog(QtWidgets.QDialog):
    
    def __init__(self):
        QtWidgets.QDialog.__init__(self)
        
        self.ui = Ui_IDAngrExecDialog()
        self.ui.setupUi(self)
        
        if IDAngrCtx.find_lambda:
            self.ui.findCondEdit.setPlainText(IDAngrCtx.find_lambda)
        if IDAngrCtx.avoid_lambda:
            self.ui.avoidCondEdit.setPlainText(IDAngrCtx.avoid_lambda)
    
    @staticmethod
    def go():
        dialog = IDAngrExecDialog()
        r = dialog.exec_()
        if r == QtWidgets.QDialog.Accepted:
            if dialog.ui.useFindCondBox.isChecked():
                code = dialog.ui.findCondEdit.toPlainText()
                IDAngrCtx.find_lambda = code
                finds = IDAngrCtx.find
                avoids = IDAngrCtx.avoid
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
                find = IDAngrCtx.find
            if dialog.ui.useAvoidCondBox.isChecked():
                code = dialog.ui.avoidCondEdit.toPlainText()
                IDAngrCtx.avoid_lambda = code
                finds = IDAngrCtx.find
                avoids = IDAngrCtx.avoid
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
                avoid = IDAngrCtx.avoid
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
            model = self.ui.findView.model()
            sel = self.ui.findView.selectedIndexes()
            if len(sel) > 0:
                idc.jumpto(IDAngrCtx.find[sel[0].row()])
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
            model = self.ui.avoidView.model()
            sel = self.ui.avoidView.selectedIndexes()
            if len(sel) > 0:
                idc.jumpto(IDAngrCtx.avoid[sel[0].row()])
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
        while len(IDAngrCtx.simregs) > 0:
            IDAngrCtx.simregs.pop()
        while len(IDAngrCtx.simmem) > 0:
            IDAngrCtx.simmem.pop()
        IDAngrCtx.find = []
        IDAngrCtx.avoid = []
        IDAngrCtx.stateman = None
        IDAngrCtx.simman = None
        IDAngrCtx.foundstate = None
        self.ui.regsView.model().layoutChanged.emit()
        self.ui.memoryView.model().layoutChanged.emit()
        self.ui.findView.clear()
        self.ui.avoidView.clear()
        self.ui.todbgBtn.setEnabled(False)
        self.ui.viewFileBtn.setEnabled(False)
        self.ui.nextBtn.setEnabled(False)
        
    
    def runClicked(self):
        global project
        
        conds = IDAngrExecDialog.go()
        if conds == None:
            return
        
        #TODO check if debugger is running
        IDAngrCtx.stateman = StateManager()
        for e in IDAngrCtx.simregs:
            IDAngrCtx.stateman.sim(e[0])
        for e in IDAngrCtx.simmem:
            IDAngrCtx.stateman.sim(int(e[0], 16), int(e[1]))
        
        sm = IDAngrCtx.stateman.simulation_manager()
        IDAngrCtx.simman = sm
        
        sm.explore(find=conds[0], avoid=conds[1])
        if len(sm.found) == 0:
            QtWidgets.QMessageBox(QtWidgets.QMessageBox.Warning, 'Not Found', "Valid state not found after exploration.\n" + str(IDAngrCtx.stateman) + "\n").exec_()
            return
        IDAngrCtx.foundstate = sm.found[0]
        conc = IDAngrCtx.stateman.concretize(IDAngrCtx.foundstate)
        for i in xrange(len(IDAngrCtx.simregs)):
            try:
                IDAngrCtx.simregs[i][2] = "0x%x" % conc[IDAngrCtx.simregs[i][0]]
            except: pass
        for i in xrange(len(IDAngrCtx.simmem)):
            try:
                IDAngrCtx.simmem[i][2] = repr(conc[int(IDAngrCtx.simmem[i][0], 16)])
            except: pass
        #print IDAngrCtx.simmem
        
        self.ui.filesBox.setRange(0, len(IDAngrCtx.foundstate.posix.files) -1)
        
        self.ui.regsView.model().layoutChanged.emit()
        self.ui.memoryView.model().layoutChanged.emit()
        self.ui.todbgBtn.setEnabled(True)
        self.ui.viewFileBtn.setEnabled(True)
        self.ui.nextBtn.setEnabled(True)
    
    
    def nextClicked(self):
        global project
        
        conds = IDAngrExecDialog.go()
        if conds == None:
            return
        
        #TODO check if debugger is running
        if IDAngrCtx.stateman == None:
            IDAngrCtx.stateman = StateManager()
            for e in IDAngrCtx.simregs:
                IDAngrCtx.stateman.sim(e[0])
            for e in IDAngrCtx.simmem:
                IDAngrCtx.stateman.sim(int(e[0], 16), int(e[1]))
        
        if IDAngrCtx.simman == None:
            if IDAngrCtx.foundstate == None:
                sm = IDAngrCtx.stateman.simulation_manager()
            else:
                sm = project.factory.simulation_manager(IDAngrCtx.foundstate)
            IDAngrCtx.simman = sm
        else:
            sm = IDAngrCtx.simman
        
        sm.explore(find=conds[0], avoid=conds[1])
        if len(sm.found) == 0:
            QtWidgets.QMessageBox(QtWidgets.QMessageBox.Warning, 'Not Found', "Valid state not found after exploration.\n" + str(IDAngrCtx.stateman) + "\n").exec_()
            return
        IDAngrCtx.foundstate = sm.found[0]
        conc = IDAngrCtx.stateman.concretize(IDAngrCtx.foundstate)
        for i in xrange(len(IDAngrCtx.simregs)):
            try:
                IDAngrCtx.simregs[i][2] = "0x%x" % conc[IDAngrCtx.simregs[i][0]]
            except: pass
        for i in xrange(len(IDAngrCtx.simmem)):
            try:
                IDAngrCtx.simmem[i][2] = repr(conc[int(IDAngrCtx.simmem[i][0], 16)])
            except: pass
        #print IDAngrCtx.simmem
        self.ui.filesBox.setRange(0, len(IDAngrCtx.foundstate.posix.files) -1)
        
        self.ui.regsView.model().layoutChanged.emit()
        self.ui.memoryView.model().layoutChanged.emit()
        
    
    def todbgClicked(self):
        IDAngrCtx.stateman.to_dbg(IDAngrCtx.foundstate)
    
    
    def onRegsCtxMenu(self, point):
        m = QtWidgets.QMenu(self.ui.regsView)
        def delete():
            model = self.ui.regsView.model()
            for i in self.ui.regsView.selectedIndexes():
                IDAngrCtx.simregs.pop(i.row())
            self.ui.regsView.model().layoutChanged.emit()
        def jumpto():
            model = self.ui.regsView.model()
            sel = self.ui.regsView.selectedIndexes()
            if len(sel) > 0:
                try:
                    addr = int(IDAngrCtx.simregs[sel[0].row()][2], 16)
                    idc.jumpto(addr)
                except:
                    pass
        def copyval():
            model = self.ui.regsView.model()
            sel = self.ui.regsView.selectedIndexes()
            if len(sel) > 0:
                cb = QtWidgets.QApplication.clipboard()
                cb.clear(mode=cb.Clipboard)
                cb.setText(IDAngrCtx.simregs[sel[0].row()][2], mode=cb.Clipboard)      
        m.addAction('Jump to', jumpto)
        m.addAction('Copy value', copyval)
        m.addAction('Delete', delete)
        m.exec_(self.ui.regsView.viewport().mapToGlobal(point))

    def onMemCtxMenu(self, point):
        m = QtWidgets.QMenu(self.ui.memoryView)
        def delete():
            model = self.ui.memoryView.model()
            for i in self.ui.memoryView.selectedIndexes():
                IDAngrCtx.simmem.pop(i.row())
            self.ui.memoryView.model().layoutChanged.emit()
        def jumpto():
            model = self.ui.memoryView.model()
            sel = self.ui.memoryView.selectedIndexes()
            if len(sel) > 0:
                idc.jumpto(int(IDAngrCtx.simmem[sel[0].row()][0], 16))
        def copyval():
            model = self.ui.memoryView.model()
            sel = self.ui.memoryView.selectedIndexes()
            if len(sel) > 0:
                cb = QtWidgets.QApplication.clipboard()
                cb.clear(mode=cb.Clipboard)
                cb.setText(IDAngrCtx.simmem[sel[0].row()][2], mode=cb.Clipboard)           
        m.addAction('Jump to', jumpto)
        m.addAction('Copy value', copyval)
        m.addAction('Delete', delete)
        m.exec_(self.ui.memoryView.viewport().mapToGlobal(point))

    
    def addReg(self, idx):
        reg = IDAngrCtx.regs[idx]
        for row in IDAngrCtx.simregs: #don't add a reg twice
            if row[0] == reg:
                return
        IDAngrCtx.simregs.append([reg, project.arch.registers[reg][1], "?"])
        self.ui.regsView.model().layoutChanged.emit()
    
    def addMem(self, addr, size):
        if type(addr) == int or type(addr) == long:
            addr = "0x%x" % addr
        IDAngrCtx.simmem.append([addr, size, "?"])
        self.ui.memoryView.model().layoutChanged.emit()
    
    def removeMem(self, addr):
        pass
    
    
    
    def viewFileClicked(self):
        fd = self.ui.filesBox.value()
        IDAngrTextViewerForm.showText(IDAngrCtx.foundstate.posix.dumps(fd), "File %d Viewer" % fd)
    
    
    def OnCreate(self, form):
        """
        Called when the plugin form is created
        """
        global project
        
        # Get parent widget
        self.parent = self.FormToPyQtWidget(form)
        
        self.ui = Ui_IDAngrPanel()
        self.ui.setupUi(self.parent)

        self.ui.findView.customContextMenuRequested.connect(self.onFindCtxMenu)
        self.ui.avoidView.customContextMenuRequested.connect(self.onAvoidCtxMenu)

        self.ui.resetBtn.clicked.connect(self.resetClicked)
        self.ui.runBtn.clicked.connect(self.runClicked)
        self.ui.nextBtn.clicked.connect(self.nextClicked)
        self.ui.todbgBtn.clicked.connect(self.todbgClicked)
        self.ui.viewFileBtn.clicked.connect(self.viewFileClicked)
        
        IDAngrCtx.regs = sorted(project.arch.registers, key=lambda x: project.arch.registers.get(x)[0])
        
        for reg in IDAngrCtx.regs:
            self.ui.registerChooser.addItem(reg)
        
        self.ui.registerChooser.setCurrentIndex(-1)
        self.ui.registerChooser.currentIndexChanged.connect(self.addReg)
        
        tablemodel = IDAngrTableModel(IDAngrCtx.simregs, ['Name', 'Size', 'Value'], self.parent)
        self.ui.regsView.setModel(tablemodel)
        self.ui.regsView.resizeColumnsToContents()
        
        tablemodel = IDAngrTableModel(IDAngrCtx.simmem, ['Address', 'Length', 'Value'], self.parent)
        self.ui.memoryView.setModel(tablemodel)
        self.ui.memoryView.resizeColumnsToContents()
        
        self.ui.regsView.customContextMenuRequested.connect(self.onRegsCtxMenu)
        self.ui.memoryView.customContextMenuRequested.connect(self.onMemCtxMenu)
        
        

    def OnClose(self, form):
        """
        Called when the plugin form is closed
        """
        del IDAngrCtx.panel


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
        if self.action == "Find":
            addr = idaapi.get_screen_ea()
            if addr in IDAngrCtx.avoid:
                IDAngrCtx.avoid.remove(addr)
                IDAngrCtx.panel.removeAvoid(addr)
            if addr in IDAngrCtx.find:
                return
            IDAngrCtx.find.append(addr)
            IDAngrCtx.panel.addFind(addr)
        elif self.action == "Avoid":
            addr = idaapi.get_screen_ea()
            if addr in IDAngrCtx.find:
                IDAngrCtx.find.remove(addr)
                IDAngrCtx.panel.removeFind(addr)
            if addr in IDAngrCtx.avoid:
                return
            IDAngrCtx.avoid.append(addr)
            IDAngrCtx.panel.addAvoid(addr)
        elif self.action == "Symbolic":
            addr = idaapi.get_screen_ea()
            #if addr in IDAngrCtx.simmem:
            #    return
            m = IDAngrAddMemDialog.getMem(addr)
            if m != None:
                IDAngrCtx.panel.addMem(m[0], m[1])
                #IDAngrCtx.simmem.append(m)
        
        
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

IDAngrCtx.hooks = IDAngrHooks()
IDAngrCtx.hooks.hook()

'''
try:
    IDAngrCtx.panel
except:
    IDAngrCtx.panel = IDAngrPanelForm()'''
IDAngrCtx.panel = IDAngrPanelForm()
IDAngrCtx.panel.Show()


