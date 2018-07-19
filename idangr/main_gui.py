from idaapi import PluginForm
from PyQt5 import QtCore, QtGui, QtWidgets
from PyQt5.QtCore import Qt

from ui import *

from angrdbg import *

import angr
import claripy

import idaapi
import idc
import idautils

import sip
import pickle
import os

import manage
import context_gui as ctx

from dialogs_gui import *

def save_ctx(filename):
    with open(filename, "wb") as fh:
        pickle.dump(ctx, fh)

def load_ctx(filename):
    with open(filename, "rb") as fh:
        ctx = pickle.load(fh)


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


def show_edit_hook(idx):
    pass

class IDAngrPanelForm(PluginForm):
    
    def on_find_menu(self, point):
        m = QtWidgets.QMenu(self.ui.findView)
        def delete():
            model = self.ui.findView.model()
            for i in self.ui.findView.selectedIndexes():
                model.removeRow(i.row())
        def jumpto():
            model = self.ui.findView.model()
            sel = self.ui.findView.selectedIndexes()
            if len(sel) > 0:
                idc.jumpto(ctx.find[sel[0].row()])
        m.addAction('Jump to', jumpto)
        m.addAction('Delete', delete)
        m.exec_(self.ui.findView.viewport().mapToGlobal(point))
    
    def on_avoid_menu(self, point):
        m = QtWidgets.QMenu(self.ui.avoidView)
        def delete():
            model = self.ui.avoidView.model()
            for i in self.ui.avoidView.selectedIndexes():
                model.removeRow(i.row())
        def jumpto():
            model = self.ui.avoidView.model()
            sel = self.ui.avoidView.selectedIndexes()
            if len(sel) > 0:
                idc.jumpto(ctx.avoid[sel[0].row()])
        m.addAction('Jump to', jumpto)
        m.addAction('Delete', delete)
        m.exec_(self.ui.avoidView.viewport().mapToGlobal(point))
    
    def on_hook_menu(self, point):
        m = QtWidgets.QMenu(self.ui.hooksView)
        def delete():
            model = self.ui.hooksView.model()
            for i in self.ui.hooksView.selectedIndexes():
                model.removeRow(i.row())
        def jumpto():
            global _idangr_hooks
            model = self.ui.hooksView.model()
            sel = self.ui.hooksView.selectedIndexes()
            if len(sel) > 0:
                idc.jumpto(_idangr_hooks[sel[0].row()][0])
        def edit():
            global _idangr_hooks
            model = self.ui.hooksView.model()
            sel = self.ui.hooksView.selectedIndexes()
            if len(sel) > 0:
                show_edit_hook(sel[0].row())
        m.addAction('Jump to', jumpto)
        m.addAction('Edit code', edit)
        m.addAction('Delete', delete)
        m.exec_(self.ui.hooksView.viewport().mapToGlobal(point))

    def add_find(self, addr):
        item = QtWidgets.QListWidgetItem("0x%x" % addr)
        self.ui.findView.addItem(item)
    
    def remove_find(self, addr):
        model = self.ui.findView.model()
        for item in self.ui.findView.findItems("0x%x" % addr, Qt.MatchExactly):
            i = self.ui.findView.indexFromItem(item)
            model.removeRow(i.row())
    
    def add_avoid(self, addr):
        item = QtWidgets.QListWidgetItem("0x%x" % addr)
        self.ui.avoidView.addItem(item)
    
    def remove_avoid(self, addr):
        model = self.ui.avoidView.model()
        for item in self.ui.avoidView.findItems("0x%x" % addr, Qt.MatchExactly):
            i = self.ui.avoidView.indexFromItem(item)
            model.removeRow(i.row())
    
    def add_hook(self, addr):
        item = QtWidgets.QListWidgetItem("0x%x" % addr)
        self.ui.hooksView.addItem(item)
    
    def remove_hook(self, addr):
        model = self.ui.hooksView.model()
        for item in self.ui.hooksView.findItems("0x%x" % addr, Qt.MatchExactly):
            i = self.ui.hooksView.indexFromItem(item)
            model.removeRow(i.row())
    
    
    def reset_clicked(self):
        ctx.reset()
        self.ui.regsView.model().layoutChanged.emit()
        self.ui.memoryView.model().layoutChanged.emit()
        self.ui.findView.clear()
        self.ui.avoidView.clear()
        self.ui.todbgBtn.setEnabled(False)
        self.ui.viewFileBtn.setEnabled(False)
        self.ui.nextBtn.setEnabled(False)
        
    
    def run_clicked(self):
        conds = IDAngrExecDialog.go()
        if conds == None:
            return
        
        try:
            ctx.stateman = StateManager()
        except Exception as ee:
            QtWidgets.QMessageBox(QtWidgets.QMessageBox.Critical, 'StateManager - Python Error', str(ee)).exec_()
            return
        
        for e in ctx.simregs:
            ctx.stateman.sim(e[0])
            if e[0] in ctx.constraints:
                try:
                    ctx.constraints[e[0]][1](ctx.stateman.symbolics[e[0]][0], ctx.stateman.state)
                except Exception as ee:
                    QtWidgets.QMessageBox(QtWidgets.QMessageBox.Critical, 'Constraints on %s - Python Error' % str(e[0]), str(ee)).exec_()
                    return
        for e in ctx.simmem:
            addr = int(e[0], 16)
            ctx.stateman.sim(addr, int(e[1]))
            if addr in ctx.constraints:
                try:
                    ctx.constraints[addr][1](ctx.stateman.symbolics[int(e[0], 16)][0], ctx.stateman.state)
                except Exception as ee:
                    QtWidgets.QMessageBox(QtWidgets.QMessageBox.Critical, 'Constraints on %s - Python Error' % str(e[0]), str(ee)).exec_()
                    return
        
        sm = ctx.stateman.simulation_manager()
        ctx.simman = sm
        
        sm.explore(find=conds[0], avoid=conds[1])
        if len(sm.found) == 0:
            QtWidgets.QMessageBox(QtWidgets.QMessageBox.Warning, 'Not Found', "Valid state not found after exploration.\n" + str(ctx.stateman) + "\n").exec_()
            return
        ctx.foundstate = sm.found[0]
        conc = ctx.stateman.concretize(ctx.foundstate)
        for i in xrange(len(ctx.simregs)):
            try:
                ctx.simregs[i][2] = "0x%x" % conc[ctx.simregs[i][0]]
            except: pass
        for i in xrange(len(ctx.simmem)):
            try:
                ctx.simmem[i][2] = repr(conc[int(ctx.simmem[i][0], 16)])
            except: pass
        #print ctx.simmem
        
        self.ui.filesBox.setRange(0, len(ctx.foundstate.posix.files) -1)
        
        self.ui.regsView.model().layoutChanged.emit()
        self.ui.memoryView.model().layoutChanged.emit()
        self.ui.todbgBtn.setEnabled(True)
        self.ui.viewFileBtn.setEnabled(True)
        self.ui.nextBtn.setEnabled(True)
        
        QtWidgets.QMessageBox(QtWidgets.QMessageBox.Information, 'Done', "Valid state found").exec_()
    
    
    def next_clicked(self):
        conds = IDAngrExecDialog.go()
        if conds == None:
            return
        
        if ctx.stateman == None:
            ctx.stateman = StateManager()
            for e in ctx.simregs:
                ctx.stateman.sim(e[0])
                if e[0] in ctx.constraints:
                    try:
                        ctx.constraints[e[0]][1](ctx.stateman.symbolics[e[0]], ctx.stateman.state)
                    except Exception as ee:
                        QtWidgets.QMessageBox(QtWidgets.QMessageBox.Critical, 'Constraints on %s - Python Error' % str(e[0]), str(ee)).exec_()
                        return
            for e in ctx.simmem:
                addr = int(e[0], 16)
                ctx.stateman.sim(addr, int(e[1]))
                if addr in ctx.constraints:
                    try:
                        ctx.constraints[addr][1](ctx.stateman.symbolics[int(e[0], 16)], ctx.stateman.state)
                    except Exception as ee:
                        QtWidgets.QMessageBox(QtWidgets.QMessageBox.Critical, 'Constraints on %s - Python Error' % str(e[0]), str(ee)).exec_()
                        return
        
        if ctx.simman == None:
            if ctx.foundstate == None:
                sm = ctx.stateman.simulation_manager()
            else:
                sm = load_project().factory.simulation_manager(ctx.foundstate)
            ctx.simman = sm
        else:
            sm = ctx.simman
        
        sm.explore(find=conds[0], avoid=conds[1])
        if len(sm.found) == 0:
            QtWidgets.QMessageBox(QtWidgets.QMessageBox.Warning, 'Not Found', "Valid state not found after exploration.\n" + str(ctx.stateman) + "\n").exec_()
            return
        ctx.foundstate = sm.found[-1]
        conc = ctx.stateman.concretize(ctx.foundstate)
        for i in xrange(len(ctx.simregs)):
            try:
                ctx.simregs[i][2] = "0x%x" % conc[ctx.simregs[i][0]]
            except: pass
        for i in xrange(len(ctx.simmem)):
            try:
                ctx.simmem[i][2] = repr(conc[int(ctx.simmem[i][0], 16)])
            except: pass
         
        #print ctx.simmem
        self.ui.filesBox.setRange(0, len(ctx.foundstate.posix.files) -1)
        
        self.ui.regsView.model().layoutChanged.emit()
        self.ui.memoryView.model().layoutChanged.emit()
        
        QtWidgets.QMessageBox(QtWidgets.QMessageBox.Information, 'Done', "Valid state found").exec_()

    
    def todbg_clicked(self):
        ctx.stateman.to_dbg(ctx.foundstate)
    
    
    def on_regs_menu(self, point):
        m = QtWidgets.QMenu(self.ui.regsView)
        def delete():
            model = self.ui.regsView.model()
            for i in self.ui.regsView.selectedIndexes():
                ctx.simregs.pop(i.row())
            self.ui.regsView.model().layoutChanged.emit()
        def jumpto():
            model = self.ui.regsView.model()
            sel = self.ui.regsView.selectedIndexes()
            if len(sel) > 0:
                try:
                    addr = int(ctx.simregs[sel[0].row()][2], 16)
                    idc.jumpto(addr)
                except:
                    pass
        def copyval():
            model = self.ui.regsView.model()
            sel = self.ui.regsView.selectedIndexes()
            if len(sel) > 0:
                cb = QtWidgets.QApplication.clipboard()
                cb.clear(mode=cb.Clipboard)
                cb.setText(ctx.simregs[sel[0].row()][2], mode=cb.Clipboard)
        def set_constr():
            model = self.ui.regsView.model()
            sel = self.ui.regsView.selectedIndexes()
            if len(sel) > 0:
                item = ctx.simregs[sel[0].row()][0]
                IDAngrConstraintsDialog.go(item)    
        m.addAction('Jump to', jumpto)
        m.addAction('Copy value', copyval)
        m.addAction('Set constraints', set_constr)
        m.addAction('Delete', delete)
        m.exec_(self.ui.regsView.viewport().mapToGlobal(point))

    def on_mem_menu(self, point):
        m = QtWidgets.QMenu(self.ui.memoryView)
        def delete():
            model = self.ui.memoryView.model()
            for i in self.ui.memoryView.selectedIndexes():
                ctx.simmem.pop(i.row())
            self.ui.memoryView.model().layoutChanged.emit()
        def jumpto():
            model = self.ui.memoryView.model()
            sel = self.ui.memoryView.selectedIndexes()
            if len(sel) > 0:
                idc.jumpto(int(ctx.simmem[sel[0].row()][0], 16))
        def copyval():
            model = self.ui.memoryView.model()
            sel = self.ui.memoryView.selectedIndexes()
            if len(sel) > 0:
                cb = QtWidgets.QApplication.clipboard()
                cb.clear(mode=cb.Clipboard)
                cb.setText(ctx.simmem[sel[0].row()][2], mode=cb.Clipboard)
        def set_constr():
            model = self.ui.memoryView.model()
            sel = self.ui.memoryView.selectedIndexes()
            if len(sel) > 0:
                item = int(ctx.simmem[sel[0].row()][0], 16)
                IDAngrConstraintsDialog.go(item)
        m.addAction('Jump to', jumpto)
        m.addAction('Copy value', copyval)
        m.addAction('Set constraints', set_constr)
        m.addAction('Delete', delete)
        m.exec_(self.ui.memoryView.viewport().mapToGlobal(point))

    
    def add_reg(self, idx):
        reg = ctx.regs[idx]
        for row in ctx.simregs: #don't add a reg twice
            if row[0] == reg:
                return
        ctx.simregs.append([reg, load_project().arch.registers[reg][1], "?"])
        self.ui.regsView.model().layoutChanged.emit()
    
    def add_mem(self, addr, size):
        if type(addr) == int or type(addr) == long:
            addr = "0x%x" % addr
        ctx.simmem.append([addr, size, "?"])
        self.ui.memoryView.model().layoutChanged.emit()
    
    def remove_mem(self, addr):
        pass
    
    
    
    def view_file_clicked(self):
        fd = self.ui.filesBox.value()
        IDAngrTextViewerForm.show_text(ctx.foundstate.posix.dumps(fd), "File %d Viewer" % fd)
    
    def load_clicked(self):
        filename = QtWidgets.QFileDialog.getOpenFileName(self.parent, 'Open File')[0]
        if filename != "":
            self.reset_clicked()
            load_ctx(filename)
            for addr in ctx.find:
                self.add_find(addr)
            for addr in ctx.avoid:
                self.add_avoid(addr)
                
            tablemodel = IDAngrTableModel(ctx.simregs, ['Name', 'Size', 'Value'], self.parent)
            self.ui.regsView.setModel(tablemodel)
            self.ui.regsView.resizeColumnsToContents()
            
            tablemodel = IDAngrTableModel(ctx.simmem, ['Address', 'Length', 'Value'], self.parent)
            self.ui.memoryView.setModel(tablemodel)
            self.ui.memoryView.resizeColumnsToContents()
        
    
    def save_clicked(self):
        filename = QtWidgets.QFileDialog.getSaveFileName(self.parent, 'Save File')[0]
        if filename != "":
            save_ctx(filename)
    
    
    def OnCreate(self, form):
        """
        Called when the plugin form is created
        """
        #ctx.reset()
        
        # Get parent widget
        self.parent = self.FormToPyQtWidget(form)
        
        self.ui = Ui_IDAngrPanel()
        self.ui.setupUi(self.parent)
        
        project = load_project()
        
        self.ui.findView.customContextMenuRequested.connect(self.on_find_menu)
        self.ui.avoidView.customContextMenuRequested.connect(self.on_avoid_menu)
        self.ui.hooksView.customContextMenuRequested.connect(self.on_hook_menu)
        
        self.ui.resetBtn.clicked.connect(self.reset_clicked)
        self.ui.runBtn.clicked.connect(self.run_clicked)
        self.ui.nextBtn.clicked.connect(self.next_clicked)
        self.ui.todbgBtn.clicked.connect(self.todbg_clicked)
        self.ui.viewFileBtn.clicked.connect(self.view_file_clicked)
        self.ui.loadBtn.clicked.connect(self.load_clicked)
        self.ui.saveBtn.clicked.connect(self.save_clicked)
        
        ctx.regs = sorted(project.arch.registers, key=lambda x: project.arch.registers.get(x)[0])
        
        for reg in ctx.regs:
            self.ui.registerChooser.addItem(reg)
        
        self.ui.registerChooser.setCurrentIndex(-1)
        self.ui.registerChooser.currentIndexChanged.connect(self.add_reg)
        
        tablemodel = IDAngrTableModel(ctx.simregs, ['Name', 'Size', 'Value'], self.parent)
        self.ui.regsView.setModel(tablemodel)
        self.ui.regsView.resizeColumnsToContents()
        
        tablemodel = IDAngrTableModel(ctx.simmem, ['Address', 'Length', 'Value'], self.parent)
        self.ui.memoryView.setModel(tablemodel)
        self.ui.memoryView.resizeColumnsToContents()
        
        self.ui.regsView.customContextMenuRequested.connect(self.on_regs_menu)
        self.ui.memoryView.customContextMenuRequested.connect(self.on_mem_menu)
        
        for addr, _ in ctx.hooks:
            self.add_hook(addr)
        for addr in ctx.find:
            self.add_find(addr)
        for addr in ctx.avoid:
            self.add_avoid(addr)
        

    def OnClose(self, form):
        """
        Called when the plugin form is closed
        """
        #global _idangr_panel
        #del _idangr_panel


    def Show(self):
        """Creates the form is not created or focuses it if it was"""
        return PluginForm.Show(self,
                               "IDAngr Panel",
                               options = (PluginForm.FORM_TAB | PluginForm.FORM_CLOSE_LATER))


class IDAngrActionHandler(idaapi.action_handler_t):

    def __init__(self, action):
        idaapi.action_handler_t.__init__(self)
        self.action = action
    
    def activate(self, ctx):
        global _idangr_panel
        if self.action == "Find":
            addr = idaapi.get_screen_ea()
            if addr in ctx.avoid:
                ctx.avoid.remove(addr)
                _idangr_panel.remove_avoid(addr)
            if addr in ctx.find:
                return
            ctx.find.append(addr)
            _idangr_panel.add_find(addr)
        elif self.action == "Avoid":
            addr = idaapi.get_screen_ea()
            if addr in ctx.find:
                ctx.find.remove(addr)
                _idangr_panel.remove_find(addr)
            if addr in ctx.avoid:
                return
            ctx.avoid.append(addr)
            _idangr_panel.add_avoid(addr)
        elif self.action == "Symbolic":
            addr = idaapi.get_screen_ea()
            #if addr in ctx.simmem:
            #    return
            m = IDAngrAddMemDialog.get_mem(addr)
            if m != None:
                _idangr_panel.add_mem(m[0], m[1]) #addr, size
                #ctx.simmem.append(m)
        elif self.action == "Hook":
            addr = idaapi.get_screen_ea()
            m = IDAngrHookDialog.get_hook(addr)
            if m != None:
                _idangr_panel.add_hook(m)
        
        
    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


class IDAngrUIHooks(idaapi.UI_Hooks):

    @staticmethod
    def finish_populating_tform_popup(form, popup):
        idaapi.attach_action_to_popup(form, popup, "Find", "IDAngr/")
        idaapi.attach_action_to_popup(form, popup, "Avoid", "IDAngr/")
        idaapi.attach_action_to_popup(form, popup, "Symbolic", "IDAngr/")
        idaapi.attach_action_to_popup(form, popup, "Hook", "IDAngr/")


idaapi.register_action(idaapi.action_desc_t('Find', 'Find', IDAngrActionHandler("Find")))
idaapi.register_action(idaapi.action_desc_t('Avoid', 'Avoid', IDAngrActionHandler("Avoid")))
idaapi.register_action(idaapi.action_desc_t('Symbolic', 'Symbolic', IDAngrActionHandler("Symbolic")))
idaapi.register_action(idaapi.action_desc_t('Hook', 'Hook', IDAngrActionHandler("Hook")))

_ui_hooks = IDAngrUIHooks()
_ui_hooks.hook()

_idangr_panel = None

def idangr_panel_show():
    global _idangr_panel
    if _idangr_panel == None:
        _idangr_panel = IDAngrPanelForm()
    _idangr_panel.Show()



