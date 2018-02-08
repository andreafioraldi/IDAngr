from idangr import *
from idaapi import PluginForm, Form
from PyQt5 import QtCore, QtGui, QtWidgets

from ui import *

__idangr_find = None
__idangr_avoid = []
__idangr_symset = SimbolicsSet()


class IDAngrPanelForm_t(PluginForm):
   
    def OnCreate(self, form):
        """
        Called when the plugin form is created
        """

        # Get parent widget
        self.parent = self.FormToPyQtWidget(form)
        
        self.ui = Ui_IDAngrPanel()
        self.ui.setupUi(self.parent)
        
        
    def OnClose(self, form):
        """
        Called when the plugin form is closed
        """
        global __idangr_panel
        del __idangr_panel


    def Show(self):
        """Creates the form is not created or focuses it if it was"""
        return PluginForm.Show(self,
                               "IDAngr Panel",
                               options = PluginForm.FORM_PERSIST)
    

try:
    __idangr_panel
except:
    __idangr_panel = IDAngrPanelForm_t()

__idangr_panel.Show()



class TestEmbeddedChooserClass(Choose2):

    def __init__(self, title, nb=5, flags=0):
        Choose2.__init__(
            self,
            title,
            [["Address", 10], ["Name", 30]],
            embedded=True,
            width=30,
            height=20,
            flags=flags
        )
        self.n = 0
        self.items = [self.make_item()]*(nb+1)
        self.icon = 5
        self.selcount = 0

    def make_item(self):
        r = [str(self.n), "func_%04d" % self.n]
        self.n += 1
        return r

    def OnClose(self):
        pass

    def OnGetLine(self, n):
        print("getline %d" % n)
        return self.items[n]

    def OnGetSize(self):
        n = len(self.items)
        print("getsize -> %d" % n)
        return n

class ExpForm(Form):
    def __init__(self):
        self.invert = False
        self.EChooser = TestEmbeddedChooserClass("E1", flags=Choose2.CH_MULTI)
        Form.__init__(self, r"""STARTITEM {id:rDiscardLazySolves}
Options
<Discard LAZY_SOLVES:{rDiscardLazySolves}>
<Immutable:{rImmutable}>
<Auto Load Libs:{rAutoLoadLibs}>{cGroup1}>

Symbolic stdin
<##Enter length of stdin:{iStdinLen}>
<Ending newline:{rNewline}>
<Allow Null:{rNull}>
<White Space:{rWhite}>
<Force ASCII:{rASCII}>{cGroup2}>
""", {
    'cGroup1': Form.ChkGroupControl(("rDiscardLazySolves", "rImmutable", "rAutoLoadLibs")),
    'iStdinLen':Form.NumericInput(),
    'cGroup2': Form.ChkGroupControl(("rNewline", "rNull", "rWhite", "rASCII"))
    })

class ActionHandler(idaapi.action_handler_t):

    def __init__(self, action):
        idaapi.action_handler_t.__init__(self)
        self.action = action

    def activate(self, ctx):
        if self.action == "Finds:Set":
            find_set()
        elif self.action == "Finds:Remove":
            find_remove()
        elif self.action == "Finds:Print":
            find_view()
        elif self.action == "Avoids:Set":
            avoid_set()
        elif self.action == "Avoids:Remove":
            avoid_remove()
        elif self.action == "Avoids:Print":
            avoid_view()
        elif self.action == "Explore:Run":
            explore_run()
        elif self.action == "Explore:Options":
            explore_options()
        elif self.action == "Refresh:Refresh":
            refresh()
        elif self.action == "Quit:Quit":
            my_quit()

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS

class Hooks(idaapi.UI_Hooks):

    @staticmethod
    def finish_populating_tform_popup(form, popup):
        """
        Arguments:
        Return Value:
        Description:
            -
        TODO:
            - Doc String
        """
        idaapi.attach_action_to_popup(form, popup, "Finds:Set", "AngryIDA/Finds/")
        idaapi.attach_action_to_popup(form, popup, "Finds:Remove", "AngryIDA/Finds/")
        idaapi.attach_action_to_popup(form, popup, "Finds:Print", "AngryIDA/Finds/")
        idaapi.attach_action_to_popup(form, popup, "Avoids:Set", "AngryIDA/Avoids/")
        idaapi.attach_action_to_popup(form, popup, "Avoids:Remove", "AngryIDA/Avoids/")
        idaapi.attach_action_to_popup(form, popup, "Avoids:Print", "AngryIDA/Avoids/")
        idaapi.attach_action_to_popup(form, popup, "Explore:Run", "AngryIDA/Explore/")
        idaapi.attach_action_to_popup(form, popup, "Explore:Options", "AngryIDA/Explore/")
        idaapi.attach_action_to_popup(form, popup, "Refresh:Refresh", "AngryIDA/")
        idaapi.attach_action_to_popup(form, popup, "Quit:Quit", "AngryIDA/")

def set_line_color(color, addr=here(), item=CIC_ITEM): #pylint: disable=undefined-variable
    SetColor(addr, item, color) #pylint: disable=undefined-variable

def find_set():
    addr = idaapi.get_screen_ea()
    if addr in AVOID_ADDRS:
        AVOID_ADDRS.remove(addr)
        print("AngryIDA: Removed avoid address [%s]" % hex(addr))
    FIND_ADDRS.append(addr)
    set_line_color(0x208020, addr)
    print("AngryIDA: Added find address [%s]" % hex(addr))

def find_remove():
    addr = idaapi.get_screen_ea()
    if addr in FIND_ADDRS:
        FIND_ADDRS.remove(addr)
        set_line_color(0xffffff, addr)
        print("AngryIDA: Removed find address [%s]" % hex(addr))

def find_view():
    print("AngryIDA:\n\tFind Addresses")
    for addr in FIND_ADDRS:
        print("\t\t%s" % hex(addr))

def avoid_set():
    addr = idaapi.get_screen_ea()
    if addr in FIND_ADDRS:
        FIND_ADDRS.remove(addr)
        print("AngryIDA: Removed find address [%s]" % hex(addr))
    AVOID_ADDRS.append(addr)
    set_line_color(0x2020c0, addr)
    print("AngryIDA: Added avoid address [%s]" % hex(addr))

def avoid_remove():
    addr = idaapi.get_screen_ea()
    if addr in AVOID_ADDRS:
        AVOID_ADDRS.remove(addr)
        set_line_color(0xffffff, addr)
        print("AngryIDA: Removed avoid address [%s]" % hex(addr))

def avoid_view():
    print("\tAvoid Addresses")
    for addr in AVOID_ADDRS:
        print("\t\t%s" % hex(addr))

def explore_run():
    sm = StateManager()

    print(EXP_OPTS)

    for _ in range(0, EXP_OPTS["stdin"]["length"]-1):
        k = sm.state.posix.files[0].read_from(1)
        if not EXP_OPTS["stdin"]["null"]:
            sm.state.se.add(k != 0)
        if not EXP_OPTS["stdin"]["white_space"]:
            sm.state.se.add(k != 10)

    k = sm.state.posix.files[0].read_from(1)
    if EXP_OPTS["stdin"]["newline"]:
        sm.state.se.add(k == 10)

    sm.state.posix.files[0].seek(0)
    sm.state.posix.files[0].length = EXP_OPTS["stdin"]["length"]

    m = sm.simulation_manager()
    
    m.explore(find=FIND_ADDRS, avoid=AVOID_ADDRS)

    found = m.found[0]
    found.posix.files[0].seek(0)
    print("Found: "+ found.se.any_str(found.posix.files[0].read_from(EXP_OPTS["stdin"]["length"])))

def explore_options():
    EXP_FORM.Execute()
    EXP_OPTS["state"]["discard_lazy_solves"] = EXP_FORM.rDiscardLazySolves.checked
    EXP_OPTS["load"]["auto_load_libs"] = EXP_FORM.rAutoLoadLibs.checked
    EXP_OPTS["path_group"]["immutable"] = EXP_FORM.rImmutable.checked
    EXP_OPTS["stdin"]["newline"] = EXP_FORM.rNewline.checked
    EXP_OPTS["stdin"]["null"] = EXP_FORM.rNull.checked
    EXP_OPTS["stdin"]["ascii"] = EXP_FORM.rASCII.checked
    EXP_OPTS["stdin"]["white_space"] = EXP_FORM.rWhite.checked
    EXP_OPTS["stdin"]["length"] = EXP_FORM.iStdinLen.value

def refresh():
    print(FIND_ADDRS, AVOID_ADDRS)
    for addr in FIND_ADDRS:
        set_line_color(0xffffff, addr)
    del FIND_ADDRS[:]
    for addr in AVOID_ADDRS:
        set_line_color(0xffffff, addr)
    del AVOID_ADDRS[:]
    print("AngryIDA: Refresh completed.")

def my_quit():
    return None

#------------------------------MAIN------------------------------------

EXP_FORM = ExpForm()

# Compile (in order to populate the controls)
EXP_FORM.Compile()

# Set some defaults
EXP_FORM.rDiscardLazySolves.checked = True
EXP_FORM.rNewline.checked = True

# Create actions from context menu
ACTION_FS = idaapi.action_desc_t('Finds:Set', 'Set', ActionHandler("Finds:Set"))
ACTION_FR = idaapi.action_desc_t('Finds:Remove', 'Remove', ActionHandler("Finds:Remove"))
ACTION_FP = idaapi.action_desc_t('Finds:Print', 'Print', ActionHandler("Finds:Print"))
ACTION_AS = idaapi.action_desc_t('Avoids:Set', 'Set', ActionHandler("Avoids:Set"))
ACTION_AR = idaapi.action_desc_t('Avoids:Remove', 'Remove', ActionHandler("Avoids:Remove"))
ACTION_AP = idaapi.action_desc_t('Avoids:Print', 'Print', ActionHandler("Avoids:Print"))
ACTION_ER = idaapi.action_desc_t('Explore:Run', 'Run', ActionHandler("Explore:Run"))
ACTION_EO = idaapi.action_desc_t('Explore:Options', 'Options', ActionHandler("Explore:Options"))
ACTION_RR = idaapi.action_desc_t('Refresh:Refresh', 'Refresh', ActionHandler("Refresh:Refresh"))
ACTION_QQ = idaapi.action_desc_t('Quit:Quit', 'Quit', ActionHandler("Quit:Quit"))

# Register Actions
idaapi.register_action(ACTION_FS)
idaapi.register_action(ACTION_FR)
idaapi.register_action(ACTION_FP)
idaapi.register_action(ACTION_AS)
idaapi.register_action(ACTION_AR)
idaapi.register_action(ACTION_AP)
idaapi.register_action(ACTION_ER)
idaapi.register_action(ACTION_EO)
idaapi.register_action(ACTION_RR)
idaapi.register_action(ACTION_QQ)

HOOKS = Hooks()
HOOKS.hook()

