import idaapi

class IDAngrPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_KEEP
    comment = ""

    help = "IDAngr plugin: Use angr in the IDA Pro debugger generating a state from the current debug session"
    wanted_name = "IDAngr"
    wanted_hotkey = "Ctrl-Alt-I"
    

    def init(self):
        idaapi.msg("\n########### IDAngr plugin ###########\n")
        r = idaapi.attach_action_to_menu('View/Open subviews/', 'IDAngr Panel', idaapi.SETMENU_APP)
        if r is None:
            idaapi.msg("IDAngr plugin: add menu failed!\n")
        idaapi.msg("IDAngr plugin: shortcut key is Ctrl-Alt-I\n\n")
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        self.openPanel()

    def term(self):
        idaapi.msg("IDAngr plugin: terminated\n")

    def openPanel(self):
        import idangr
        import idangr.gui
        idangr.gui.show()


def PLUGIN_ENTRY():
    return IDAngrPlugin()
