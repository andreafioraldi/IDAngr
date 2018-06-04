import idangr
import idangr.gui_init

if idangr.gui_init.IDAngrConnectDialog.go():
    import idangr.gui
    idangr.gui.idangr_panel_show()
