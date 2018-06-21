import manage

def show():
    if not manage.is_initialized():
        from init_gui import IDAngrConnectDialog
        if IDAngrConnectDialog.go():
            from main_gui import *
            idangr_panel_show()
    else:
        from main_gui import *
        idangr_panel_show()
