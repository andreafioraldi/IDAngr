import angr
#import cle

import idaapi

project = None

def load_project():
    global project
    if project == None:
        print " >> creating angr project..."
        project = angr.Project(idaapi.get_input_file_path(),
                                main_opts={ 'custom_base_addr': idaapi.get_imagebase() },
                                load_options={ "auto_load_libs": False })
        print " >> done."
    return project


self_modifying = False

def set_self_modifying(value):
    global self_modifying
    self_modifying = value

def is_self_modifying():
    global self_modifying
    return self_modifying
