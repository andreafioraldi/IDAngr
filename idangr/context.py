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


TEXT_SIMPROCS_FROM_LOADER = 0
ONLY_SIMPROCS_FROM_LOADER = 1
EXECUTE_ALL_DISCARD_LOADER = 2

memory_type = TEXT_SIMPROCS_FROM_LOADER

def set_memory_type(value):
    global memory_type
    if value not in range(0,3):
        raise ValueError()
    memory_type = value

def get_memory_type():
    global memory_type
    return memory_type

