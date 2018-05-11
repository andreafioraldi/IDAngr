import angr

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

SIMPROCS_FROM_CLE = 0
ONLY_GOT_FROM_CLE = 1
TEXT_GOT_FROM_CLE = 2
GET_ALL_DISCARD_CLE = 3

memory_type = SIMPROCS_FROM_CLE

def set_memory_type(value):
    global memory_type
    if value not in range(0,4):
        raise ValueError("invalid memory_type")
    memory_type = value

def get_memory_type():
    global memory_type
    return memory_type

