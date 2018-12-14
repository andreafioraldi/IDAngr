import idc
import idautils

def search_simproc(name):
    import angr
    for libname in angr.SIM_PROCEDURES:
        if name in angr.SIM_PROCEDURES[libname]:
            return angr.SIM_PROCEDURES[libname][name]
        elif name.startswith("_") and name[1:] in angr.SIM_PROCEDURES[libname]:
            return angr.SIM_PROCEDURES[libname][name[1:]]


def hook_lib_funcs():
    from angrdbg import load_project
    project = load_project()
    for func in idautils.Functions():
        flags = idc.GetFunctionFlags(func)
        if flags & idc.FUNC_LIB:
            name = idc.GetFunctionName(func)
            simproc = search_simproc(name)
            if simproc is not None:
                print name, simproc
                project.hook_symbol(func, simproc())