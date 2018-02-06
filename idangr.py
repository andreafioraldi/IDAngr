from memory import SimSymbolicIdaMemory
import angr
import idaapi
import idc


idc.RefreshDebuggerMemory()

fpath = idaapi.get_input_file_path()

project = angr.Project(fpath, load_options={"auto_load_libs":False})

mem = SimSymbolicIdaMemory(memory_backer=project.loader.memory, permissions_backer=None, memory_id="mem")

state = project.factory.blank_state(plugins={"memory": mem})

b = project.arch.bits / 8

for reg in sorted(project.arch.registers, key=lambda x: project.arch.registers.get(x)[1]):
    if reg in ("sp", "bp", "ip"):
        continue
    try:
        setattr(state.regs, reg, idc.GetRegValue(reg))
        #print reg, hex(idc.GetRegValue(reg))
    except:
        #print "fail to set register", reg
        pass


