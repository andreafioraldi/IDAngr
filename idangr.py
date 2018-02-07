from memory import SimSymbolicIdaMemory
import angr
import idaapi
import idc
import claripy

project = None

__IDANGR_BITS = None

def StateShot():
    global project
    
    idc.RefreshDebuggerMemory()

    fpath = idaapi.get_input_file_path()

    if project == None:
        project = angr.Project(fpath, load_options={"auto_load_libs":False})
        __IDANGR_BITS = project.arch.bits

    mem = SimSymbolicIdaMemory(memory_backer=project.loader.memory, permissions_backer=None, memory_id="mem")

    state = project.factory.blank_state(plugins={"memory": mem})

    for reg in sorted(project.arch.registers, key=lambda x: project.arch.registers.get(x)[1]):
        if reg in ("sp", "bp", "ip"):
            continue
        try:
            setattr(state.regs, reg, idc.GetRegValue(reg))
            #print reg, hex(idc.GetRegValue(reg))
        except:
            #print "fail to set register", reg
            pass
    
    return state



class StateManager(object):
    def __init__(self):
        self.state = StateShot()
        self.symbolics = {}
    
    def sim(self, key, size=None):
        '''
        key: memory address(int) or register name(str)
        size: size of object in bytes
        '''
        if key in project.arch.registers:
            if size == None:
                size = project.arch.registers[key][1]
            size *= 8
            s = claripy.BVS("idangr_reg_" + str(key), size)
            setattr(self.state.regs, key, s)
            self.symbolics[key] = (s, size)
        elif type(key) == int:
            if size == None:
                size = __IDANGR_BITS
            else:
                size *= 8
            s = claripy.BVS("idangr_mem_" + hex(key), size)
            self.state.memory.store(key, s)
            self.symbolics[key] = (s, size)
        else:
            raise ValueError("key must be a register name or a memory address")
    
    def __getitem__(self, key):
        if key not in self.symbolics:
            return None
        return self.symbolics[key][0]
    
    def simulation_manager(self):
        return project.factory.simulation_manager(self.state)
    
    def to_dbg(self, found_state):
        for key in self.symbolics:
            try:
                if key in project.arch.registers:
                    r = found_state.solver.eval(self.symbolics[key][0], cast_to=int)
                    idc.SetRegValue(r, key)
                else:
                    r = found_state.solver.eval(self.symbolics[key][0], cast_to=str)
                    for i in xrange(len(r)):
                        idc.PatchByte(key + i, r[i])
            except Exception as ee:
                print " >> failed to write %s to debugger" % key
                #print ee


print
print "########### IDAngr ###########"
print "  usage: sm = StateManager()"
print "##############################"
print


