from memory import SimSymbolicIdaMemory
import angr
import idaapi
import idc
import claripy

project = None

def StateShot():
    global project
    
    idc.RefreshDebuggerMemory()

    fpath = idaapi.get_input_file_path()

    if project == None:
        project = angr.Project(fpath, load_options={"auto_load_libs":False})

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


class MemoryPointer(object):
    def __init__(self, state, addr):
        self.state = state
        self.addr = addr
    
    def __call__(self, size=None):
        if size is None:
            size = project.arch.bits / 8
        if project.arch.memory_endness == "Iend_LE":
            return self.state.memory.load(self.addr, size).reversed
        return self.state.memory.load(self.addr, size)
    
    def m(self, size):
        return self.state.memory.load(self.addr, size)
    
    def eval(self, size=None, type=int):
        e = self(size)
        return self.state.solver.eval(e, cast_to=type)
    

class StateManager(object):
    def __init__(self, state=None):
        self.state = StateShot() if state is None else state
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
        elif type(key) == int or type(key) == long:
            if size == None:
                size = project.arch.bits
            else:
                size *= 8
            s = claripy.BVS("idangr_mem_" + hex(key), size)
            self.state.memory.store(key, s)
            self.symbolics[key] = (s, size)
        elif type(key) == claripy.ast.bv.BV:
            key = self.state.solver.eval(key, cast_to=int)
            self.sim(key, size)
        else:
            raise ValueError("key must be a register name or a memory address, not %s" % str(type(key)))
    
    def __getitem__(self, key):
        if key in project.arch.registers:
            return getattr(self.state.regs, key)
        elif type(key) == int or type(key) == long:
            return MemoryPointer(self.state, key)
        elif type(key) == claripy.ast.bv.BV:
            #key = self.state.solver.eval(key, cast_to=int)
            return MemoryPointer(self.state, key)
        else:
            raise ValueError("key must be a register name or a memory address")
    
    def __setitem__(self, key, value):
        size = None
        if type(value) == tuple:
            if len(value) < 2:
                raise ValueError("tuple must contains 2 items")
            size = value[1]
            value = value[0]
        elif type(value) == str:
            size = len(value)
        elif type(value) == claripy.ast.bv.BV:
            size = len(value) / 8
        #print value, size
        
        if key in project.arch.registers:
            if size == None:
                size = project.arch.registers[key][1]
            self.state.registers.store(key, value, size)
        elif type(key) == int or type(key) == long:
            self.state.memory.store(key, value, size)
        elif type(key) == claripy.ast.bv.BV:
            #key = self.state.solver.eval(key, cast_to=int)
            self.state.memory.store(key, value, size)
    
    def simulation_manager(self):
        return project.factory.simulation_manager(self.state)
    
    def to_dbg(self, found_state):
        if type(found_state) == StateManager:
            return self.to_dbg(found_state.state)
        for key in self.symbolics:
            try:
                if key in project.arch.registers:
                    r = found_state.solver.eval(self.symbolics[key][0], cast_to=int)
                    idc.SetRegValue(r, key)
                else:
                    r = found_state.solver.eval(self.symbolics[key][0], cast_to=str)
                    for i in xrange(len(r)):
                        idc.PatchByte(key + i, ord(r[i]))
            except Exception as ee:
                print " >> failed to write %s to debugger" % key
                #print ee


print
print "########### IDAngr ###########"
print "  usage: sm = StateManager()"
print "##############################"
print


