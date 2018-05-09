import idc
import idautils

from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection

class SegIO(object):
    def __init__(self, start, end):
        self.start = start
        self.end = end
        self.size = end - start
        self.pos = 0
    
    def seek(self, pos):
        if pos > self.end:
            self.pos = self.end
        self.pos = pos
    
    def read(self, size=None):
        if size == None or size > self.size - self.pos:
            size = self.size - self.pos
        r = idc.GetManyBytes(self.start + self.pos, size)
        self.pos += len(r)
        return r


def build_mixed_got(proj, state):
    
    got_start = -1
    for ea in idautils.Segments():
        if idc.SegName(ea) == proj.arch.got_section_name:
            got_start = idc.SegStart(ea)
            got_end = idc.SegEnd(ea)
    
    if got_start == -1:
        print "IDAngr: cannot find .got section"
        return state
    
    entry_len = proj.arch.bits / 8
    get_mem = idc.Dword if entry_len == 4 else idc.Qword
    
    print "## angr got - before ##"
    for a in xrange(got_start, got_end, entry_len):
        print "0x%x:  0x%x" % (a, state.solver.eval(getattr(state.mem[a], "uint%d_t" % proj.arch.bits).resolved))
    print
    
    #libs prefix names
    names = map(lambda x: x.split(".")[0], proj.loader.requested_names)
    if len(names) == 0:
        return state # static binary
    
    ranges = {} # {"libname": [start, end]}
    libs = {} # {start: "libname"}
    
    for ea in idautils.Segments():
        for name in names:
            if idc.SegName(ea).startswith(name):
                s = idc.SegStart(ea)
                e = idc.SegEnd(ea)
                ranges[name] = ranges.get(name, [-1, -1])
                if ranges[name][0] == -1:
                    ranges[name][0] = s
                    libs[s] = name
                elif ranges[name][1] != s:
                    names.remove(name)
                ranges[name][1] = e
    
    libs_addr = sorted(libs)
    if len(libs_addr) == 0:
        return state # static binary (?)
    
    got_start += 3*entry_len # skip first 3 entry
    
    to_resolve = []
    to_resolve_map = {}
    
    for a in xrange(got_start, got_end, entry_len):
        state_val = state.solver.eval(getattr(state.mem[a], "uint%d_t" % proj.arch.bits).resolved)
        if state_val in proj._sim_procedures:
            if proj._sim_procedures[state_val].is_stub: # real simprocs or not?
                dbg_val = get_mem(a)
                if dbg_val >= libs_addr[0]: # already resolved by the loader in the dbg
                    setattr(state.mem[a], "uint%d_t" % proj.arch.bits, dbg_val)
                else:
                    name = proj._sim_procedures[state_val].display_name
                    to_resolve.append(name)
                    to_resolve_map[name] = a
    
    print to_resolve
    print "## angr got - step 0 ##"
    for a in xrange(got_start, got_end, entry_len):
        print "0x%x:  0x%x" % (a, state.solver.eval(getattr(state.mem[a], "uint%d_t" % proj.arch.bits).resolved))
    print
    
    if len(to_resolve) > 0:
        for start in libs_addr:
            end = ranges[libs[start]][1]
                    
            sio = SegIO(start, end)
            elffile = ELFFile(sio)

            symbol_tables = [s for s in elffile.iter_sections()
                             if isinstance(s, SymbolTableSection)]

            resolved_symbols = {} # this is the result 

            for section in symbol_tables:
                if not isinstance(section, SymbolTableSection):
                    continue

                if section['sh_entsize'] == 0:
                    continue
                
                for nsym, symbol in enumerate(section.iter_symbols()):
                    if symbol.name in to_resolve and "FUNC" in symbol['st_info']['type']:
                        resolved = symbol["st_value"] + start
                        print "resolved 0x%x %s --> 0x%x" % (to_resolve_map[symbol.name], symbol.name, resolved)
                        setattr(state.mem[to_resolve_map[symbol.name]], "uint%d_t" % proj.arch.bits, resolved)
                        to_resolve.remove(symbol.name)
                        
            
        if len(to_resolve) > 0:
            for n in to_resolve:
                print "IDAngr: warning symbol %s not resolve, using stub simproc" % n

    print "## angr got - final ##"
    for a in xrange(got_start, got_end, entry_len):
        print "0x%x:  0x%x" % (a, state.solver.eval(getattr(state.mem[a], "uint%d_t" % proj.arch.bits).resolved))
    print
    

    



