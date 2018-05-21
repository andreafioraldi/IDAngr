import idc
import idaapi


def build_mixed_got(proj, state):
    got_seg = idaapi.get_segm_by_name(proj.arch.got_section_name)
    plt_seg = idaapi.get_segm_by_name(".plt")
    
    if got_seg is None:
        print "IDAngr: cannot find .got.plt section"
        return state
    if plt_seg is None:
        print "IDAngr: cannot find .plt section"
        return state
    
    entry_len = proj.arch.bits / 8
    get_mem = idc.Dword if entry_len == 4 else idc.Qword
    
    got_start = got_seg.start_ea
    
    got_start += 3*entry_len # skip first 3 entries
    
    '''
    print "## angr got - before ##"
    for a in xrange(got_start, got_seg.end_ea, entry_len):
        print "0x%x:  0x%x" % (a, state.solver.eval(getattr(state.mem[a], "uint%d_t" % proj.arch.bits).resolved))
    print
    '''
    
    for a in xrange(got_start, got_seg.end_ea, entry_len):
        state_val = state.solver.eval(getattr(state.mem[a], "uint%d_t" % proj.arch.bits).resolved)
        if state_val in proj._sim_procedures:
            if proj._sim_procedures[state_val].is_stub: # real simprocs or not?
                dbg_val = get_mem(a)
                name = proj._sim_procedures[state_val].display_name
                
                if dbg_val >= plt_seg.end_ea or dbg_val < plt_seg.start_ea: # already resolved by the loader in the dbg
                    setattr(state.mem[a], "uint%d_t" % proj.arch.bits, dbg_val)
                else:
                    ea = idaapi.get_debug_name_ea(name)
                    if ea != idaapi.BADADDR:
                        setattr(state.mem[a], "uint%d_t" % proj.arch.bits, ea)
                        
    '''
    print "## angr got - final ##"
    for a in xrange(got_start, got_seg.end_ea, entry_len):
        print "0x%x:  0x%x" % (a, state.solver.eval(getattr(state.mem[a], "uint%d_t" % proj.arch.bits).resolved))
    print
    '''
    
    return state

    
def build_bind_now_got(proj, state):
    got_seg = idaapi.get_segm_by_name(proj.arch.got_section_name)
    plt_seg = idaapi.get_segm_by_name(".plt")
    
    if got_seg is None:
        print "IDAngr: cannot find .got.plt section"
        return state
    if plt_seg is None:
        print "IDAngr: cannot find .plt section"
        return state
    
    entry_len = proj.arch.bits / 8
    get_mem = idc.Dword if entry_len == 4 else idc.Qword
    
    got_start = got_seg.start_ea
    
    got_start += 3*entry_len # skip first 3 entries
    
    '''
    print "## angr got - before ##"
    for a in xrange(got_start, got_seg.end_ea, entry_len):
        print "0x%x:  0x%x" % (a, state.solver.eval(getattr(state.mem[a], "uint%d_t" % proj.arch.bits).resolved))
    print
    '''
    
    for a in xrange(got_start, got_seg.end_ea, entry_len):
        state_val = state.solver.eval(getattr(state.mem[a], "uint%d_t" % proj.arch.bits).resolved)
        if state_val in proj._sim_procedures:
            dbg_val = get_mem(a)
            name = proj._sim_procedures[state_val].display_name
            
            if dbg_val >= plt_seg.end_ea or dbg_val < plt_seg.start_ea: # already resolved by the loader in the dbg
                setattr(state.mem[a], "uint%d_t" % proj.arch.bits, dbg_val)
            else:
                ea = idaapi.get_debug_name_ea(name)
                if ea != idaapi.BADADDR:
                    setattr(state.mem[a], "uint%d_t" % proj.arch.bits, ea)
                        
    '''
    print "## angr got - final ##"
    for a in xrange(got_start, got_seg.end_ea, entry_len):
        print "0x%x:  0x%x" % (a, state.solver.eval(getattr(state.mem[a], "uint%d_t" % proj.arch.bits).resolved))
    print
    '''
    
    return state

