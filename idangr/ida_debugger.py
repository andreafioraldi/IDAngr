import angrdbg

import idc
import idaapi

class IdaDebugger(angrdbg.Debugger):
    def __init__(self):
        self.get_byte = idaapi.get_byte
    
    #-------------------------------------
    def is_active(self):
        return idaapi.is_debugger_on() and idaapi.dbg_can_query()
    
    #-------------------------------------
    def input_file_path(self):
        return idaapi.get_input_file_path()
    
    def image_base(self):
        return idaapi.get_imagebase()
    
    #-------------------------------------
    #def get_byte(self, addr):
    #    return idaapi.get_byte(addr)
    
    def get_word(self, addr):
        return idaapi.get_word(addr)
    
    def get_dword(self, addr):
        return idaapi.get_dword(addr)
    
    def get_qword(self, addr):
        return idaapi.get_qword(addr)
    
    def get_bytes(self, addr, size):
        return idc.get_bytes(addr, size)
    
    def put_byte(self, addr, value):
        idc.patch_dbg_byte(addr, value)
    
    def put_word(self, addr, value):
        idc.patch_dbg_word(addr, value)
    
    def put_dword(self, addr, value):
        idc.patch_dbg_dword(addr, value)
    
    def put_qword(self, addr, value):
        idc.patch_dbg_qword(addr, value)
    
    def put_bytes(self, addr, value):
        for i in xrange(len(value)):
            idc.patch_dbg_byte(addr +i, ord(value[i]))
    
    #-------------------------------------
    def get_reg(self, name):
        return idc.get_reg_value(name)
    
    def set_reg(self, name, value):
        idc.set_reg_value(value, name)
    
    #-------------------------------------
    def step_into(self):
        idaapi.step_into()
    
    def run(self):
        pass
    
    def wait_ready(self):
        idc.GetDebuggerEvent(idc.WFNE_SUSP, -1)
    
    def refresh_memory(self):
        idc.refresh_debugger_memory()
    
    #-------------------------------------
    def seg_by_name(self, name):
        ida_seg = idaapi.get_segm_by_name(name)
        if ida_seg is None:
            return None
        perms = 0
        perms |= angrdbg.SEG_PROT_R if ida_seg.perm & idaapi.SEGPERM_READ else 0
        perms |= angrdbg.SEG_PROT_W if ida_seg.perm & idaapi.SEGPERM_WRITE else 0
        perms |= angrdbg.SEG_PROT_X if ida_seg.perm & idaapi.SEGPERM_EXEC else 0
        return angrdbg.Segment(name, ida_seg.start_ea, ida_seg.end_ea, perms)

    def seg_by_addr(self, addr):
        ida_seg = idaapi.getseg(addr)
        if ida_seg is None:
            return None
        perms = 0
        perms |= angrdbg.SEG_PROT_R if ida_seg.perm & idaapi.SEGPERM_READ else 0
        perms |= angrdbg.SEG_PROT_W if ida_seg.perm & idaapi.SEGPERM_WRITE else 0
        perms |= angrdbg.SEG_PROT_X if ida_seg.perm & idaapi.SEGPERM_EXEC else 0
        return angrdbg.Segment(ida_seg.name, ida_seg.start_ea, ida_seg.end_ea, perms)

    #-------------------------------------
    def resolve_name(self, name): #return None on fail
        return idaapi.get_debug_name_ea(name)


angrdbg.register_debugger(IdaDebugger())


