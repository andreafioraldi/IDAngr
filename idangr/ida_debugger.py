from manage import get_angrdbg

import idc
import idaapi
import functools

def idawrite(f):
    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        ff = functools.partial(f, *args, **kwargs)
        return idaapi.execute_sync(ff, idaapi.MFF_WRITE)
    return wrapper


class RemoteFile(object):
    def __init__(self, f, name):
        self.f = f
        self.name = name
    
    def __eq__(self, o):
        try:
            return self.name == o.name
        except:
            return False
    
    def read(self, size=None):
        if size == None:
            return self.f.read()
        return self.f.read(size)
    
    def seek(self, pos):
        return self.f.seek(pos)


SEG_PROT_R = 4
SEG_PROT_W = 2
SEG_PROT_X = 1

class IdaDebugger(object):
    #must implements all methods of angrdbg.Debugger !!!
    
    def __init__(self, angrdbg_mod, remote=False):
        #self.get_byte = idaapi.get_byte
        self.name = "IDAngr"
        self.angrdbg_mod = angrdbg_mod
        self.remote = remote
    
    #-------------------------------------
    def before_stateshot(self):
        pass
        
    def after_stateshot(self, state):
        pass

    #-------------------------------------
    def is_active(self):
        return idaapi.is_debugger_on() and idaapi.dbg_can_query()
    
    #-------------------------------------
    def input_file(self):
        path = idaapi.get_input_file_path()
        f = open(path, "rb")
        if self.remote:
            return RemoteFile(f, path)
        return f
    
    def image_base(self):
        return idaapi.get_imagebase()
    
    #-------------------------------------
    def get_byte(self, addr):
        return idaapi.get_byte(addr)
    
    def get_word(self, addr):
        return idaapi.get_word(addr)
    
    def get_dword(self, addr):
        return idaapi.get_dword(addr)
    
    def get_qword(self, addr):
        return idaapi.get_qword(addr)
    
    def get_bytes(self, addr, size):
        return idc.get_bytes(addr, size)
    
    @idawrite
    def put_byte(self, addr, value):
        idc.patch_dbg_byte(addr, value)
    
    @idawrite
    def put_word(self, addr, value):
        idc.patch_dbg_word(addr, value)
    
    @idawrite
    def put_dword(self, addr, value):
        idc.patch_dbg_dword(addr, value)
    
    @idawrite
    def put_qword(self, addr, value):
        idc.patch_dbg_qword(addr, value)
    
    @idawrite
    def put_bytes(self, addr, value):
        for i in xrange(len(value)):
            idc.patch_dbg_byte(addr +i, ord(value[i]))
    
    #-------------------------------------
    def get_reg(self, name):
        return idc.get_reg_value(name)
    
    @idawrite
    def set_reg(self, name, value):
        idc.set_reg_value(value, name)
    
    #-------------------------------------
    @idawrite
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
        perms |= SEG_PROT_R if ida_seg.perm & idaapi.SEGPERM_READ else 0
        perms |= SEG_PROT_W if ida_seg.perm & idaapi.SEGPERM_WRITE else 0
        perms |= SEG_PROT_X if ida_seg.perm & idaapi.SEGPERM_EXEC else 0
        return self.angrdbg_mod.Segment(name, ida_seg.start_ea, ida_seg.end_ea, perms)
    
    def seg_by_addr(self, addr):
        ida_seg = idaapi.getseg(addr)
        if ida_seg is None:
            return None
        perms = 0
        perms |= SEG_PROT_R if ida_seg.perm & idaapi.SEGPERM_READ else 0
        perms |= SEG_PROT_W if ida_seg.perm & idaapi.SEGPERM_WRITE else 0
        perms |= SEG_PROT_X if ida_seg.perm & idaapi.SEGPERM_EXEC else 0
        return self.angrdbg_mod.Segment(ida_seg.name, ida_seg.start_ea, ida_seg.end_ea, perms)

    def get_got(self): #return tuple(start_addr, end_addr)
        ida_seg = idaapi.get_segm_by_name(".got.plt")
        return (ida_seg.start_ea, ida_seg.end_ea)
    
    def get_plt(self): #return tuple(start_addr, end_addr)
        ida_seg = idaapi.get_segm_by_name(".plt")
        return (ida_seg.start_ea, ida_seg.end_ea)
    
    def get_idata(self): #return tuple(start_addr, end_addr)
        ida_seg = idaapi.get_segm_by_name(".idata")
        if ida_seg is None:
            addr = None
            def cb(ea, name, i):
                addr = ea
            idaapi.enum_import_names(0, cb)
            ida_seg = idaapi.seg_by_addr(addr)
        return (ida_seg.start_ea, ida_seg.end_ea)
    
    #-------------------------------------
    def resolve_name(self, name): #return None on fail
        try:
            return idaapi.get_debug_name_ea(name)
        except:
            return None


class IdaPinDebugger(IdaDebugger):
    
    def before_stateshot(self):
        import win_vmmap
        pid = send_dbg_command("getpid")
        self.vmmap = win_vmmap.vmmap(pid)
    
    def seg_by_addr(self, addr):
        ida_seg = idaapi.getseg(addr)
        name = "<no name>"
        if ida_seg is not None:
            name = ida_seg.name
        for start, end, perms, name in self.vmmap:
            if addr >= start and addr < end:
                return Segment(name, start, end, perms)
        # fallback on ida segs
        perms = 0
        perms |= SEG_PROT_R if ida_seg.perm & idaapi.SEGPERM_READ else 0
        perms |= SEG_PROT_W if ida_seg.perm & idaapi.SEGPERM_WRITE else 0
        perms |= SEG_PROT_X if ida_seg.perm & idaapi.SEGPERM_EXEC else 0
        return self.angrdbg_mod.Segment(ida_seg.name, ida_seg.start_ea, ida_seg.end_ea, perms)


def register(conn):
    if conn:
        conn[0].modules.angrdbg.register_debugger(IdaDebugger(conn[0].modules.angrdbg, True))
        conn[1].modules.angrdbg.register_debugger(IdaDebugger(conn[1].modules.angrdbg, True))
    else:
        get_angrdbg().register_debugger(IdaDebugger(get_angrdbg(), False))
    


