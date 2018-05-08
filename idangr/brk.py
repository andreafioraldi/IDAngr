import idc
import idaapi

def get_dbg_brk_linux64():
    '''
    Return the current brk value in the debugged process (only x86_64 Linux)
    '''
    #TODO this method is so weird, find a unused address to inject code not the base address
    
    code = ""
    code += 'H\xc7\xc0\x0c\x00\x00\x00' #mov rax, sys_brk ; 12
    code += 'H1\xff' #xor rdi, rdi
    code += '\x0f\x05' #syscall

    rax = idc.get_reg_value("rax")
    rdi = idc.get_reg_value("rdi")
    rip = idc.get_reg_value("rip")
    efl = idc.get_reg_value("efl")

    base = idaapi.get_imagebase()

    #inj = idc.next_head(rip) #skip current instr
    inj = base

    save = idc.get_bytes(inj, len(code), use_dbg=True)

    for i in xrange(len(code)):
        idc.patch_dbg_byte(inj +i, ord(code[i]))

    #idc.MakeCode(inj)

    idc.set_reg_value(inj, "rip")

    idaapi.step_into()
    idc.GetDebuggerEvent(WFNE_SUSP, -1)
    idaapi.step_into()
    idc.GetDebuggerEvent(WFNE_SUSP, -1)
    idaapi.step_into()
    idc.GetDebuggerEvent(WFNE_SUSP, -1)

    brk_res = idc.get_reg_value("rax")

    idc.set_reg_value(rax, "rax")
    idc.set_reg_value(rdi, "rdi")
    idc.set_reg_value(rip, "rip")
    idc.set_reg_value(efl, "efl")

    for i in xrange(len(save)):
        idc.patch_dbg_byte(inj +i, ord(save[i]))

    save = idc.get_bytes(inj, len(code), use_dbg=True)

    #idc.MakeCode(inj)

    return brk_res


def get_dbg_brk_linux32():
    '''
    Return the current brk value in the debugged process (only x86 Linux)
    '''
    #TODO this method is so weird, find a unused address to inject code not the base address
    
    code = ""
    code += '\xb8-\x00\x00\x00' #mov eax, sys_brk ; 45
    code += '1\xdb' #xor ebx, ebx
    code += '\xcd\x80' #int 0x80

    eax = idc.get_reg_value("eax")
    ebx = idc.get_reg_value("ebx")
    eip = idc.get_reg_value("eip")
    efl = idc.get_reg_value("efl")

    base = idaapi.get_imagebase()

    #inj = idc.next_head(eip) #skip current instr
    inj = base

    save = idc.get_bytes(inj, len(code), use_dbg=True)

    for i in xrange(len(code)):
        idc.patch_dbg_byte(inj +i, ord(code[i]))

    #idc.MakeCode(inj)

    idc.set_reg_value(inj, "eip")

    idaapi.step_into()
    idc.GetDebuggerEvent(WFNE_SUSP, -1)
    idaapi.step_into()
    idc.GetDebuggerEvent(WFNE_SUSP, -1)
    idaapi.step_into()
    idc.GetDebuggerEvent(WFNE_SUSP, -1)

    brk_res = idc.get_reg_value("eax")

    idc.set_reg_value(eax, "eax")
    idc.set_reg_value(ebx, "ebx")
    idc.set_reg_value(eip, "eip")
    idc.set_reg_value(efl, "efl")

    for i in xrange(len(save)):
        idc.patch_dbg_byte(inj +i, ord(save[i]))

    save = idc.get_bytes(inj, len(code), use_dbg=True)

    #idc.MakeCode(inj)

    return brk_res




if idaapi.get_inf_structure().is_64bit():
    print "brk(0) = 0x%x" % get_dbg_brk_linux64()
else:
    print "brk(0) = 0x%x" % get_dbg_brk_linux32()



