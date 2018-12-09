import win32con
import win32api

import ctypes
from ctypes import windll, wintypes

SEG_PROT_R = 4
SEG_PROT_W = 2
SEG_PROT_X = 1


class MEMORY_BASIC_INFORMATION_64(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", wintypes.LARGE_INTEGER),
        ("AllocationBase", wintypes.LARGE_INTEGER),
        ("AllocationProtect", wintypes.DWORD),
        ("RegionSize", wintypes.LARGE_INTEGER),
        ("State", wintypes.DWORD),
        ("Protect", wintypes.DWORD),
        ("Type", wintypes.DWORD)
    ]

class MEMORY_BASIC_INFORMATION_32(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", wintypes.DWORD),
        ("AllocationBase", wintypes.DWORD),
        ("AllocationProtect", wintypes.DWORD),
        ("RegionSize", wintypes.UINT),
        ("State", wintypes.DWORD),
        ("Protect", wintypes.DWORD),
        ("Type", wintypes.DWORD)
    ]

def vmmap(pid, is_64=True):
    base = 0
    if is_64:
        mbi = MEMORY_BASIC_INFORMATION_64()
        addr_type = wintypes.LARGE_INTEGER
    else:
        mbi = MEMORY_BASIC_INFORMATION_32()
        addr_type = wintypes.DWORD
    proc = win32api.OpenProcess(win32con.PROCESS_QUERY_INFORMATION, 0, pid)
    
    maps = []
    while windll.kernel32.VirtualQueryEx(proc.handle, addr_type(base), ctypes.byref(mbi), ctypes.sizeof(mbi)) > 0:
        mapperm = 0
        if mbi.Protect & win32con.PAGE_EXECUTE:
            mapperm = SEG_PROT_X
        elif mbi.Protect & win32con.PAGE_EXECUTE_READ:
            mapperm = SEG_PROT_X | SEG_PROT_R
        elif mbi.Protect & win32con.PAGE_EXECUTE_READWRITE:
            mapperm = SEG_PROT_X | SEG_PROT_R | SEG_PROT_W
        elif mbi.Protect & win32con.PAGE_EXECUTE_WRITECOPY:
            mapperm = SEG_PROT_X | SEG_PROT_R
        elif mbi.Protect & win32con.PAGE_NOACCESS:
            mapperm = 0
        elif mbi.Protect & win32con.PAGE_READONLY:
            mapperm = SEG_PROT_R
        elif mbi.Protect & win32con.PAGE_READWRITE:
            mapperm = SEG_PROT_R | SEG_PROT_W
        elif mbi.Protect & win32con.PAGE_WRITECOPY:
            mapperm = SEG_PROT_R
        #print hex(mbi.BaseAddress) +"\t"+ hex(mbi.BaseAddress + mbi.RegionSize) +"\t"+ hex(mapperm)
        maps.append((mbi.BaseAddress, mbi.BaseAddress + mbi.RegionSize, mapperm, ""))
        base += mbi.RegionSize
    
    win32api.CloseHandle(proc)
    return maps


if __name__ == "__main__":
    import sys
    import json
    m = vmmap(int(sys.argv[1]), sys.argv[2] == "True")
    print json.dumps(m)
