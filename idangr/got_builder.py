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

libc_start = -1
libc_end = -1

for ea in idautils.Segments():
    if "libc" in idc.SegName(ea):
        s = idc.SegStart(ea)
        e = idc.SegEnd(ea)
        if libc_start == -1:
            libc_start = s
        elif libc_end != s:
            break
        libc_end = e


sio = SegIO(libc_start, libc_end)

elffile = ELFFile(sio)

symbol_tables = [s for s in elffile.iter_sections()
                 if isinstance(s, SymbolTableSection)]

to_resolve = [
    "malloc",
    "realloc",
    "open"
]

resolved_symbols = {} # this is the result 

for section in symbol_tables:
    if not isinstance(section, SymbolTableSection):
        continue

    if section['sh_entsize'] == 0:
        continue
    
    for nsym, symbol in enumerate(section.iter_symbols()):
        if symbol.name in to_resolve and "FUNC" in symbol['st_info']['type']:
            resolved_symbols[symbol.name] = symbol["st_value"] + libc_start



