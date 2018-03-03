import os
import logging
import archinfo

import idc
import idaapi
import idautils

from cle.backends import Backend, register_backend 
from cle.backends.relocation import Relocation
from cle.errors import CLEError, CLEFileNotFoundError
from cle import Clemory
from symbol import *

l = logging.getLogger("idangr")

class IdaReloc(Relocation):
    def __init__(self, owner, symbol, relative_addr, addend=None):
        super(IdaReloc, self).__init__(owner, symbol, relative_addr)

        self._addend = addend

    @property
    def is_rela(self):
        return self._addend is not None

    @property
    def addend(self):
        if self.is_rela:
            return self._addend
        else:
            return self.owner_obj.memory.read_addr_at(self.relative_addr, orig=True)

    @property
    def value(self):    # pylint: disable=no-self-use
        l.error('Value property of Relocation must be overridden by subclass!')
        return 0


ida_arch_map = {
    ("arm", 64): archinfo.ArchAArch64,
    ("armb", 64): archinfo.ArchAArch64,
    ("arm", 32): archinfo.ArchARM,
    ("armb", 32): archinfo.ArchARM,
    ("metapc", 64): archinfo.ArchAMD64,
    #("avr", 16): archinfo.ArchAVR, #??? check if it is true in ida
    ("mips", 32): archinfo.ArchMIPS32,
    ("mipsb", 32): archinfo.ArchMIPS32,
    ("mips64", 64): archinfo.ArchMIPS64,
    ("mips64b", 64): archinfo.ArchMIPS64,
    ("ppc", 32): archinfo.ArchPPC32,
    ("ppcb", 32): archinfo.ArchPPC32,
    ("ppc64", 64): archinfo.ArchPPC64,
    ("ppc64b", 64): archinfo.ArchPPC64,
    ("metapc", 32): archinfo.ArchX86
    #TODO add more ida processors in the map
}

def arch_from_ida():
    info = idaapi.get_inf_structure()
    if info.is_64bit():
        bits = 64
    elif info.is_32bit():
        bits = 32
    else:
        bits = 16
    try:
        is_be = info.is_be()
    except:
        is_be = info.mf
    a = ida_arch_map[(info.procName, bits)]
    if is_be:
        return a(archinfo.Endness.BE)
    return a(archinfo.Endness.LE)


class IDADbg(Backend):
    """
    Get information from binaries using IDA.
    """
    is_default = True # Tell CLE to automatically consider using the IDADbg backend

    def __init__(self, binary, *args, **kwargs):
        super(IDADbg, self).__init__(binary, *args, **kwargs)

        if self.binary is None:
            self.binary = idaapi.get_input_file_path()
        
        if self.arch is None:
            self.arch = arch_from_ida()
        self.memory = Clemory(self.arch)
        l.debug("Loading binary %s using IDA with arch %s", self.binary, self.arch.ida_processor)
        
        self.BADADDR = idc.BADADDR
        
        self.got_begin = None
        self.got_end = None
        self.raw_imports = {}
        self.current_module_name = None

        self.imports = self._get_imports()
        self.resolved_imports = {}
        self.linking = self._get_linking_type()

        self.exports = self._get_exports()
        
        if self.got_begin:
            self.memory.add_backer(self.got_begin, idc.GetManyBytes(self.got_begin, self.got_end-self.got_begin))

        

    @staticmethod
    def is_compatible(stream):
        return stream == 0  # Don't use this for anything unless it's manually selected

    def in_which_segment(self, addr):
        """
        Return the segment name at address `addr` (IDA).
        """
        seg = idc.SegName(addr)
        if len(seg) == 0:
            seg = "unknown"
        return seg

    def _find_got(self):
        """
        Locate the section (e.g. .got) that should be updated when relocating functions (that's where we want to
        write absolute addresses).
        """
        sec_name = self.arch.got_section_name
        self.got_begin = None
        self.got_end = None

        for seg in idautils.Segments():
            name = idc.SegName(seg)
            if name == sec_name:
                self.got_begin = idc.SegStart(seg)
                self.got_end = idc.SegEnd(seg)

        # If we reach this point, we should have the addresses
        if self.got_begin is None or self.got_end is None:
            l.warning("No section %s, is this a static binary ? (or stripped)", sec_name)
            return False
        return True

    def _in_proper_section(self, addr):
        """
        Is `addr` in the proper section for this architecture ?
        """
        return self.got_begin < addr < self.got_end

    def function_name(self, addr):
        """
        Return the function name at address `addr` (IDA).
        """
        name = idc.GetFunctionName(addr)
        if len(name) == 0:
            name = "UNKNOWN"
        return name

    def _lookup_symbols(self, symbols):
        """
        Resolves a bunch of symbols denoted by the list `symbols`.

        :returns: A dict of the form {symb:addr}.
        """
        addrs = {}

        for sym in symbols:
            addr = self.get_symbol_addr(sym)
            if not addr:
                l.debug("Symbol %s was not found (IDA)", sym)
                continue
            addrs[sym] = addr
        return addrs

    def get_symbol_addr(self, sym):
        """
        Get the address of the symbol `sym` from IDA.

        :returns: An address.
        """
        #addr = idaapi.get_name_ea(idc.BADADDR, sym)
        addr = idc.LocByName(sym)
        if addr == self.BADADDR:
            addr = None
        return addr

    def _get_exports(self):
        """
        Get the binary exports names from IDA and return a list.
        """
        exports = {}
        for item in list(idautils.Entries()):
            name = item[-1]
            if name is None:
                continue
            ea = item[1]
            exports[name] = ea
            #l.debug("\t export %s 0x@%x" % (name, ea))
        return exports

    def _get_ida_imports(self):
        """
        Extract imports from binary (IDA).
        """
        l.warning("TODO: improve this: IDA mixes functions and global data in exports, this will cause issues.")
        import_modules_count = idaapi.get_import_module_qty()
        self.raw_imports = {}

        for i in xrange(0, import_modules_count):
            self.current_module_name = idaapi.get_import_module_name(i)
            idaapi.enum_import_names(i, self._import_entry_callback)

    def _import_entry_callback(self, ea, name, entry_ord): # pylint: disable=unused-argument
        """
        Callback function for IDA's enum_import_names.
        """
        self.raw_imports[name] = ea
        return True

    def _get_imports(self):
        """
        Extract imports from the binary. This uses the exports we get from IDA and then tries to find the GOT
        entries related to them.

        :returns:   a dict of the form {import:got_address}.
        """
        # Get the list of imports from IDA
        self._get_ida_imports()

        # Static binary
        if len(self.raw_imports) == 0:
            l.info("This is a static binary.")
            return

        # Locate the GOT on this architecture. If we can't, let's just default
        # to IDA's imports (which gives stub addresses instead).
        if not self._find_got():
            l.warning("We could not identify the GOT section. This looks like a stripped binary. IDA'll probably give "
                      "us PLT stubs instead, so keep in mind that Ld.find_symbol_got_entry() and friends won't work "
                      "with actual GOT addresses. If that's a problem, use the ELF backend instead.")
            return self.raw_imports

        # Then process it to get the correct addresses
        imports = {}
        for name, ea in self.raw_imports.iteritems():
            # If this architecture uses the plt directly, then we need to look
            # in the code segment.
            if self.arch.got_section_name == '.plt':
                lst = list(idautils.CodeRefsTo(ea, 1))
            else:
                lst = list(idautils.DataRefsTo(ea))
            
            o = 0
            for addr in lst:
                if self._in_proper_section(addr) and addr != self.BADADDR:
                    s = IdaSymbol(self, name, addr, True, False, o, None)
                    imports[name] = IdaReloc(self, s, addr)
                    l.debug("\t -> has import %s - GOT entry @ 0x%x", name, addr)
                    o += 1
        return imports

    @property
    def min_addr(self):
        """
        Get the min address of the binary (IDA).
        """
        nm = idc.NextAddr(0)
        pm = idc.PrevAddr(nm)

        if pm == self.BADADDR:
            return nm
        else:
            return pm

    @property
    def max_addr(self):
        """
        Get the max address of the binary (IDA).
        """
        pm = idc.PrevAddr(idc.MAXADDR)
        nm = idc.NextAddr(pm)

        if nm == self.BADADDR:
            return pm
        else:
            return nm

    @property
    def entry(self):
        if self._custom_entry_point is not None:
            return self._custom_entry_point + self.mapped_base
        return idc.BeginEA() + self.mapped_base

    def resolve_import_dirty(self, sym, new_val):
        """
        Resolve import for symbol `sym` the dirty way, i.e. find all references to it in the code and replace it with
        the address `new_val` inline (instead of updating GOT slots). Don't use this unless you really have to, use
        :func:`resolve_import_with` instead.
        """

        #l.debug("\t %s resolves to 0x%x", sym, new_val)

        # Try IDA's _ptr
        plt_addr = self.get_symbol_addr(sym + "_ptr")
        if plt_addr:
            self.memory.write_addr_at(plt_addr, new_val)
            return

        # Try the __imp_name
        plt_addr = self.get_symbol_addr("__imp_" + sym)
        if plt_addr:
            for addr in idautils.DataRefsTo(plt_addr):
                self.memory.write_addr_at(addr, new_val)
            return

        # Try the normal name
        plt_addr = self.get_symbol_addr(sym)
        if plt_addr:
            addrlist = list(idautils.DataRefsTo(plt_addr))
            # If not datarefs, try coderefs. It can happen on PPC
            if len(addrlist) == 0:
                addrlist = list(idautils.CodeRefsTo(plt_addr))
            for addr in addrlist:
                self.memory.write_addr_at(addr, new_val)
            return

        # If none of them has an address, that's a problem
        l.warning("Could not find references to symbol %s (IDA)", sym)

    def set_got_entry(self, name, newaddr):
        """
        Resolve import `name` with address `newaddr`. That is, update the GOT entry for `name` with `newaddr`.
        """
        if name not in self.imports:
            l.warning("%s not in imports", name)
            return

        addr = self.imports[name]
        self.memory.write_addr_at(addr, newaddr)

    def is_thumb(self, addr):
        """
        Is the address `addr` in thumb mode ? (ARM).
        """
        if not "arm" in self.arch:
            return False
        return idc.GetReg(addr, "T") == 1

    def get_strings(self):
        """
        Extract strings from binary (IDA).

        :returns:   An array of strings.
        """
        ss = idautils.Strings()
        string_list = []
        for s in ss:
            t_entry = (s.ea, str(s), s.length)
            string_list.append(t_entry)
        return string_list

    def _get_linking_type(self):
        """
        Returns whether a binary is statically or dynamically linked based on its imports.
        """
        # TODO: this is not the best, and with the Elf class we actually look for the presence of a dynamic table. We
        # should do it with IDA too.

        if len(self.raw_imports) == 0:
            return "static"
        else:
            return "dynamic"

    # must be able to duck type as a MetaELF subclass

    @property
    def plt(self):
        # I know there's a way to do this but BOY do I not want to do it right now
        return {}

    @property
    def reverse_plt(self):
        return {}

    @staticmethod
    def get_call_stub_addr(name): # pylint: disable=unused-argument
        return None

    @property
    def is_ppc64_abiv1(self):
        # IDA 6.9 segfaults when loading ppc64 abiv1 binaries so....
        return False

register_backend("idadbg", IDADbg)

