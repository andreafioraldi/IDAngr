import sys
import rpyc
import thread
from rpyc.utils.classic import DEFAULT_SERVER_PORT, DEFAULT_SERVER_SSL_PORT

class AngrDbgNotInstalled(RuntimeError):
    pass

def _angr_not_installed():
    e = "ERROR: angrdbg is not installed!\n"
    e += "  to use idangr locally install angrdbg with:\n"
    e += "  $ pip install angrdbg\n\n"
    raise AngrDbgNotInstalled(e)

_conn = None

_angr_module = None
_claripy_module = None
_pyvex_module = None
_angrdbg_module = None

def remote(host="localhost", port=DEFAULT_SERVER_PORT):
    srv = rpyc.classic.connect(host, port=port) #server
    cl = rpyc.classic.connect(host, port=port) #client
    return (cl, srv)


def get_angr():
    global _conn, _angr_module
    if _conn != None:
        return _conn[0].modules.angr
    elif _angr_module != None:
        return _angr_module
    else:
        try:
            import angr
        except: _angr_not_installed()
        return angr

def get_claripy():
    global _conn, _claripy_module
    if _conn != None:
        return _conn[0].modules.claripy
    elif _claripy_module != None:
        return _claripy_module
    else:
        try:
            import claripy
        except: _angr_not_installed()
        return claripy

def get_pyvex():
    global _conn, _pyvex_module
    if _conn != None:
        return _conn[0].modules.pyvex
    elif _pyvex_module != None:
        return _pyvex_module
    else:
        try:
            import pyvex
        except: _angr_not_installed()
        return pyvex


def get_angrdbg():
    global _conn, _angrdbg_module
    if _conn != None:
        return _conn[0].modules.angrdbg
    elif _angrdbg_module != None:
        return _angrdbg_module
    else:
        try:
            import angrdbg
        except: _angr_not_installed()
        return angrdbg


def init(is_remote=False, host="localhost", port=DEFAULT_SERVER_PORT):
    global _conn, _angr_module, _claripy_module, _pyvex_module, _angrdbg_module
    if _conn != None:
        _conn.close()
    _conn = None
    if is_remote:
        _conn = remote(host, port)
        
        if "angr" in sys.modules and type(sys.modules["angr"]) == type(sys):
            _angr_module = sys.modules["angr"]
            sys.modules.pop("angr")
        if "claripy" in sys.modules and type(sys.modules["claripy"]) == type(sys):
            _claripy_module = sys.modules["claripy"]
            sys.modules.pop("claripy")
        if "pyvex" in sys.modules and type(sys.modules["pyvex"]) == type(sys):
            _pyvex_module = sys.modules["pyvex"]
            sys.modules.pop("pyvex")
        if "angrdbg" in sys.modules and type(sys.modules["angrdbg"]) == type(sys):
            _angrdbg_module = sys.modules["angrdbg"]
            sys.modules.pop("angrdbg")
    else:
        if "angr" in sys.modules:
            sys.modules.pop("angr")
        if "claripy" in sys.modules:
            sys.modules.pop("claripy")
        if "pyvex" in sys.modules:
            sys.modules.pop("pyvex")
        if "angrdbg" in sys.modules:
            sys.modules.pop("angrdbg")
    
    sys.modules["angr"] = get_angr()
    sys.modules["claripy"] = get_claripy()
    sys.modules["pyvex"] = get_pyvex()
    sys.modules["angrdbg"] = get_angrdbg()

    from ida_debugger import register
    register(_conn)
    
    if is_remote:
        thread.start_new_thread(_conn[1].serve_all, tuple())
        #_conn.serve_all()
        

def close():
    global _conn
    if _conn != None:
        _conn[0].close()
        _conn[1].close()
    _conn = None

def serve_all():
    global _conn
    if not _is_remote:
        print "Not remote..."
    else:
        _conn[1].serve_all()
    


