
find = []
avoid = []
find_lambda = "def find_cond(state):\n\tsol = state.solver.eval\n\tfor addr in finds:\n\t\tif sol(state.regs.pc) == addr: return True\n\treturn False"
avoid_lambda = "def avoid_cond(state):\n\tsol = state.solver.eval\n\tfor addr in avoids:\n\t\tif sol(state.regs.pc) == addr: return True\n\treturn False"
regs = []
simregs = []
simmem = []
constraints = {} #{ item: (code string, lambda) }
stateman = None
foundstate = None
simman = None

# indipendent from context
hooks = [] #[(address, code)]


def reset():
    global find, avoid, find_lambda, avoid_lambda, regs, simregs, simmem, constraints, stateman, foundstate, simman
    find = []
    avoid = []
    find_lambda = "def find_cond(state):\n\tsol = state.solver.eval\n\tfor addr in finds:\n\t\tif sol(state.regs.pc) == addr: return True\n\treturn False"
    avoid_lambda = "def avoid_cond(state):\n\tsol = state.solver.eval\n\tfor addr in avoids:\n\t\tif sol(state.regs.pc) == addr: return True\n\treturn False"
    regs = []
    while len(simregs) > 0:
        simregs.pop()
    while len(simmem) > 0:
        simmem.pop()
    constraints = {} #{ item: (code string, lambda) }
    stateman = None
    foundstate = None
    simman = None
