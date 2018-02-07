import angr
import claripy
import socket

project = angr.Project("test0.exe")

@project.hook(0x00401493, length=5)
def wsa_call(state):
    return

@project.hook(0x004014AC, length=5)
def ghn_call(state):
    h = socket.gethostname()
    state.memory.store(state.regs.esp, h)


argv1 = claripy.BVS("argv1",100*8) #since we do not the length now, we just put 100 bytes
initial_state = project.factory.blank_state()

initial_state.regs.eip=0x00401460
initial_state.memory.store(initial_state.memory.load(initial_state.regs.esp + 8, 4).reversed, argv1)

sm = project.factory.simulation_manager(initial_state)

e = sm.explore(find=0x004014D2, avoid=[0x004014E0], n=1)
print e

while len(sm.found) == 0:
    e = sm.explore(find=0x004014D2, avoid=[0x004014E0], n=1)
    print e
    #print e.active[0].regs.eip

found = sm.found[0]
solution = found.solver.eval(argv1, cast_to=str)
print repr(solution)

