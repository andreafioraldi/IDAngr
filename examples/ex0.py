import idangr
import idc

sm = idangr.StateManager()

print "target: found a combination of a1 and a2 that fail the assert"

print "before:"
print "  a1 =", idc.Dword(idc.GetRegValue("ebp")+0x8)
print "  a2 =", idc.Dword(idc.GetRegValue("ebp")+0xc)

a1 = sm["ebp"] +0x8
a2 = sm["ebp"] +0xc

sm.sim(a1, 4)
sm.sim(a2, 4)

print sm.symbolics

m = sm.simulation_manager()

print m.explore(find=0x0040149E, avoid=[0x004014BA])

if len(m.found) < 1:
    print "DOH"
else:
    sm.to_dbg(m.found[0])
    print "after:"
    print "  a1 =", idc.Dword(idc.GetRegValue("ebp")+0x8)
    print "  a2 =", idc.Dword(idc.GetRegValue("ebp")+0xc)
