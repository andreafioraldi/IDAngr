
sm = StateManager()

print "addr: ", sm[sm["esp"] +4]()
print "val:", sm[sm[sm["esp"] +4]()].m(100)
print "reversed val:", sm[sm[sm["esp"] +4]()](100)

print "before:", idc.GetManyBytes(Dword(idc.GetRegValue("esp")+4), 100)

sm.sim(sm[sm["esp"] +4](), 100)

print sm.symbolics

m = sm.simulation_manager()

print m.explore(find=0x004014D2, avoid=[0x004014E0])

if len(m.found) < 1:
    print "DOH"
else:
    sm.to_dbg(m.found[0])
    print "after:", idc.GetManyBytes(Dword(idc.GetRegValue("esp")+4), 100)
