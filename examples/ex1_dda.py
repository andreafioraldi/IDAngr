#must be loaded after fgets call

smg = StateManager()

smg.sim(smg["rax"], 100)

target = smg["rsp"] +4

m = smg.simulation_manager()

#explore untile target become symbolic
m.explore(find=lambda s: s.memory.load(target, 4).op != "BVV") 

print m
print m.found[0].memory.load(target, 4)
