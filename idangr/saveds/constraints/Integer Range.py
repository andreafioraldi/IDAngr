# add your constraints to the var 'sym' using the var 'state'

# set interval [LOW, HIGH]
LOW = 0
HIGH = 100

a = claripy.BVV(LOW, sym.size())
b = claripy.BVV(HIGH, sym.size())

state.se.add(state.se.And(sym >= a, sym <= b))

