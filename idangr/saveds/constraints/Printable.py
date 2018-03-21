# add your constraints to the var 'sym' using the var 'state'

for o in sym.chop(8):
	state.se.add(state.se.Or(state.se.And(o >= 0x20, o <= 0x7e), o == 0))

