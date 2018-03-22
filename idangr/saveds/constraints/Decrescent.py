# add your constraints to the var 'sym' using the var 'state'

c = 255
for o in sym.chop(8):
	state.se.add(o <= c)
	c = o

