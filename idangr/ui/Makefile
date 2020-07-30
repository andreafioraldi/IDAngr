all: connect.py panel.py addmem.py execute.py viewer.py constraints.py saveds.py explorer.py

connect.py: %.py: %.ui
	pyuic5 connect.ui -o connect.py

panel.py: %.py: %.ui
	pyuic5 panel.ui -o panel.py

addmem.py: %.py: %.ui
	pyuic5 addmem.ui -o addmem.py

execute.py: %.py: %.ui
	pyuic5 execute.ui -o execute.py

viewer.py: %.py: %.ui
	pyuic5 viewer.ui -o viewer.py

constraints.py: %.py: %.ui
	pyuic5 constraints.ui -o constraints.py

saveds.py: %.py: %.ui
	pyuic5 saveds.ui -o saveds.py

explorer.py: %.py: %.ui
	pyuic5 explorer.ui -o explorer.py

clean:
	rm panel.py addmem.py execute.py viewer.py constraints.py saveds.py explorer.py
