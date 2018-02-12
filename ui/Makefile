all: panel.py addmem.py

panel.py: %.py: %.ui
	pyuic5 panel.ui -o panel.py

addmem.py: %.py: %.ui
	pyuic5 addmem.ui -o addmem.py

clean:
	rm panel.py addmem.py
