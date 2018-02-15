all: panel.py addmem.py exec.py

panel.py: %.py: %.ui
	pyuic5 panel.ui -o panel.py

addmem.py: %.py: %.ui
	pyuic5 addmem.ui -o addmem.py

exec.py: %.py: %.ui
	pyuic5 exec.ui -o exec.py

clean:
	rm panel.py addmem.py exec.py
