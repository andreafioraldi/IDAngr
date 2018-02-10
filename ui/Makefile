all: panel.py

panel.py: %.py: %.ui
	pyuic5 panel.ui -o panel.py

clean:
	rm panel.py
