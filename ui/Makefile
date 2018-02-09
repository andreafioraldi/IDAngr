all: panel.py

panel.py: %.py: %.ui
	pyuic5 panel.ui -o panel.py

designer:
	/usr/lib/x86_64-linux-gnu/qt5/bin/designer panel.ui

clean:
	rm panel.py
