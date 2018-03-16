# must be loaded after the GUI

from idangr import StateShot
from idangr.gui import IDAngrTextViewerForm

s = StateShot()

sm = load_project().factory.simulation_manager(s, save_unconstrained=True)

while len(sm.unconstrained) == 0:
    sm.step()

IDAngrTextViewerForm.showText(sm.unconstrained[0].posix.dumps(0), "Crash Input Viewer")


