# IDAngr
use angr in the ida debugger taking as state the current debugger state

## VERY NAIVE VERSION - ONLY AN IDEA

### usage

1. Load the idangr.py script from the ida menu to create an angr project.
2. During the debug type on the shell 'state = StateShot()' to create an angr state from the current debugger state.
3. Do things with angr
4. Return to 2 or exit
