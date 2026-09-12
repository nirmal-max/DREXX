import os
import sys
import pytest

# Ensure TCL_LIBRARY / TK_LIBRARY are defined so sub-tests creating Tk instances find Tcl
_tcl_dir = os.path.join(sys.prefix, "tcl", "tcl8.6")
_tk_dir = os.path.join(sys.prefix, "tcl", "tk8.6")
if os.path.isdir(_tcl_dir):
    os.environ["TCL_LIBRARY"] = _tcl_dir
if os.path.isdir(_tk_dir):
    os.environ["TK_LIBRARY"] = _tk_dir

@pytest.fixture(scope="session")
def drex_gui_app():
    from drex_app import DrexApp, ElevationState
    import drex_app
    drex_app._ELEVATION_STATE = ElevationState.NOT_ELEVATED
    app = DrexApp()
    app.update_idletasks()
    yield app
    try:
        app.destroy()
    except Exception:
        pass
