"""
Test GUI Page Rendering
Verifies that DrexApp initializes properly and that every page
(Dashboard, Wipe Drive, Wipe File/Folder, Recover, Destroy Drive, Certificates, Help)
renders without errors or regressions.
"""
import os
import pytest
from drex_app import DrexApp

def test_all_pages_render_cleanly(drex_gui_app):
    app = drex_gui_app
    pages = [
        "Dashboard",
        "Wipe Drive",
        "Wipe File/Folder",
        "Recover",
        "Destroy Drive",
        "Certificates",
        "Help",
    ]
    for page_name in pages:
        app.show_page(page_name)
        assert app.current_page == page_name
        # Ensure page frame was built
        assert app.page is not None
        app.update_idletasks()

