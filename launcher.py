"""Entry point for frozen (PyInstaller) builds.

``nova_osint/gui/__main__.py`` uses a relative import, which is correct for
``python -m nova_osint.gui`` but fails under PyInstaller: the bootloader runs
the entry file as a top-level script, so there is no parent package for the
relative import to resolve against. This module imports absolutely instead.

Not used when running from source - see NOVA.spec.
"""

from __future__ import annotations

import multiprocessing
import sys

from nova_osint.gui.app import main

if __name__ == "__main__":
    # Harmless when nothing spawns a process, essential if anything ever does:
    # without it a frozen app re-runs its own entry point per child.
    multiprocessing.freeze_support()
    sys.exit(main())
