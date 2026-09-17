# PyInstaller spec for the NOVA desktop app.
#   pip install pyinstaller
#   pyinstaller NOVA.spec --noconfirm
# Produces dist/NOVA.exe - a single file with Python, Tk and the site
# catalogue inside, so it runs on a machine with no Python installed.

block_cipher = None

a = Analysis(
    ["launcher.py"],
    pathex=[],
    binaries=[],
    # The bundled site catalogue and disposable-mail seed are read with
    # Path(__file__).parent, which PyInstaller resolves inside the archive.
    datas=[("nova_osint/data", "nova_osint/data")],
    hiddenimports=[
        # registry.import_modules() imports these by name at runtime; they are
        # statically visible, but list them so a future dynamic import cannot
        # silently drop a module from the build.
        "nova_osint.modules.breach",
        "nova_osint.modules.domain",
        "nova_osint.modules.dorks",
        "nova_osint.modules.email",
        "nova_osint.modules.github",
        "nova_osint.modules.ip",
        "nova_osint.modules.phone",
        "nova_osint.modules.username",
        "nova_osint.modules.web",
    ],
    hookspath=[],
    runtime_hooks=[],
    # The CLI's pretty-printer and the scientific stack are not part of the
    # desktop app; excluding them keeps the binary under ~20 MB.
    excludes=["numpy", "pandas", "matplotlib", "PIL", "pytest", "setuptools"],
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="NOVA",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    runtime_tmpdir=None,
    console=False,          # no terminal window behind the UI
    disable_windowed_traceback=False,
    icon="assets/nova.ico",
)
