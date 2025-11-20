"""
Small wrapper/entrypoint for running the scanner application. This avoids filename with
spaces when packaging (PyInstaller/Nuitka).

This file simply imports and runs the main GUI loop present in the project.
"""
import os
import sys

ROOT = os.path.abspath(os.path.dirname(__file__))
MAIN_SCRIPT = os.path.join(ROOT, "Projekt AB Skaner Portów.py")

with open(MAIN_SCRIPT, "r", encoding="utf-8") as f:
    code = f.read()

# Execute the main script in its own global namespace
globals_dict = {"__name__": "__main__", "__file__": MAIN_SCRIPT}
exec(compile(code, MAIN_SCRIPT, "exec"), globals_dict)
