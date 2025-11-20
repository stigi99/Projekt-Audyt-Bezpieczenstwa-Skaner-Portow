import os
import sys

# If you need to import modules from the project, add the path here.
sys.path.insert(0, os.path.abspath('..'))

project = 'Projekt Audyt Bezpieczeństwa — Skaner Portów'
author = 'Mateusz Misiak'
extensions = [
    'sphinx.ext.autodoc',
    'sphinx.ext.napoleon',
    'sphinxcontrib.mermaid',
]
autodoc_mock_imports = ['PySide6', 'scapy']
templates_path = ['_templates']
exclude_patterns = []
html_theme = 'sphinx_rtd_theme'
html_static_path = ['_static']

master_doc = 'index'
