"""
paths.py
========
Single source of truth for all absolute paths in the project.

Every module imports from here instead of computing paths individually.
This guarantees correct resolution regardless of the working directory
from which the user runs `python app.py`.
"""

import os

# The directory that contains THIS file (modules/)
_MODULES_DIR = os.path.dirname(os.path.abspath(__file__))

# The project root is always one level above modules/
PROJECT_ROOT = os.path.dirname(_MODULES_DIR)

# Key paths
CONFIG_PATH      = os.path.join(PROJECT_ROOT, "config.json")
CA_DIR           = os.path.join(PROJECT_ROOT, "ca")
CA_KEY_PATH      = os.path.join(CA_DIR, "ca_private_key.pem")
CA_CERT_PATH     = os.path.join(CA_DIR, "ca_cert.pem")
MEMBERS_CSV      = os.path.join(PROJECT_ROOT, "data", "it_club_members.csv")
CANDIDATES_CSV   = os.path.join(PROJECT_ROOT, "data", "candidates.csv")
