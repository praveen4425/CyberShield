"""
Vercel Serverless Function entry point for CyberShield.
Exposes the existing FastAPI application instance for Vercel Python runtime.
"""

import sys
from pathlib import Path

# Add project root to sys.path so backend and data packages resolve cleanly
ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from backend.main import app
