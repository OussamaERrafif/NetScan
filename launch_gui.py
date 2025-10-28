#!/usr/bin/env python3
"""
NetScan GUI Launcher

Simple launcher script for the NetScan GUI application.
"""
import sys
import os

# Add src directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

# Import and run GUI
from gui import main

if __name__ == "__main__":
    main()
