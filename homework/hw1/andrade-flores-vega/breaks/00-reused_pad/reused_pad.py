import sys
from pathlib import Path

folder_path = str(Path(__file__).resolve().parent.parent / "sibling_folder")

# 2. Add that folder path to Python's search path
sys.path.insert(0, folder_path)

# 3. Now you can import directly from tools.py
from tools import my_function
