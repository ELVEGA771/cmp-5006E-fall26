import sys
from pathlib import Path

folder_path = str(Path(__file__).resolve().parent.parent / "sibling_folder")

sys.path.insert(0, folder_path)

from tools import my_function
