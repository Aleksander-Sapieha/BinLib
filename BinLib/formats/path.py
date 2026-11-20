import sys
import os

def resource_path(path):
    if getattr(sys, 'frozen', False):
        return os.path.join(sys._MEIPASS, path)

    return os.path.join(os.path.dirname(__file__), path)